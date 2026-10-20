"""VPC Reachability Analyzer as evidence (B16): can the workload reach what it depends on, and if not, what blocks it.

A timeout to the database looks the same in the logs whether the database is slow or a security group, a network ACL
or a route stopped the packets. Reachability Analyzer answers the second question from the network's configuration
(it sends no packets): for a path - a source (a Lambda function's or an ECS task's network interface, an instance) to
a destination (an Aurora or RDS endpoint, an address) on one TCP port - whether a path exists and, when it does not,
which component blocks it (`ENI_SG_RULES_MISMATCH` at sg-..., a missing route ...).

⛔ IT COSTS MONEY, SO IT IS OFF AND CAPPED. Each analysis is billed: $0.10 per analysis processed (AWS Price List API,
AmazonVPC, ap-south-1 `RunAnalysis`, published 2026-10-16T22:43:21Z). It runs only when an operator switches it on
(WARDEN_REACHABILITY=1), only for the paths an operator names (WARDEN_REACHABILITY_PATHS), only when the alert names
a path's source or destination, and never more than MAX_PER_INCIDENT (2) analyses for one incident - counted from the
paths already tagged with the incident in the account, not only in this process, so a re-read never runs more. At most
$0.20 an incident; nothing at all while it is off. Paths cost nothing and are kept, tagged, as that count.

Its IAM is its own optional policy (iam/templates/platform-reachability.json): no permission, no analysis.

WARDEN_REACHABILITY_PATHS: `source=destination:port` pairs, comma-separated. A source is `lambda/<function>`,
`ecs/<cluster>/<service>`, or an `eni-`/`i-` id; a destination is `aurora/<cluster>`, `rds/<instance>`, an `eni-`/`i-`
id or an IPv4 address. Example: `lambda/warden-dev-orders=aurora/warden-dev-db:5432`.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .grafana import PARTIAL
from .models import Alert
from .read_errors import READ_ERRORS
from .tools import ToolError

MAX_PER_INCIDENT = 2
PRICE_USD = 0.10
WAIT_S = 20.0
POLL_S = 2.0
PATH_PAGES = 5
MAX_EXPLANATIONS = 3
TAG_INCIDENT = "warden:incident"
TAG_PATH = "warden:path"  # the configured path, `source destination port`: a re-read reports it, never pays again
PURPOSE = "warden-evidence"

_NAME = r"[A-Za-z0-9][A-Za-z0-9._-]{0,126}"
_SOURCE = re.compile(rf"^(?:lambda/({_NAME})|ecs/({_NAME})/({_NAME})|((?:eni|i)-[0-9a-f]{{8,17}}))$")
_DEST = re.compile(rf"^(?:aurora/({_NAME})|rds/({_NAME})|((?:eni|i)-[0-9a-f]{{8,17}})|(\d{{1,3}}(?:\.\d{{1,3}}){{3}}))$")
_CODE = re.compile(r"^[A-Z0-9_]{1,64}$")
_ID = re.compile(r"^[a-z]{1,8}-[0-9a-f]{8,17}$")


@dataclass(frozen=True)
class Path:
    source: str
    destination: str
    port: int

    @property
    def tag(self) -> str:
        return f"{self.source} {self.destination} {self.port}"

    @property
    def names(self) -> set[str]:
        """The resource names this path is about, to match against the alert's labels."""
        return {part for side in (self.source, self.destination) for part in side.split("/")[1:]} | {
            side for side in (self.source, self.destination) if "/" not in side}


def paths(raw: str | None = None) -> list[Path]:
    """The operator's paths (WARDEN_REACHABILITY_PATHS); a malformed one is dropped, never guessed."""
    raw = os.environ.get("WARDEN_REACHABILITY_PATHS", "") if raw is None else raw
    out = []
    for item in (p.strip() for p in raw.split(",")):
        src, _, rest = item.partition("=")
        dst, _, port = rest.rpartition(":")
        if _SOURCE.match(src) and _DEST.match(dst) and port.isdigit() and 0 < int(port) < 65536:
            out.append(Path(src, dst, int(port)))
    return out


def chosen(alert: Alert, configured: list[Path]) -> list[Path]:
    """The configured paths this alert names (its service or any label value), at most MAX_PER_INCIDENT."""
    named = {alert.service, *(str(v) for v in (alert.labels or {}).values())}
    return [p for p in configured if p.names & named][:MAX_PER_INCIDENT]


class ReachabilityReader:
    """Reachability analyses for the alert's configured paths. `clients` makes the boto3 clients for an alert - in the
    runtime, the ones over the incident's environment's reader role. `resolve`, `sleep` and `clock` are injectable."""

    source = "reachability"

    def __init__(self, clients: Any, *, environment: Callable[[Alert], str] = lambda a: a.environment,
                 configured: list[Path] | None = None, resolve: Callable[[str], str] | None = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> None:
        self._clients, self._environment = clients, environment
        self._configured = paths() if configured is None else configured
        self._resolve = resolve or (lambda host: socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0])
        self._sleep, self._clock = sleep, clock

    def traces(self, _alert: Alert) -> list[str]:
        return []

    def metrics(self, _alert: Alert) -> dict[str, float]:
        return {}

    def logs(self, alert: Alert) -> list[str]:
        wanted = chosen(alert, self._configured)
        if not wanted:
            return []
        try:
            made = self._clients(alert)
            ec2 = made["ec2"]
            earlier = self._already(ec2, alert.alert_id)
        except (*READ_ERRORS, ToolError) as exc:  # a read that did not happen, never a reachable path
            return [f"{PARTIAL}reachability: {type(exc).__name__} - not read"]
        out: list[str] = []
        # A path this incident already analysed is reported from that analysis: a re-read never pays again.
        reported = [(path, earlier[path.tag]) for path in wanted if path.tag in earlier]
        room = max(0, MAX_PER_INCIDENT - len(earlier))
        fresh = [path for path in wanted if path.tag not in earlier]
        if len(fresh) > room:
            out.append(f"{PARTIAL}reachability: {len(earlier)} of {MAX_PER_INCIDENT} analyses already run for this "
                       f"incident - {len(fresh) - room} path(s) not analysed")
        started = []
        for path in fresh[:room]:
            got = self._start(made, path, alert)
            if isinstance(got, str):
                out.append(got)
            else:
                started.append(got)
        try:
            return out + self._results(ec2, [*self._latest(ec2, reported), *started])
        except READ_ERRORS as exc:  # started and billed, but its answer not read: said, never a reachable path
            return [*out, f"{PARTIAL}reachability: {type(exc).__name__} reading the analyses - not read"]

    # ------------------------------------------------------------------ the cap

    @staticmethod
    def _already(ec2: Any, incident: str) -> dict[str, str]:
        """{path tag: path id} of the paths already made for this incident, in the account - each one analysis WARDEN
        ran and paid for. EC2 filters these listings by no tag (its Filters: source, destination, protocol and the
        filter-at fields), so they are read and matched here; a listing longer than PATH_PAGES counts as the cap
        reached - an unseen path could be this incident's, and a third analysis is never risked."""
        found: dict[str, str] = {}
        token, key = "", incident[:128]  # the tag value as it was written (tags hold at most 256 characters)
        for _ in range(PATH_PAGES):
            page = ec2.describe_network_insights_paths(**({"NextToken": token} if token else {}))
            for p in page.get("NetworkInsightsPaths") or []:
                tags = {t.get("Key"): t.get("Value") for t in p.get("Tags") or []}
                if tags.get(TAG_INCIDENT) == key:
                    found[str(tags.get(TAG_PATH) or p.get("NetworkInsightsPathId"))] = str(p.get("NetworkInsightsPathId"))
            token = str(page.get("NextToken") or "")
            if not token:
                return found
        return {**{f"unseen-{i}": "" for i in range(MAX_PER_INCIDENT)}, **found}

    @staticmethod
    def _latest(ec2: Any, reported: list[tuple[Path, str]]) -> list[tuple[Path, str]]:
        """Each already-analysed path's latest analysis, to report again."""
        out = []
        for path, path_id in reported:
            got = ec2.describe_network_insights_analyses(NetworkInsightsPathId=path_id)
            runs = sorted(got.get("NetworkInsightsAnalyses") or [], key=lambda a: str(a.get("StartDate") or ""))
            if runs:
                out.append((path, str(runs[-1].get("NetworkInsightsAnalysisId"))))
        return out

    # ------------------------------------------------------------------ one analysis

    def _start(self, made: Any, path: Path, alert: Alert) -> tuple[Path, str] | str:
        try:
            source = self._source(made, path.source)
            destination = self._destination(made, path.destination)
        except READ_ERRORS as exc:  # an unresolved end is a path not analysed, and nothing is billed
            return f"{PARTIAL}reachability {path.source}: {type(exc).__name__} resolving it - not analysed"
        if not source or not destination:
            return f"{PARTIAL}reachability {path.source}: no network interface or address found - not analysed"
        tags = [{"Key": "Environment", "Value": self._environment(alert)},
                {"Key": TAG_INCIDENT, "Value": alert.alert_id[:128]}, {"Key": TAG_PATH, "Value": path.tag[:256]},
                {"Key": "Purpose", "Value": PURPOSE}]
        # One token per incident and path, of fixed length: a retry is the same request, two paths never collide.
        token = hashlib.sha256(f"{alert.alert_id}|{path.tag}".encode()).hexdigest()[:48]
        ec2 = made["ec2"]
        try:
            made_path = ec2.create_network_insights_path(
                Source=source, Protocol="tcp", DestinationPort=path.port, ClientToken=f"{token}-p",
                **({"DestinationIp": destination} if _is_ip(destination) else {"Destination": destination}),
                TagSpecifications=[{"ResourceType": "network-insights-path", "Tags": tags}])
            path_id = made_path["NetworkInsightsPath"]["NetworkInsightsPathId"]
            run = ec2.start_network_insights_analysis(
                NetworkInsightsPathId=path_id, ClientToken=f"{token}-a",
                TagSpecifications=[{"ResourceType": "network-insights-analysis", "Tags": tags}])
        except READ_ERRORS as exc:  # refused or failed: said, never a reachable path
            return f"{PARTIAL}reachability {path.source}: {type(exc).__name__} - not analysed"
        return path, str(run["NetworkInsightsAnalysis"]["NetworkInsightsAnalysisId"])

    def _source(self, made: Any, source: str) -> str:
        fn, cluster, service, raw = _SOURCE.match(source).groups()
        if raw:
            return raw
        return _lambda_eni(made["ec2"], fn) if fn else _task_eni(made["ecs"], cluster, service)

    def _destination(self, made: Any, destination: str) -> str:
        aurora, rds, raw, ip = _DEST.match(destination).groups()
        if raw or ip:
            return raw or ip
        host = _db_host(made["rds"], aurora, rds)
        return self._resolve(host) if host else ""

    # ------------------------------------------------------------------ the answers

    def _results(self, ec2: Any, started: list[tuple[Path, str]]) -> list[str]:
        if not started:
            return []
        pending = {aid: path for path, aid in started}
        answers: dict[str, dict[str, Any]] = {}
        until = self._clock() + WAIT_S
        while pending and self._clock() < until:
            got = ec2.describe_network_insights_analyses(NetworkInsightsAnalysisIds=sorted(pending))
            done = [a for a in got.get("NetworkInsightsAnalyses") or []
                    if a.get("Status") != "running" and a.get("NetworkInsightsAnalysisId") in pending]
            for a in done:
                answers[a["NetworkInsightsAnalysisId"]] = a
                pending.pop(a["NetworkInsightsAnalysisId"])
            if pending:
                self._sleep(POLL_S)
        out = [_line(path, answers[aid]) for path, aid in started if aid in answers]
        out += [f"{PARTIAL}reachability {path.source}: analysis {aid} still running after {WAIT_S:g}s - not read"
                for path, aid in started if aid not in answers]
        return out


def _lambda_eni(ec2: Any, fn: str) -> str:
    """A VPC function's network interface - the first by id, so the same one each time."""
    enis = ec2.describe_network_interfaces(Filters=[
        {"Name": "description", "Values": [f"AWS Lambda VPC ENI-{fn}-*", f"AWS Lambda VPC ENI-{fn}"]}])
    found = sorted(str(n.get("NetworkInterfaceId")) for n in enis.get("NetworkInterfaces") or [])
    return found[0] if found else ""


def _task_eni(ecs: Any, cluster: str, service: str) -> str:
    """A running task's network interface (awsvpc), from the first task by ARN."""
    tasks = ecs.list_tasks(cluster=cluster, serviceName=service, desiredStatus="RUNNING").get("taskArns") or []
    if not tasks:
        return ""
    described = ecs.describe_tasks(cluster=cluster, tasks=sorted(tasks)[:1]).get("tasks") or []
    details = [d for t in described for att in t.get("attachments") or [] for d in att.get("details") or []]
    return next((str(d.get("value") or "") for d in details if d.get("name") == "networkInterfaceId"), "")


def _db_host(rds: Any, aurora: str | None, instance: str | None) -> str:
    if aurora:
        found = rds.describe_db_clusters(DBClusterIdentifier=aurora).get("DBClusters") or []
        return str((found[0] if found else {}).get("Endpoint") or "")
    found = rds.describe_db_instances(DBInstanceIdentifier=instance).get("DBInstances") or []
    return str(((found[0] if found else {}).get("Endpoint") or {}).get("Address") or "")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def _line(path: Path, analysis: dict[str, Any]) -> str:
    """One analysis as WARDEN's own read: reachable or not and, if not, the blocking components AWS names."""
    head = f"STATE reachability {path.source} -> {path.destination}:{path.port} tcp"
    if analysis.get("Status") != "succeeded":
        return f"{PARTIAL}reachability {path.source}: analysis {analysis.get('Status') or 'unknown'} - not read"
    if analysis.get("NetworkPathFound"):
        return f"{head} path_found=true"
    blocks = []
    for e in (analysis.get("Explanations") or [])[:MAX_EXPLANATIONS]:
        code = str(e.get("ExplanationCode") or "")
        where = next((str(c.get("Id")) for c in (e.get(k) for k in ("SecurityGroup", "Acl", "RouteTable", "Subnet",
                                                                      "NetworkInterface", "Component"))
                      if isinstance(c, dict) and _ID.match(str(c.get("Id") or ""))), "")
        if _CODE.match(code):
            blocks.append(f"{code}{' at ' + where if where else ''}")
    return f"{head} path_found=false blocked_by={'; '.join(blocks) or 'not named'}"
