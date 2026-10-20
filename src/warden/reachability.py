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

MAX_PER_INCIDENT = 2
PRICE_USD = 0.10
WAIT_S = 20.0
POLL_S = 2.0
PATH_PAGES = 5
MAX_EXPLANATIONS = 3
TAG_INCIDENT = "warden:incident"
PURPOSE = "warden-evidence"

_NAME = r"[A-Za-z0-9][A-Za-z0-9._-]{0,126}"
_SOURCE = re.compile(rf"^(?:lambda/({_NAME})|ecs/({_NAME})/({_NAME})|((?:eni|i)-[0-9a-f]{{8,17}}))$")
_DEST = re.compile(rf"^(?:aurora/({_NAME})|rds/({_NAME})|((?:eni|i)-[0-9a-f]{{8,17}})|(\d{{1,3}}(?:\.\d{{1,3}}){{3}}))$")
_CODE = re.compile(r"^[A-Z0-9_]{1,64}$")
_ID = re.compile(r"^[a-z]{1,8}-[0-9a-f]{8,17}$")


def _read_errors() -> tuple[type[BaseException], ...]:
    """How a read can fail: AWS's own errors (botocore, when installed), the network's (DNS included), an answer of the
    wrong shape."""
    try:
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError)
    return (BotoCoreError, ClientError, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError)


READ_ERRORS = _read_errors()


@dataclass(frozen=True)
class Path:
    source: str
    destination: str
    port: int

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

    def traces(self, alert: Alert) -> list[str]:
        return []

    def metrics(self, alert: Alert) -> dict[str, float]:
        return {}

    def logs(self, alert: Alert) -> list[str]:
        wanted = chosen(alert, self._configured)
        if not wanted:
            return []
        try:
            made = self._clients(alert)
            ec2 = made["ec2"]
            done = self._already(ec2, alert.alert_id)
        except READ_ERRORS as exc:  # a read that did not happen, never a reachable path
            return [f"{PARTIAL}reachability: {type(exc).__name__} - not read"]
        room = max(0, MAX_PER_INCIDENT - done)
        out: list[str] = []
        if room < len(wanted):
            out.append(f"{PARTIAL}reachability: {done} of {MAX_PER_INCIDENT} analyses already run for this incident "
                       f"- {len(wanted) - room} path(s) not analysed again")
        started = []
        for path in wanted[:room]:
            got = self._start(made, path, alert)
            if isinstance(got, str):
                out.append(got)
            else:
                started.append(got)
        try:
            return out + self._results(ec2, started)
        except READ_ERRORS as exc:  # started and billed, but its answer not read: said, never a reachable path
            return [*out, f"{PARTIAL}reachability: {type(exc).__name__} reading the analyses - not read"]

    # ------------------------------------------------------------------ the cap

    @staticmethod
    def _already(ec2: Any, incident: str) -> int:
        """Paths already made for this incident, in the account: each one is one analysis WARDEN ran (and paid for)."""
        count, token = 0, ""
        for _ in range(PATH_PAGES):
            page = ec2.describe_network_insights_paths(**({"NextToken": token} if token else {}))
            count += sum(1 for p in page.get("NetworkInsightsPaths") or []
                         if {"Key": TAG_INCIDENT, "Value": incident[:128]} in (p.get("Tags") or []))
            token = str(page.get("NextToken") or "")
            if not token:
                return count
        return MAX_PER_INCIDENT  # more paths than WARDEN reads: never risk a third analysis

    # ------------------------------------------------------------------ one analysis

    def _start(self, made: Any, path: Path, alert: Alert) -> tuple[Path, str] | str:
        try:
            source = self._source(made, path.source)
            destination = self._destination(made, path.destination)
        except READ_ERRORS as exc:  # an unresolved end is a path not analysed, and nothing is billed
            return f"{PARTIAL}reachability {path.source}: {type(exc).__name__} resolving it - not analysed"
        if not source or not destination:
            return f"{PARTIAL}reachability {path.source}: no network interface or address found - not analysed"
        tags = [{"Key": "Environment", "Value": self._environment(alert)}, {"Key": TAG_INCIDENT,
                                                                            "Value": alert.alert_id[:128]},
                {"Key": "Purpose", "Value": PURPOSE}]
        ec2 = made["ec2"]
        try:
            made_path = ec2.create_network_insights_path(
                Source=source, Protocol="tcp", DestinationPort=path.port, ClientToken=f"{alert.alert_id[:40]}-{path}"[:64],
                **({"DestinationIp": destination} if _is_ip(destination) else {"Destination": destination}),
                TagSpecifications=[{"ResourceType": "network-insights-path", "Tags": tags}])
            path_id = made_path["NetworkInsightsPath"]["NetworkInsightsPathId"]
            run = ec2.start_network_insights_analysis(
                NetworkInsightsPathId=path_id, ClientToken=f"{path_id}-run",
                TagSpecifications=[{"ResourceType": "network-insights-analysis", "Tags": tags}])
        except READ_ERRORS as exc:  # refused or failed: said, never a reachable path
            return f"{PARTIAL}reachability {path.source}: {type(exc).__name__} - not analysed"
        return path, str(run["NetworkInsightsAnalysis"]["NetworkInsightsAnalysisId"])

    def _source(self, made: Any, source: str) -> str:
        fn, cluster, service, raw = _SOURCE.match(source).groups()
        if raw:
            return raw
        if fn:
            enis = made["ec2"].describe_network_interfaces(Filters=[
                {"Name": "description", "Values": [f"AWS Lambda VPC ENI-{fn}-*", f"AWS Lambda VPC ENI-{fn}"]}])
            found = sorted(str(n.get("NetworkInterfaceId")) for n in enis.get("NetworkInterfaces") or [])
            return found[0] if found else ""
        ecs = made["ecs"]
        tasks = ecs.list_tasks(cluster=cluster, serviceName=service, desiredStatus="RUNNING").get("taskArns") or []
        if not tasks:
            return ""
        described = ecs.describe_tasks(cluster=cluster, tasks=sorted(tasks)[:1]).get("tasks") or []
        for t in described:
            for att in t.get("attachments") or []:
                for d in att.get("details") or []:
                    if d.get("name") == "networkInterfaceId":
                        return str(d.get("value") or "")
        return ""

    def _destination(self, made: Any, destination: str) -> str:
        aurora, rds, raw, ip = _DEST.match(destination).groups()
        if raw or ip:
            return raw or ip
        if aurora:
            found = made["rds"].describe_db_clusters(DBClusterIdentifier=aurora).get("DBClusters") or []
            host = str((found[0] if found else {}).get("Endpoint") or "")
        else:
            found = made["rds"].describe_db_instances(DBInstanceIdentifier=rds).get("DBInstances") or []
            host = str(((found[0] if found else {}).get("Endpoint") or {}).get("Address") or "")
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
            for a in got.get("NetworkInsightsAnalyses") or []:
                if a.get("Status") != "running" and a.get("NetworkInsightsAnalysisId") in pending:
                    answers[a["NetworkInsightsAnalysisId"]] = a
                    pending.pop(a["NetworkInsightsAnalysisId"])
            if pending:
                self._sleep(POLL_S)
        out = [_line(path, answers[aid]) for path, aid in started if aid in answers]
        out += [f"{PARTIAL}reachability {path.source}: analysis {aid} still running after {WAIT_S:g}s - not read"
                for path, aid in started if aid not in answers]
        return out


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
