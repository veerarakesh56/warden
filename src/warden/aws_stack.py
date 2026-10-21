"""The full-stack evidence backend (`WARDEN_BACKEND=stack`) - the full-stack lab, docs/FULLSTACK-LAB.md.

Same three-method contract as every other backend. The alert's labels name the application's
resources (docs/FULLSTACK-LAB.md section 4, contract A); one READER per resource reads it, and the metric names and
line formats it emits are exactly contract B, C and D.

Deliberate:

1. **Each reader is isolated.** A reader that raises becomes one `TOOL-PARTIAL <reader>: <reason>`
   line (which `gather()` moves into `tool_errors`, where policy P8 reads it). It never costs the
   other readers their evidence and it is never silent.

2. **One read, three views.** `gather()` asks for logs, then metrics, then deploys. A reader reads
   its resource once and yields all three, so the whole snapshot is taken on the first call and the
   other two return from it. That is also what lets a failed METRIC read reach `tool_errors`: a
   `dict[str, float]` cannot carry a TOOL-PARTIAL string, the log list can. Readers run in parallel
   - a dozen sequential API reads would not fit one tool budget.

3. **Absent is not zero.** A CloudWatch series with no datapoint is left out, never filled with 0.

4. **Reuse.** ECS is `AwsBackend`, Kubernetes is `KubernetesBackend` (one per Deployment), the
   Aurora session reads are `DatabaseBackend` on the writer and reader DSNs. Their lines are
   re-tagged per contract C; their metric names are unchanged. Windows, timeouts and the retry cap
   are aws_backend's own constants, imported, not copied.

5. **Read-only.** No write API, no `secretsmanager:GetSecretValue` (DescribeSecret: metadata only),
   no `s3:GetObject`, no `ssm:GetParameter*`. The Lambda deployment package is fetched through the
   pre-signed URL `lambda:GetFunction` returns, into memory, capped, never to disk. The IAM role in
   terraform/fullstack/reader.tf is the boundary; tests/test_aws_stack.py asserts its actions equal
   the calls in this module (and aws_backend's) in both directions.
"""

from __future__ import annotations

import fnmatch
import io
import json
import os
import re
import threading
import time
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any

from . import settings
from .aws_backend import (
    CONNECT_TIMEOUT,
    LOG_LOOKBACK,
    METRIC_PERIOD_S,
    METRIC_WINDOW,
    READ_TIMEOUT,
    RECENT_DEPLOY_WINDOW,
    AwsBackend,
    _aware,
    _one_line,
)
from .environments import strip_prefix
from .models import Alert
from .tools import PARTIAL_PREFIX, ToolError, deploy_in_window, failure, status_tag

# Re-exported so the report/harness can import the windows from the backend they describe.
__all__ = [
    "CODE_MAX_BYTES",
    "LOG_LOOKBACK",
    "METRIC_PERIOD_S",
    "METRIC_WINDOW",
    "RECENT_DEPLOY_WINDOW",
    "SOURCE_CONTEXT_LINES",
    "StackBackend",
]

# A deployment package larger than this is not downloaded (a TOOL-PARTIAL says so).
CODE_MAX_BYTES = int(os.environ.get("WARDEN_STACK_CODE_MAX_BYTES", str(20 * 1024 * 1024)))
SOURCE_CONTEXT_LINES = 3
MAX_CODE_FRAMES = 3  # distinct tracebacks per function turned into CODE/SOURCE lines
# Lambda rollback target: the version that served `live` traffic in this long before the current
# version was published, among the newest SERVED_CANDIDATES older versions (_served_before).
SERVED_LOOKBACK = timedelta(hours=6)
SERVED_CANDIDATES = 10
# Register C8: a version is known-good when it served KNOWN_GOOD of unbroken SERVED_PERIOD periods with invocations
# and no error. One rule for the evidence (the report's "previous") and the plan (the version moved back to).
KNOWN_GOOD = timedelta(minutes=30)
SERVED_PERIOD = 300  # seconds
# CloudWatch namespaces and names read below, each named once.
LAMBDA_NAMESPACE = "AWS/Lambda"
DYNAMODB_NAMESPACE = "AWS/DynamoDB"
RDS_NAMESPACE = "AWS/RDS"
ALB_NAMESPACE = "AWS/ApplicationELB"
APIGW_NAMESPACE = "AWS/ApiGateway"
LATEST_VERSION = "$LATEST"  # Lambda's unpublished version
SUM_PER_SECOND = "Sum/s"  # _cw_read: the busiest period's per-second rate
DB_LOAD_METRIC = "db.load.avg"  # Performance Insights' database load


def served_queries(fn: str, alias: str, cands: list[str]) -> list[dict]:
    """GetMetricData queries: each candidate version's invocations (v<i>) and errors (e<i>) on the alias."""
    def spec(prefix: str, metric: str) -> list[dict]:
        return [{"Id": f"{prefix}{i}", "ReturnData": True, "MetricStat": {
            "Metric": {"Namespace": LAMBDA_NAMESPACE, "MetricName": metric, "Dimensions": [
                {"Name": "FunctionName", "Value": fn}, {"Name": "Resource", "Value": f"{fn}:{alias}"},
                {"Name": "ExecutedVersion", "Value": v}]}, "Period": SERVED_PERIOD, "Stat": "Sum"}}
                for i, v in enumerate(cands)]
    return spec("v", "Invocations") + spec("e", "Errors")


def _stamp(t: Any) -> datetime | None:
    if isinstance(t, datetime):
        return t if t.tzinfo else t.replace(tzinfo=UTC)
    try:
        return datetime.fromisoformat(str(t))
    except ValueError:
        return None


def last_known_good(results: list[dict], cands: list[str]) -> str:
    """Of `cands`, the version whose latest known-good stretch ended latest - the state just before the change - or ""
    when none was known-good. Not the one that served most (live, 2026-10-16, fs-01: the broken version 4 had served
    3.5 erring hours, the good version 3 two clean hours up to the change) and not the one that served last (Wave 4,
    2026-09-26: a broken version served a few calls after the good one's hours)."""
    series = _served_series(results, cands)
    ended: dict[str, datetime] = {}
    for v in cands:
        end = _last_good_end(series.get(("v", v), {}), series.get(("e", v), {}))
        if end is not None:
            ended[v] = end
    return max(ended, key=lambda v: (ended[v], int(v))) if ended else ""


def _served_series(results: list[dict], cands: list[str]) -> dict[tuple[str, str], dict[datetime, float]]:
    """{("v" calls | "e" errors, version): {period start: value}} from the metric results `v<i>` / `e<i>` (index into
    `cands`); a result of another id, or a time that cannot be read, is left out."""
    series: dict[tuple[str, str], dict[datetime, float]] = {}
    for r in results:
        rid = str(r.get("Id", ""))
        if rid[:1] in ("v", "e") and rid[1:].isdigit() and int(rid[1:]) < len(cands):
            series[(rid[0], cands[int(rid[1:])])] = {
                s: float(n) for t, n in zip(r.get("Timestamps") or [], r.get("Values") or [], strict=False)
                if (s := _stamp(t)) is not None}
    return series


def _last_good_end(calls: dict[datetime, float], errors: dict[datetime, float]) -> datetime | None:
    """The last period of the latest unbroken run of serving, error-free periods at least KNOWN_GOOD long, or None."""
    good = sorted(t for t, n in calls.items() if n > 0 and not errors.get(t))
    end, start = None, 0
    for i in range(1, len(good) + 1):
        if i == len(good) or (good[i] - good[i - 1]).total_seconds() != SERVED_PERIOD:
            if (i - start) * SERVED_PERIOD >= KNOWN_GOOD.total_seconds():
                end = good[i - 1]
            start = i
    return end

_TRACEBACK = "Traceback (most recent call last):"
_FRAME = re.compile(r'File "([^"]+)", line (\d+), in (\S+)')
_EXCEPTION = re.compile(r"^(?:\[ERROR\]\s++)?([A-Za-z_][\w.]*+)(?::\s*+(.*))?$")  # possessive: nothing to hand back (Sonar python:S8786, 2026-10-16)
_LAMBDA_ERROR = "[ERROR]"  # how the Lambda runtime starts the line naming an unhandled exception
_STREAM_VERSION = re.compile(r"\[(\d+|\$LATEST)\]")


class _Out:
    """One reader's evidence."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.metrics: dict[str, float] = {}
        self.deploys: list[dict] = []


LIST_MAX_PAGES = int(os.environ.get("WARDEN_AWS_LIST_MAX_PAGES", "20"))


def _pages(call, items: str, *, token: str = "Marker", next_token: str | None = None, **kwargs) -> tuple[list, bool]:
    """Every page of an AWS listing, up to LIST_MAX_PAGES: (items, truncated). One page was read, and a long history
    or a busy account lost what came after it (audit A-B-M8, A-B-L3, A-B-L4)."""
    out: list = []
    for _ in range(LIST_MAX_PAGES):
        page = call(**kwargs)
        out += page.get(items) or []
        nxt = page.get(next_token or token)
        if not nxt:
            return out, False
        kwargs[token] = nxt
    return out, True


def _names(alert: Alert, key: str) -> list[str]:
    return [n.strip() for n in (alert.labels.get(key) or "").split(",") if n.strip()]


def _suffix(name: str, several: bool) -> str:
    return f"__{strip_prefix(name)}" if several else ""


def _z(dt: datetime | None) -> str:
    dt = _aware(dt)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else "?"


def _parse_time(value) -> datetime | None:
    """boto3 datetimes, or Lambda's `2026-09-26T10:00:01.000+0000` strings."""
    if isinstance(value, datetime):
        return _aware(value)
    try:
        return _aware(datetime.fromisoformat(str(value)))
    except (TypeError, ValueError):
        return None


# Logs Insights (requirement R22): error-looking lines per minute. A count, never the text.
INSIGHTS_QUERY = ("filter @message like /(?i)(error|exception|fatal|panic|timed? ?out|refused|denied)/ "
                  "| stats count(*) as n by bin(1m)")
INSIGHTS_WAIT_S = float(os.environ.get("WARDEN_LOGS_INSIGHTS_WAIT_S", "10"))


def _error_code(exc) -> str:
    return (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")


def _retag_aws_line(tag: str, line: str) -> str:
    """AwsBackend's `<stream> <iso> <message>` -> `LOG <tag> <Z> <message>`."""
    _stream, stamp, message = (line.removeprefix("LOG ").split(" ", 2) + ["", ""])[:3]
    return f"LOG {tag} {_z(_parse_time(stamp))} {message}"


# The clients every StackBackend holds; a test fakes each (a missing one is built for real - G10-C2 was red in CI).
NEEDED_CLIENTS = ("lambda", "logs", "cloudwatch", "ecs", "sqs", "dynamodb", "elasticache", "rds", "elbv2",
                  "apigatewayv2", "secretsmanager", "sns", "events", "sts", "ec2", "eks", "pi", "cloudtrail",
                  "autoscaling", "stepfunctions")
# Research 2026-10-15, item 9: an AccessDenied in the evidence, checked against the role's own policies with the IAM
# policy simulator. AWS's standard denial text names the action and, usually, the resource; the ROLE simulated is only
# ever one the trusted configuration names (a TASKROLE line) in the incident's environment - a log line chooses at
# most which action is simulated, read-only, never whose permissions are read.
_DENIED = re.compile(r"is not authorized to perform: ([a-z0-9-]{2,40}:[A-Za-z0-9*]{2,80})"
                     r"(?: on resource: (arn:aws[a-z-]{0,20}:[A-Za-z0-9:/_.*+=,@-]{3,400}))?")
_TASKROLE_LINE = re.compile(r"^TASKROLE (?:ecs|lambda)/\S+ role=([A-Za-z0-9+=,.@_-]{1,64})$")
SIMULATE_MAX = 3
# Research 2026-10-15, item 10: how far back an alarm's own history is read.
ALARM_HISTORY = timedelta(hours=24)
# G10-C1: an ECS service's last stopped tasks, its events in the hour before the alert, and how each is classified.
STOPPED_TASKS = 10
ECS_EVENT_WINDOW = timedelta(hours=1)
_ECS_EVENT_KINDS = (
    ("health_check_failed", re.compile(r"failed (?:container|ELB) health checks|is unhealthy in target-group", re.IGNORECASE)),
    ("unable_to_place", re.compile(r"unable to place a task", re.IGNORECASE)),
    ("deployment_failed", re.compile(r"deployment failed|circuit breaker", re.IGNORECASE)),
    ("steady_state", re.compile(r"has reached a steady state", re.IGNORECASE)),
    ("started_tasks", re.compile(r"has started \d+ tasks", re.IGNORECASE)),
    ("stopped_tasks", re.compile(r"has stopped \d+ running tasks", re.IGNORECASE)),
)
# Why ECS could not place a task, from its own words (G10 held-out set, 2026-10-10: counting the events hid that the
# cluster had run out of network interfaces). The first that matches; the rest stay plain `unable_to_place`.
_PLACE_WHY = (
    ("eni", re.compile(r"RESOURCE:ENI", re.IGNORECASE)),
    ("memory", re.compile(r"RESOURCE:MEMORY|insufficient memory", re.IGNORECASE)),
    ("cpu", re.compile(r"RESOURCE:CPU|insufficient CPU", re.IGNORECASE)),
    ("ports", re.compile(r"RESOURCE:PORTS|already-used port", re.IGNORECASE)),
    ("gpu", re.compile(r"RESOURCE:GPU|insufficient GPU", re.IGNORECASE)),
    ("no_instances", re.compile(r"no container instances were found", re.IGNORECASE)),
    ("constraints", re.compile(r"did not match required attributes|placement constraint|MemberOf", re.IGNORECASE)),
)
# G10-C4: the writes that cut a workload off the network, and the request keys that name what they wrote to.
_NETWORK_EVENTS = ("RevokeSecurityGroupEgress", "RevokeSecurityGroupIngress", "ModifySecurityGroupRules",
                   "DeleteRoute", "ReplaceRoute", "ReplaceRouteTableAssociation", "DisassociateRouteTable",
                   "DeleteNetworkAclEntry", "ReplaceNetworkAclEntry", "ReplaceNetworkAclAssociation")
_NETWORK_ID_KEYS = frozenset({"groupid", "routetableid", "associationid", "networkaclid"})


def _request_ids(request: dict) -> list[str]:
    """The ids an EC2 write's request names: `groupId` at the top (RevokeSecurityGroupEgress), or `GroupId` one level
    down in the newer APIs' request wrapper (ModifySecurityGroupRules)."""
    found = [v for k, v in request.items() if k.lower() in _NETWORK_ID_KEYS and isinstance(v, str)]
    for inner in (v for v in request.values() if isinstance(v, dict)):
        found += [v for k, v in inner.items() if k.lower() in _NETWORK_ID_KEYS and isinstance(v, str)]
    return found
_NETWORK_SYMPTOM = re.compile(r"i/o timeout|dial tcp|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|ECONNREFUSED|network is "
                              r"unreachable|no route to host|context deadline exceeded|cause=network", re.IGNORECASE)
# G10-C2: node groups, scaling activities and failed executions read per incident.
NODEGROUPS = 10
ASG_ACTIVITIES = 20
SFN_FAILURES = 3
_ASG_CAUSES = (
    ("scheduled", re.compile(r"scheduled action", re.IGNORECASE)),
    ("health_check", re.compile(r"health check|unhealthy", re.IGNORECASE)),
    ("policy", re.compile(r"policy|alarm", re.IGNORECASE)),
    ("instance_refresh", re.compile(r"instance refresh", re.IGNORECASE)),
    ("rebalance", re.compile(r"rebalanc", re.IGNORECASE)),
    ("spot", re.compile(r"spot", re.IGNORECASE)),
    ("manual", re.compile(r"user request|SetDesiredCapacity|UpdateAutoScalingGroup", re.IGNORECASE)),
)
_CAPACITY_CHANGE = re.compile(r"capacity from (\d{1,6}) to (\d{1,6})", re.IGNORECASE)
# AWS's own stoppedReason and container reasons, classified - first match wins. The order matters: a secret that does
# not exist before a denied one, both before the network (a pull that timed out), the network before an image.
_STOP_CAUSES = (
    ("secret_missing", re.compile(r"ResourceNotFoundException|ParameterNotFound|secret[^.]{0,80}(?:not found|does not exist|marked for deletion)",
                                  re.IGNORECASE)),
    ("permission", re.compile(r"AccessDenied|not authorized|UnauthorizedOperation|is not permitted", re.IGNORECASE)),
    ("network", re.compile(r"i/o timeout|dial tcp|context deadline exceeded|network is unreachable|no route to host|"
                           r"connection refused|could not resolve|no such host", re.IGNORECASE)),
    ("image", re.compile(r"CannotPullContainerError|manifest unknown|pull access denied|not found: manifest", re.IGNORECASE)),
    ("oom", re.compile(r"OutOfMemory|out of memory|OOMKilled", re.IGNORECASE)),
    ("health_check", re.compile(r"health check", re.IGNORECASE)),
)


def _head_and_tail(text: str, limit: int) -> str:
    """At most `limit` characters, keeping both ends: ECS puts the decisive exception at the END of a long
    stoppedReason (G10 held-out set, 2026-10-10: "...because it was marked for deletion" was cut off)."""
    if len(text) <= limit:
        return text
    head = limit // 2
    return f"{text[:head]} ... {text[-(limit - head - 5):]}"


def task_stop_cause(stop_code: str, reason: str, exit_codes: list) -> str:
    """One stopped task's cause, from a closed set: what an ECS task stopped for, decided from AWS's own words."""
    for cause, rx in _STOP_CAUSES:
        if rx.search(reason):
            return cause
    if 137 in exit_codes:
        return "oom"
    if stop_code == "EssentialContainerExited" or "Essential container" in reason:
        return "exit"
    return {"UserInitiated": "user", "ServiceSchedulerInitiated": "scheduler", "SpotInterruption": "spot",
            "TerminationNotice": "spot", "TaskFailedToStart": "failed_to_start"}.get(stop_code, "unknown")


# The universal alarm reader (G9-A2a): how many of the resource's other metrics, and CloudTrail's limits.
SIBLING_METRICS = int(os.environ.get("WARDEN_ALARM_SIBLING_METRICS", "12"))
MATH_PARTS = 5  # a metric-math alarm's metrics read (its expression never is)
CHANGE_NAMES = 3
CHANGE_MAX = 20
_READ_VERBS = ("Describe", "Get", "List", "Lookup", "BatchGet", "Head", "Search", "Scan", "Query")
CHANGE_PAGES = 5
# CloudTrail lists a management event about 5 minutes after the call, with no guarantee (AWS CloudTrail FAQ, research
# 2026-10-15). Until the alert is this old, "no write" only means none was delivered yet - the change just before an
# alarm, the likeliest cause, may not be listed.
CLOUDTRAIL_DELIVERY = timedelta(minutes=int(os.environ.get("WARDEN_CLOUDTRAIL_DELIVERY_MIN", "8")))
# Writes CloudTrail files WITHOUT the resource's name, so a lookup by resource name never finds them (live,
# 2026-10-12: a schedule switched off nine minutes before its alarm was read as "CHANGE none", and the report ruled a
# change out). For a resource of these kinds the reader also looks the writes up by event name and keeps the ones
# whose request names the resource: (the event names, the request fields that carry the name).
UNNAMED_WRITES = {"eventbridge_rule": (("DisableRule", "EnableRule", "PutRule", "DeleteRule", "PutTargets",
                                        "RemoveTargets"), ("name", "rule"))}
# A queue's consumer switched off or removed (fs-07, live, 2026-10-15): CloudTrail files the write as Lambda's
# UpdateEventSourceMapping20150331 with no resource name, only the mapping's id - so a lookup by the queue's name never
# found it, and "who changed it" was left out. The queue's own mappings (by its ARN) say which ids are its.
QUEUE_MAPPING_WRITES = ("UpdateEventSourceMapping20150331", "DeleteEventSourceMapping20150331")
# Labels that qualify a resource rather than name one: never looked up as a CloudTrail resource name.
_NOT_RESOURCES = frozenset({"lambda_qualifier", "apigw_stage", "namespace", "quota_service", "quota_resource"})


def _a_write(e: dict) -> bool:
    """A write that happened: read-only events and attempts that failed or were denied are not changes (an attempt
    is anyone's to make - independent review 2026-10-10, M2)."""
    try:
        detail = json.loads(e.get("CloudTrailEvent") or "{}")
    except ValueError:
        detail = {}
    if detail.get("errorCode"):
        return False
    ro = e.get("ReadOnly")
    if ro is None:
        ro = detail.get("readOnly")
    if ro is None:
        return not str(e.get("EventName", "")).startswith(_READ_VERBS)
    return str(ro).lower() == "false"


# A request's top-level field names are AWS's API member names (`desiredCount`, `forceNewDeployment`), never a value.
_FIELD_NAME = re.compile(r"[A-Za-z][A-Za-z0-9]{0,40}")


def _request_names(e: dict, fields: tuple[str, ...], name: str) -> bool:
    """Does this event's recorded request name the resource, in one of the fields its service uses for it?"""
    try:
        r = json.loads(e.get("CloudTrailEvent") or "{}").get("requestParameters")
    except ValueError:
        return False
    return isinstance(r, dict) and any(str(r.get(f, "")).rsplit("/", 1)[-1] == name for f in fields)


def _request_fields(e: dict) -> str:
    """` request=<names>`: which fields the recorded request named - an UpdateService that set the desired count is not
    a forced redeploy (G10 held-out baseline, 2026-10-10: g10-135 missed a desired-count cut, and a forced redeploy's
    UpdateService read as one WARDEN could undo). The values are never shown."""
    try:
        r = json.loads(e.get("CloudTrailEvent") or "{}").get("requestParameters")
    except ValueError:
        return ""
    if not isinstance(r, dict):
        return ""
    keys = sorted(k for k in r if isinstance(k, str) and _FIELD_NAME.fullmatch(k))[:12]
    return f" request={','.join(keys)}" if keys else ""


def _principal(e: dict) -> str:
    """Who made a change, by KIND and an administrator-set name (a role's or an IAM user's), never the caller-chosen
    session name or an SSO e-mail (independent review 2026-10-10, M1)."""
    try:
        who = json.loads(e.get("CloudTrailEvent") or "{}").get("userIdentity") or {}
    except ValueError:
        who = {}
    kind = _safe(who.get("type") or "unknown")
    if kind == "AssumedRole":
        return _role(who)
    if kind == "IAMUser":
        return f"user/{_safe(who.get('userName'))}" if who.get("userName") else "user"
    if kind == "AWSService":
        return f"service/{_safe(who.get('invokedBy'))}" if who.get("invokedBy") else "service"
    return kind


def _role(who: dict) -> str:
    """An assumed role's actor: `role/<the role's name>`, or `role` when CloudTrail did not name it."""
    role = ((who.get("sessionContext") or {}).get("sessionIssuer") or {}).get("userName")
    # An IAM Identity Center role ends in an opaque 16-hex id: with it the redactor's entropy backstop hid the
    # whole actor, `role/` included, and a person's change read `by <HIGHENTROPY_1>` (G10 held-out, 2026-10-11).
    if role and str(role).startswith("AWSReservedSSO_"):
        role = re.sub(r"_[0-9a-f]{16}$", "", str(role))
    return f"role/{_safe(role)}" if role else "role"


def _safe(value) -> str:
    """An AWS-returned name or code as one token: anything else becomes `_` (no space, no quote, no newline)."""
    return re.sub(r"[^A-Za-z0-9._:/@=+-]", "_", str(value if value is not None else "-"))[:120] or "-"


def _dims(dims: dict[str, str]) -> str:
    return ",".join(f"{_safe(k)}={_safe(v)}" for k, v in sorted(dims.items())) or "-"


def _key(name: str) -> str:
    """`ApproximateNumberOfMessagesVisible` -> `approximatenumberofmessagesvisible`; a metric key, never text."""
    return re.sub(r"[^a-z0-9]+", "_", str(name).lower()).strip("_")[:60] or "metric"


_PLAIN_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def _plain(name) -> str:
    """A name its owner writes freely, in a TRUSTED line only when it is a plain name (review-e L8)."""
    return str(name) if isinstance(name, str) and _PLAIN_NAME.fullmatch(name) else "(name-withheld)"


def _metric_queries(queries: dict) -> tuple[dict[str, tuple[str, str]], list[dict]]:
    """_cw_read's GetMetricData queries: ({query id: (key, stat)}, the queries), one per `queries` item in order."""
    ids, specs = {}, []
    for i, (key, q) in enumerate(queries.items()):
        ids[f"m{i}"] = (key, q[-1])
        if q[0] == "expr":
            specs.append({"Id": f"m{i}", "Expression": q[1], "Period": METRIC_PERIOD_S})
        else:
            ns, metric, dims, stat = q
            specs.append({"Id": f"m{i}", "ReturnData": True, "MetricStat": {
                "Metric": {"Namespace": ns, "MetricName": metric,
                           "Dimensions": [{"Name": k, "Value": v} for k, v in dims.items()]},
                "Period": METRIC_PERIOD_S, "Stat": stat.split("/")[0]}})
    return ids, specs


def _series_value(stat: str, values: list) -> float:
    """One series' value over the window: a `Sum` is summed (a count), `Sum/s` is the busiest period's per-second rate,
    every other stat is the max."""
    if stat == "Sum":
        return float(sum(values))
    if stat == SUM_PER_SECOND:
        return float(max(values) / METRIC_PERIOD_S)
    return float(max(values))


def _change_lines(out: _Out, n: str, events: list[dict], broke: Exception | None, truncated: bool,
                  started: datetime) -> None:
    """_read_changes' lines for the resource named `n`: its newest CHANGE_MAX writes, then why the list may be short -
    a failed lookup, more writes than read, CloudTrail not yet delivering, or no write in the window."""
    events.sort(key=lambda e: str(e.get("EventTime") or ""), reverse=True)
    writes = [e for e in events if _a_write(e)]
    lines = out.lines
    for e in writes[:CHANGE_MAX]:
        lines.append(f"CHANGE {_z(e.get('EventTime'))} {_safe(e.get('EventSource'))} "
                     f"{_safe(e.get('EventName'))} on {_safe(n)} by {_principal(e)}{_request_fields(e)}")
    if broke is not None:
        lines.append(_partial("changes", broke))
    elif truncated or len(writes) > CHANGE_MAX:
        lines.append(_partial("changes", f"[output truncated on LookupEvents] more writes to {_safe(n)} "
                                         "than were read"))
    elif not writes and datetime.now(UTC) - started < CLOUDTRAIL_DELIVERY:
        age = max(0, int((datetime.now(UTC) - started).total_seconds() // 60))
        lines.append(f"CHANGE none delivered yet on {_safe(n)}: the alert is {age} min old and CloudTrail "
                     "lists a write about 5 minutes after it, so a write just before the alert may be missing")
    elif not writes:
        lines.append(f"CHANGE none on {_safe(n)} in the {int(RECENT_DEPLOY_WINDOW.total_seconds() // 3600)} h "
                     "before the alert")


def _elasticache_queries(members: list[str]) -> dict[str, tuple]:
    """_cw_read queries for each cache node: `<metric>#<node index>`."""
    queries = {}
    for i, node in enumerate(members):
        d = {"CacheClusterId": node}
        for metric, stat in (("DatabaseMemoryUsagePercentage", "Maximum"), ("Evictions", "Sum"),
                             ("CurrConnections", "Maximum"), ("EngineCPUUtilization", "Maximum"),
                             ("ReplicationLag", "Maximum")):
            queries[f"{metric}#{i}"] = ("AWS/ElastiCache", metric, d, stat)
    return queries


def _ingress_sources(g: dict, port: int) -> list[str]:
    """Who security group `g` lets in on tcp/`port`, sorted."""
    rules = [r for r in g.get("IpPermissions") or [] if r.get("IpProtocol") in ("-1", "tcp")
             and (r.get("IpProtocol") == "-1" or r.get("FromPort", 0) <= port <= r.get("ToPort", 0))]
    # Groups, CIDR ranges and prefix lists alike (audit A-B-L5): a rule opening the port to a CIDR or a
    # prefix list was read as no rule at all.
    return sorted({p["GroupId"] for r in rules for p in r.get("UserIdGroupPairs") or []}
                  | {x["CidrIp"] for r in rules for x in r.get("IpRanges") or [] if x.get("CidrIp")}
                  | {x["CidrIpv6"] for r in rules for x in r.get("Ipv6Ranges") or [] if x.get("CidrIpv6")}
                  | {x["PrefixListId"] for r in rules for x in r.get("PrefixListIds") or []
                     if x.get("PrefixListId")})


def _datapoint_values(m: dict) -> list:
    """A Performance Insights metric's numeric datapoint values (a bool is not a number here)."""
    return [p["Value"] for p in m.get("DataPoints") or []
            if isinstance(p.get("Value"), int | float) and not isinstance(p.get("Value"), bool)]


def _member_load(out: _Out, name: str, got: dict) -> None:
    """_db_load for one member: its load (and by wait-event type) as metrics, and its TOP_SQL busiest statements'
    shapes as STATE lines."""
    top: list[tuple[float, str]] = []
    for m in got.get("MetricList") or []:
        values = _datapoint_values(m)
        if not values:
            continue
        dims = (m.get("Key") or {}).get("Dimensions") or {}
        if "db.sql_tokenized.statement" in dims:
            top.append((float(max(values)), str(dims.get("db.sql_tokenized.statement") or "")))
            continue
        kind = dims.get("db.wait_event_type.name")
        key = "aurora_db_load" + (f"_{re.sub(r'[^a-z0-9]', '', str(kind).lower())[:20]}" if kind else "")
        out.metrics[key] = max(out.metrics.get(key, 0.0), float(max(values)))
    total = out.metrics.get("aurora_db_load", 0.0)
    for rank, (load, sql) in enumerate(sorted(top, key=lambda t: -t[0])[:TOP_SQL], start=1):
        share = f" ({load / total:.0%} of the load)" if total else ""
        out.lines.append(f"STATE aurora {_one_line(name)} top-sql #{rank} load={load:.2f}{share} "
                         f"{sql_shape(sql)}")


def _insights_counts(got: dict) -> list[float]:
    """The per-minute error counts (field `n`) in a Logs Insights query's results; a value that is not a number is
    skipped."""
    counts = []
    for row in got.get("results") or []:
        for f in row:
            if f.get("field") == "n":
                try:
                    counts.append(float(f.get("value")))
                except (TypeError, ValueError):
                    continue
    return counts


def _ecs_deploy(service: str, d: dict) -> dict:
    """One ECS deploy as evidence."""
    # `version`/`previous` are family:revision (what a rollback aims at); the images ride along.
    return {"kind": "ecs", "service": service, "at": _z(_parse_time(d["at"])),
            "version": d.get("task_definition", ""),
            "previous": d.get("previous_task_definition", ""),
            "image": d.get("image", ""), "previous_image": d.get("previous_image", ""),
            "revision": d.get("revision", ""),
            # a rollback: nothing to roll back to, and the evidence says so (audit A-B-M6)
            **({"rolled_back_from": d["rolled_back_from"]} if d.get("rolled_back_from") else {}),
            # a config-only revision: the setting NAMES it changed (G10: dropped here before)
            **({"changed": d["changed"]} if d.get("changed") else {})}


def _network_change_lines(out: _Out, name: str, events: list[dict], ids: dict[str, str]) -> int:
    """_read_network_changes for one event name: a CHANGE line for each write whose request names one of the
    workload's `ids`; how many there were."""
    found = 0
    for e in events:
        if not _a_write(e):
            continue
        try:
            request = json.loads(e.get("CloudTrailEvent") or "{}").get("requestParameters") or {}
        except ValueError:
            request = {}
        hit = next((v for v in _request_ids(request) if v in ids), None)
        if hit:
            found += 1
            out.lines.append(f"CHANGE {_z(e.get('EventTime'))} ec2.amazonaws.com {_safe(name)} on {_safe(hit)} "
                             f"(this workload's {ids[hit]}) by {_principal(e)}")
    return found


def _ecs_event_kinds(svc: dict, started: datetime) -> dict[str, int]:
    """The service's own events in the ECS_EVENT_WINDOW before the alert (to 5 minutes after), counted by kind; an
    unplaceable task's kind says why it could not be placed."""
    kinds: dict[str, int] = {}
    for e in svc.get("events") or []:
        at = _parse_time(e.get("createdAt"))
        if at is None or not started - ECS_EVENT_WINDOW <= at <= started + timedelta(minutes=5):
            continue
        message = str(e.get("message", ""))
        kind = next((k for k, rx in _ECS_EVENT_KINDS if rx.search(message)), "other")
        if kind == "unable_to_place":
            kind += next((f"_{why}" for why, rx in _PLACE_WHY if rx.search(message)), "")
        kinds[kind] = kinds.get(kind, 0) + 1
    return kinds


def _stopped_task_lines(out: _Out, service: str, t: dict) -> str:
    """One stopped task: a STATE line with AWS's stop code and the cause it is classified as, and an EVENT line with
    its reason text (quarantined downstream). Returns the cause."""
    reason = " ".join([str(t.get("stoppedReason") or "")]
                      + [str(c.get("reason") or "") for c in t.get("containers") or []])
    exits = [c.get("exitCode") for c in t.get("containers") or [] if c.get("exitCode") is not None]
    cause = task_stop_cause(str(t.get("stopCode") or ""), reason, exits)
    out.lines.append(
        f"STATE ecs/{service} stopped task {_safe(str(t.get('taskArn', '')).rsplit('/', 1)[-1][:8])} "
        f"at={_z(_parse_time(t.get('stoppedAt')))} "
        f"revision={_safe(str(t.get('taskDefinitionArn', '')).rsplit('/', 1)[-1])} "
        f"stop={_safe(t.get('stopCode'))} cause={cause}" + (f" exit={int(exits[0])}" if exits else ""))
    if reason.strip():
        out.lines.append(f"EVENT ecs/{service} stopped task: {_head_and_tail(reason.strip(), 400)}")
    return cause


def _alarm_threshold(a: dict) -> str:
    """How the alarm fires, from its structured fields: operator, threshold, datapoints, missing data and state."""
    return (f"threshold {_safe(a.get('ComparisonOperator'))} {a.get('Threshold')} "
            f"datapoints={a.get('DatapointsToAlarm') or a.get('EvaluationPeriods')}/{a.get('EvaluationPeriods')} "
            f"missing={_safe(a.get('TreatMissingData') or 'missing')} state={_safe(a.get('StateValue'))}")


def _simulated_resource(resource: str, account: str, prefix: str) -> str:
    """The resource the IAM simulator is asked about: "*" (the action alone) for another account's resource, or one
    that is not this environment's."""
    if resource == "*":
        return resource
    in_account = f":{account}:" in resource or ":::" in resource
    if in_account and prefix in resource:
        return resource
    return "*"  # another account's, or not this environment's: the action alone is asked


def _partial(reader: str, line_or_exc) -> str:
    text = line_or_exc if isinstance(line_or_exc, str) else failure(line_or_exc)
    return f"{PARTIAL_PREFIX}{reader}: {text.removeprefix(PARTIAL_PREFIX)}"


# --------------------------------------------------------------------------- tracebacks (5a)


def parse_tracebacks(lines: list[str]) -> list[dict]:
    """Innermost `/var/task` frame of every Python traceback in `lines`.

    Lines are physical lines in log order; a traceback that CloudWatch stored as one event (Lambda's
    own `[ERROR] X: y` + `\\r`-joined frames) and one split over several events look the same here.
    The exception is taken from the line after the frames (the `logging.exception` shape) or, when
    none follows, from the `[ERROR] X: y` line before the traceback (the Lambda runtime shape).
    `lines` are (text, version) pairs; the version comes from the log stream name, so the source is
    read from the package that actually ran. Returns dicts with path (relative to /var/task), line,
    func, exception, version.
    """
    found: list[dict] = []
    i = 0
    while i < len(lines):
        text, version = lines[i]
        at = text.find(_TRACEBACK)
        if at < 0:
            i += 1
            continue
        frames, j = _frames(lines, i + 1)
        exception = (_exception_after(lines, j) if frames else "") or _exception_before(lines, i, text[:at])
        ours = [f for f in frames if f[0].startswith("/var/task/")]
        if ours:
            path, line_no, func = ours[-1]
            found.append({
                "path": path.removeprefix("/var/task/"), "line": line_no, "func": func,
                "exception": exception or "?", "version": version,
            })
        i = max(j, i + 1)
    return found


def _frames(lines: list, j: int) -> tuple[list[tuple[str, int, str]], int]:
    """The (path, line, function) frames from line `j` on, and the index of the first line after them."""
    frames: list[tuple[str, int, str]] = []
    while j < len(lines):
        nxt = lines[j][0]
        m = _FRAME.search(nxt)
        if m:
            frames.append((m.group(1), int(m.group(2)), m.group(3)))
        elif not nxt.strip() or nxt[:1].isspace():
            pass  # the source line under a frame
        else:
            break
        j += 1
    return frames, j


def _exception_before(lines: list, i: int, head: str) -> str:
    """The `[ERROR] X: y` the Lambda runtime writes before a traceback - on its line, or the line before - or ""."""
    before = head.strip() or (lines[i - 1][0].strip() if i else "")
    if before.startswith(_LAMBDA_ERROR):
        return before.removeprefix(_LAMBDA_ERROR).strip()
    return ""


def _exception_after(lines: list, j: int) -> str:
    """The exception line at `j` (the `logging.exception` shape), its `[ERROR]` dropped, or ""."""
    if j < len(lines) and _EXCEPTION.match(lines[j][0].strip()):
        return lines[j][0].strip().removeprefix(_LAMBDA_ERROR).strip()
    return ""


def source_excerpt(fn: str, package: bytes, path: str, line_no: int) -> list[str]:
    """SOURCE lines, +-SOURCE_CONTEXT_LINES around `line_no`, read from a zip held in memory. Only a Python file of the
    package: the path comes from traceback text in the logs, which anyone writing a log line controls, and a forged
    `File "/var/task/.env"` read the package's .env into the evidence (audit A-B-M17)."""
    parts = path.split("/")
    if not path.endswith(".py") or any(p in ("", ".", "..") for p in parts) or "\\" in path:
        raise ValueError(f"not a Python source path: {path!r}")
    with zipfile.ZipFile(io.BytesIO(package)) as zf:
        text = zf.read(path).decode("utf-8", errors="replace").splitlines()
    lo = max(1, line_no - SOURCE_CONTEXT_LINES)
    hi = min(len(text), line_no + SOURCE_CONTEXT_LINES)
    return [
        f"SOURCE {fn} {path}:{n} {'>|' if n == line_no else '|'} {text[n - 1]}"
        for n in range(lo, hi + 1)
    ]


def _download(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ToolError("code location is not an https URL")
    with urllib.request.urlopen(url, timeout=READ_TIMEOUT) as resp:  # nosec B310
        data = resp.read(CODE_MAX_BYTES + 1)
    if len(data) > CODE_MAX_BYTES:
        raise ToolError(f"deployment package larger than {CODE_MAX_BYTES} bytes, not read")
    return data


# --------------------------------------------------------------------------- the backend


# A value is shown only when it is plainly configuration: a secret-looking NAME, or a value that could
# break the `env=[A=b,C=d]` line (separators, spaces, quotes), is shown as the name alone. The report's
# fix for a wrong variable rewrites the whole environment and so is printed ONLY when every value is
# present - a masked or missing value can therefore never be written back into a function.
# Added 2026-09-25: with names only, no bad-env / write-to-reader / pinned-endpoint fix could be aimed.
_SECRETISH = re.compile(r"PASS|SECRET|TOKEN|KEY|CREDENTIAL|DSN|AUTH|PRIVATE|SESSION", re.IGNORECASE)
_PLAIN_VALUE = re.compile(r"[A-Za-z0-9._:/@-]{0,200}")


# The names whose values are configuration a diagnosis needs: which table, host, queue, region, timeout. An allowlist
# (audit A-B-M9): the name deny-list showed `DATABASE_URL=postgres://user:pw@db/x` and any credential under a name it
# did not list. A value is shown only under one of these names, and never with a login in it.
_SHOWN_NAME = re.compile(r"(?:^|_)(?:NAME|HOST|HOSTNAME|ENDPOINT|TABLE|QUEUE|TOPIC|BUCKET|REGION|PORT|STAGE|ENV|"
                         r"ENVIRONMENT|MODE|LEVEL|TIMEOUT|SECONDS|MS|SIZE|LIMIT|VERSION|SERVICE|DATABASE|DB|SCHEMA|"
                         r"CLUSTER|ARN|USER)$")


def _env_items(variables: dict) -> list[str]:
    out = []
    for name in sorted(variables):
        value = str(variables[name])
        shown = (_SHOWN_NAME.search(name.upper()) and not _SECRETISH.search(name) and _PLAIN_VALUE.fullmatch(value)
                 and "@" not in value and "://" not in value)
        out.append(f"{name}={value}" if shown else name)
    return out


def _sdk_clients(clients: Any, own: bool, region: str | None) -> tuple[Any, Any, Any]:
    """(clients, session, cfg): the clients that were not injected, made with the AWS SDK. Every client injected: the
    clients as given and no session or cfg."""
    missing = [n for n in NEEDED_CLIENTS if n not in clients]
    if not missing:
        return clients, None, None
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:
        raise ToolError(
            "WARDEN_BACKEND=stack needs the AWS SDK: pip install -e '.[aws]'"
        ) from exc
    cfg = Config(
        connect_timeout=CONNECT_TIMEOUT, read_timeout=READ_TIMEOUT,
        retries={"max_attempts": 1, "mode": "standard"},  # see aws_backend note 2
        user_agent_extra="warden",
    )
    region = region or os.environ.get("WARDEN_AWS_REGION") or None
    try:
        from .aws_backend import _LazyClients

        session = boto3.session.Session(region_name=region)
        clients = _LazyClients(session, cfg) if own else clients
        for n in missing:
            clients[n] = session.client(n, config=cfg)
    except Exception as exc:
        raise ToolError(
            "WARDEN_BACKEND=stack but no usable AWS credentials or region were found: "
            f"{_one_line(exc)}"
        ) from exc
    return clients, session, cfg


class StackBackend:
    """Reads every resource the alert's labels name, one isolated reader each."""
    reads_live_store = True  # its store receives log lines late: evidence waits for them (R23)
    # How long one whole read may take (tools.gather): every resource the alert names, in parallel, a Logs Insights
    # query among them (INSIGHTS_WAIT_S, 10 s alone) - and, behind grafana.WithSources, each outside source after it.
    # The 5 s per-tool default cut such a read off and lost the logs view (inventory review, 2026-10-15).
    read_timeout_s = float(os.environ.get("WARDEN_STACK_READ_TIMEOUT_S", "120"))


    name = "stack"

    def __init__(self, *, clients: dict | None = None, k8s_factory=None, db_factory=None,
                 download=None, region: str | None = None) -> None:
        # Injectable clients/factories so the unit tests need no AWS account, cluster or database.
        own = not clients  # nothing injected: this backend makes its clients (and, in the runtime, per incident)
        # A mapping that makes clients on first use is kept as given: copied into a plain dict, every service past
        # the first eighteen read "no client" in the cloud (independent review 2026-10-10, H1).
        clients = clients if hasattr(clients, "__missing__") else dict(clients or {})
        clients, session, cfg = _sdk_clients(clients, own, region)
        self._lambda = clients["lambda"]
        self._logs = clients["logs"]
        self._cw = clients["cloudwatch"]
        self._ecs = clients["ecs"]
        self._sqs = clients["sqs"]
        self._ddb = clients["dynamodb"]
        self._ec = clients["elasticache"]
        self._rds = clients["rds"]
        self._elb = clients["elbv2"]
        self._apigw = clients["apigatewayv2"]
        self._sm = clients["secretsmanager"]
        self._sns = clients["sns"]
        self._events = clients["events"]
        self._sts = clients["sts"]
        self._ec2 = clients["ec2"]
        self._eks = clients["eks"]
        self._pi = clients["pi"]
        self._ct = clients["cloudtrail"]
        self._asg = clients["autoscaling"]
        self._sfn = clients["stepfunctions"]
        self._clients = clients  # every other service's client, made when an alarm names one (aws_describe.py)
        # The IAM policy simulator, for an AccessDenied in the evidence (research 2026-10-15, item 9): made on first use
        # where the clients are; a test that injects no IAM client simulates nothing.
        self._iam = clients["iam"] if hasattr(clients, "__missing__") or "iam" in clients else None
        self._account_id = ""
        self._sleep = time.sleep
        # AwsBackend over the SAME clients: its logs read also serves the Lambda log groups.
        self._aws = AwsBackend(logs=self._logs, cloudwatch=self._cw, ecs=self._ecs)
        self._k8s_factory = k8s_factory or _default_k8s
        self._db_factory = db_factory or _default_db
        self._download = download or _download
        self._lock = threading.Lock()
        self._snap: tuple[tuple, object] | None = None
        # The cloud runtime (WARDEN_AWS_ROLE_ARN_TEMPLATE): every incident is read in its own environment's reader
        # role, `warden-<env>-platform-reader`, under the incident's name - never the worker's own role (G9-A2b).
        template = os.environ.get("WARDEN_AWS_ROLE_ARN_TEMPLATE", "").strip()
        self._per_env = None
        self._bound: dict[tuple[str, str], tuple[float, StackBackend]] = {}
        if template and own:
            from .aws_backend import _reader_clients

            self._per_env = _reader_clients(session, cfg, template, NEEDED_CLIENTS)

    # ------------------------------------------------------------------ the contract

    def logs(self, alert: Alert) -> list[str]:
        return self._incident(alert)._snapshot(alert).lines

    def metrics(self, alert: Alert) -> dict[str, float]:
        return self._incident(alert)._snapshot(alert).metrics

    def deploys(self, alert: Alert) -> list[dict]:
        return self._incident(alert)._snapshot(alert).deploys

    def _incident(self, alert: Alert) -> StackBackend:
        """This backend, or - in the cloud runtime - one over the incident's own reader-role clients. An environment
        the policy does not know, or a refused role, is a ToolError: a failed read, never a read as the worker."""
        if vars(self).get("_per_env") is None:
            return self
        # G10-F1: an alarm from another Region (AWS's global-services one, for CloudFront and Route 53) is read there -
        # its alarm, its metrics, the writes CloudTrail recorded - in the same environment's reader role.
        region = alert.labels.get("alarm_region", "")
        clients = self._per_env(alert.environment, alert.alert_id, region) if region else \
            self._per_env(alert.environment, alert.alert_id)
        key = (alert.environment, alert.alert_id, region)  # never id(): a recycled id would hand one incident another's
        with self._lock:
            now = time.monotonic()
            for k in [k for k, (until, _) in self._bound.items() if until <= now]:
                del self._bound[k]
            hit = self._bound.get(key)
            if hit is None or hit[1]._clients is not clients:  # a renewed session: a backend over the new clients
                hit = (now + 600, StackBackend(clients=clients, k8s_factory=self._k8s_factory,
                                               db_factory=self._db_factory, download=self._download))
                self._bound[key] = hit
        return hit[1]

    def _snapshot(self, alert: Alert) -> _Out:
        """Read everything once per alert; the three methods are views of it (note 2).

        The future is shared, so a `metrics()` call after a timed-out `logs()` waits on the same
        read instead of starting a second one.
        """
        key = (alert.alert_id, alert.started_at, tuple(sorted(alert.labels.items())))
        with self._lock:
            if self._snap is None or self._snap[0] != key:
                pool = ThreadPoolExecutor(max_workers=1)
                self._snap = (key, pool.submit(self._read_all, alert))
                pool.shutdown(wait=False)
            future = self._snap[1]
        return future.result()

    def _readers(self, alert: Alert) -> list[tuple[str, object]]:
        """(reader name, callable filling an _Out) for every resource the labels name."""
        lab = alert.labels
        fns, queues, rules, deps = (_names(alert, k) for k in ("lambda", "sqs", "eventbridge_rule", "deployment"))
        readers: list[tuple[str, object]] = []
        # Any alarm on any service (G9-A2a): the alarm as CloudWatch defines it, its metric and the resource's others,
        # and the writes to the resource. The per-service readers below add each service's own state.
        # Not for a Datadog monitor's alert: its `alarm` label is the monitor (`datadog-<id>`), not a CloudWatch alarm,
        # and the read was refused as a CloudWatch read of a name no reader may read (2026-10-15, fs-22).
        if lab.get("alarm") and not lab.get("datadog_monitor"):
            readers.append(("alarm", lambda out: self._read_alarm(out, alert, lab["alarm"])))
        # The state of any other main service's resource the alarm names (G9-A2c): one closed table of reads.
        from . import aws_describe

        readers += [(key.replace("_", "-"), lambda out, key=key: self._read_state(out, key, lab[key]))
                    for key in aws_describe.TABLE if lab.get(key)]
        # G10-C2: what the group did and why (a scheduled scale-in, a failed launch), and why executions failed.
        if lab.get("asg"):
            readers.append(("asg-activity", lambda out: self._read_asg_activity(out, alert, lab["asg"])))
        if lab.get("state_machine"):
            readers.append(("states-failures", lambda out: self._read_sfn_failures(out, lab["state_machine"])))
        readers += [(f"lambda/{f}", lambda out, f=f: self._read_lambda(out, alert, f, _suffix(f, len(fns) > 1))) for f in fns]
        readers += [(f"sqs/{q}", lambda out, q=q: self._read_sqs(out, alert, q, _suffix(q, len(queues) > 1))) for q in queues]
        readers += self._data_and_traffic_readers(alert)
        readers += self._platform_readers(alert, deps, rules)
        return readers

    def _data_and_traffic_readers(self, alert: Alert) -> list[tuple[str, object]]:
        """_readers, continued: the data stores the labels name, then the load balancer, the API and the ECS service."""
        lab = alert.labels
        readers: list[tuple[str, object]] = []
        if lab.get("dynamodb_table"):
            readers.append(("dynamodb", lambda out: self._read_dynamodb(out, alert, lab["dynamodb_table"])))
        if lab.get("elasticache"):
            readers.append(("elasticache", lambda out: self._read_elasticache(out, alert, lab["elasticache"])))
        if lab.get("aurora_cluster"):
            readers.extend([
                ("aurora", lambda out: self._read_aurora(out, alert, lab["aurora_cluster"])),
                ("aurora-db-writer", lambda out: self._read_db(out, "WARDEN_STACK_DB_PRIMARY_RO_DSN", "", alert)),
                ("aurora-db-reader", lambda out: self._read_db(out, "WARDEN_STACK_DB_REPLICA_RO_DSN", "reader_", alert)),
            ])
        if lab.get("alb_target_group"):
            readers.append(("alb", lambda out: self._read_alb(out, alert, lab["alb_target_group"])))
        if lab.get("apigw"):
            readers.append(("apigw", lambda out: self._read_apigw(out, alert, lab["apigw"])))
        if lab.get("ecs_cluster") and lab.get("ecs_service"):
            readers.append(("ecs", lambda out: self._read_ecs(out, alert)))
        return readers

    def _platform_readers(self, alert: Alert, deps: list[str], rules: list[str]) -> list[tuple[str, object]]:
        """_readers, continued: the Kubernetes Deployments, the EKS cluster, the secret, the topic and the rules."""
        lab = alert.labels
        readers: list[tuple[str, object]] = []
        ns = lab.get("namespace")
        if ns:
            readers += [(f"k8s/{d}", lambda out, d=d: self._read_k8s(out, alert, ns, d, f"__{d}" if len(deps) > 1 else ""))
                        for d in deps]
        if lab.get("eks_cluster"):
            readers.append(("eks", lambda out: self._read_eks(out, lab["eks_cluster"])))
        if lab.get("secret"):
            readers.append(("secret", lambda out: self._read_secret(out, alert, lab["secret"])))
        if lab.get("sns_topic"):
            readers.append(("sns", lambda out: self._read_sns(out, alert, lab["sns_topic"])))
        readers += [(f"eventbridge/{r}", lambda out, r=r: self._read_rule(out, alert, r, _suffix(r, len(rules) > 1)))
                    for r in rules]
        return readers

    def _read_all(self, alert: Alert) -> _Out:
        readers = self._readers(alert)
        total = _Out()
        if not readers:
            raise ToolError("the alert names no stack resource (contract A labels)")

        def run(item):
            # The reader writes into `out` as it goes, so what it read before failing is kept.
            name, fn = item
            out = _Out()
            try:
                fn(out)
            except Exception as exc:  # noqa: BLE001 - one reader failing is data (note 1)
                out.lines.append(_partial(name, exc))
            return out

        pool = ThreadPoolExecutor(max_workers=len(readers))
        try:
            results = list(pool.map(run, readers))
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        for r in results:
            total.lines += r.lines
            total.metrics.update(r.metrics)
            total.deploys += r.deploys
        try:
            self._simulate_denials(total, alert)
        except Exception as exc:  # noqa: BLE001 - the evidence read stands without it
            total.lines.append(_partial("iam-simulate", exc))
        return total

    def _simulate_denials(self, out: _Out, alert: Alert) -> None:
        """Each AccessDenied in the evidence for an action a trusted TASKROLE line's role performs, run through the IAM
        policy simulator: `STATE iam simulate role=... action=... resource=... decision=...` - whether the role's own
        policies allow it, and which statement decided. "allowed" means the denial came from elsewhere: a resource
        policy, a boundary, a session policy or an organization policy."""
        from .environments import names

        prefix = names(alert.environment).prefix + "-"
        roles = sorted({m.group(1) for line in out.lines if (m := _TASKROLE_LINE.match(line))
                        and m.group(1).startswith(prefix)})
        asked = list(dict.fromkeys((m.group(1), m.group(2) or "*") for line in out.lines
                                   for m in _DENIED.finditer(line)))
        if not roles or not asked or self._iam is None:
            return
        account = self._account()
        for action, resource in asked[:SIMULATE_MAX]:
            resource = _simulated_resource(resource, account, prefix)
            for role in roles:
                out.lines += self._simulate(account, role, action, resource)

    def _simulate(self, account: str, role: str, action: str, resource: str) -> list[str]:
        """_simulate_denials for one role, action and resource: the simulator's first decision as one STATE line."""
        got = self._iam.simulate_principal_policy(PolicySourceArn=f"arn:aws:iam::{account}:role/{role}",
                                                  ActionNames=[action], ResourceArns=[resource])
        results = got.get("EvaluationResults") or []
        if not results:
            return []
        r = results[0]
        by = sorted({str(s.get("SourcePolicyId", "")) for s in r.get("MatchedStatements") or []
                     if s.get("SourcePolicyId")})[:3]
        return [(f"STATE iam simulate role={role} action={_safe(action)} "
                 f"resource={_safe(resource)} decision={_safe(r.get('EvalDecision'))} "
                 f"by={','.join(_safe(b) for b in by) or 'none'}")]

    # ------------------------------------------------------------------ shared helpers

    def _window(self, alert: Alert):
        started = AwsBackend._started_at(alert)
        return started, started - METRIC_WINDOW, started + METRIC_WINDOW

    def _cw_read(self, out: _Out, reader: str, alert: Alert, queries: dict) -> dict[str, float]:
        """`{key: (namespace, metric, dims, stat)}` or `{key: ("expr", expression, "Sum")}`.

        One GetMetricData call. A series with no datapoint is absent. `Sum` series are summed over
        the window (a count), `Sum/s` is the busiest period's per-second rate (comparable with a
        provisioned capacity), every other stat takes the max. A failed read is a TOOL-PARTIAL for
        this reader; the reader's API evidence survives it.
        """
        if not queries:
            return {}
        _, start, end = self._window(alert)
        ids, specs = _metric_queries(queries)
        try:
            resp = self._cw.get_metric_data(MetricDataQueries=specs, StartTime=start, EndTime=end,
                                            ScanBy="TimestampDescending")
        except Exception as exc:  # noqa: BLE001
            out.lines.append(_partial(f"{reader} metrics", exc))
            return {}
        got: dict[str, float] = {}
        for res in resp.get("MetricDataResults") or []:
            values = res.get("Values") or []
            if res.get("Id") in ids and res.get("StatusCode") not in (None, "Complete"):
                # A series CloudWatch could not finish is said, not read as complete (audit A-B-M18).
                out.lines.append(_partial(f"{reader} metrics", f"{status_tag(res['StatusCode'])} {ids[res['Id']][0]} "
                                          f"{res['StatusCode']} (the series may be incomplete)"))
            if res.get("Id") in ids and values:
                key, stat = ids[res["Id"]]
                got[key] = _series_value(stat, values)
        return got

    def alarm_firing(self, alert: Alert) -> bool | None:
        """Is the alert's own CloudWatch alarm in ALARM now? None: it names none, or none by that name exists."""
        name = alert.labels.get("alarm", "")
        if not name or alert.labels.get("datadog_monitor"):
            return None  # a Datadog monitor's alert names no CloudWatch alarm
        found = self._incident(alert)._cw.describe_alarms(
            AlarmNames=[name], AlarmTypes=["MetricAlarm", "CompositeAlarm"])
        states = [a.get("StateValue") for kind in ("MetricAlarms", "CompositeAlarms") for a in found.get(kind) or []]
        return states[0] == "ALARM" if states else None

    def _read_alarm(self, out: _Out, alert: Alert, name: str) -> None:
        """Any alarm, any service (G9-A2a): the alarm exactly as CloudWatch defines it - never its name's or its
        description's text - its own metric over the window, the resource's other recently active metrics, and the
        writes to the resource in CloudTrail. Before this an alarm on anything but the named readers' resources read
        nothing (audit 2026-10-10)."""
        found = self._cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"]).get("MetricAlarms") or []
        if not found:
            raise ToolError("no metric alarm by that name (a composite alarm is read through the alarms it names)")
        a = found[0]
        self._read_appconfig(out, str(a.get("AlarmArn") or ""))
        self._alarm_history(out, alert, name)
        ns, metric = a.get("Namespace"), a.get("MetricName")
        dims = {str(d.get("Name")): str(d.get("Value")) for d in a.get("Dimensions") or []}
        threshold = _alarm_threshold(a)
        if not (ns and metric):  # metric math: the expression is the owner's text, not read
            self._read_math_alarm(out, alert, a, threshold)
            return
        stat = a.get("Statistic") or a.get("ExtendedStatistic") or "Maximum"
        out.lines.append(f"ALARM {_safe(ns)}/{_safe(metric)} {_dims(dims)} stat={_safe(stat)} "
                         f"period={a.get('Period')}s {threshold}")
        # Metric KEYS are trusted evidence ids' names (M items): only AWS's own namespaces' metric names become keys.
        # A custom namespace is the application's - anyone who can publish a metric, a log line in CloudWatch's
        # embedded metric format included, names it (independent review 2026-10-10, H2).
        aws_owned = str(ns).startswith("AWS/")
        out.metrics.update(self._cw_read(out, "alarm", alert, {
            (f"alarm_{_key(metric)}" if aws_owned else "alarm_value"): (ns, metric, dims, stat)}))
        if aws_owned:
            self._read_alarm_siblings(out, alert, ns, metric, dims)
        self._read_changes(out, alert, dims)

    def _read_math_alarm(self, out: _Out, alert: Alert, a: dict, threshold: str) -> None:
        """_read_alarm for a metric-math alarm: the expression is the owner's text, not read."""
        # Its parts are AWS's structured fields, read like a plain alarm's metric (G10 review, 2026-10-10: an API
        # Gateway fault behind a math alarm showed no symptom at all). AWS's own namespaces only, as below.
        parts = [q["MetricStat"] for q in a.get("Metrics") or [] if isinstance(q.get("MetricStat"), dict)]
        out.lines.append(f"ALARM metric-math parts={len(parts)} {threshold}")
        reads: dict[str, tuple] = {}
        for q in parts[:MATH_PARTS]:
            m = q.get("Metric") or {}
            pns, pmetric, pstat = m.get("Namespace"), m.get("MetricName"), q.get("Stat") or "Maximum"
            pdims = {str(d.get("Name")): str(d.get("Value")) for d in m.get("Dimensions") or []}
            if not (pns and pmetric):
                continue
            out.lines.append(f"ALARM part {_safe(pns)}/{_safe(pmetric)} {_dims(pdims)} stat={_safe(pstat)} "
                             f"period={q.get('Period')}s")
            if str(pns).startswith("AWS/"):
                reads[f"alarm_part_{_key(pns.split('/')[-1])}_{_key(pmetric)}"] = (pns, pmetric, pdims, pstat)
        out.metrics.update(self._cw_read(out, "alarm", alert, reads))
        self._read_changes(out, alert, {})

    def _read_alarm_siblings(self, out: _Out, alert: Alert, ns: str, metric: str, dims: dict[str, str]) -> None:
        """The resource's other recently active metrics in the alarm's (AWS-owned) namespace, same dimensions."""
        listed, _ = _pages(self._cw.list_metrics, "Metrics", token="NextToken", Namespace=ns,
                           Dimensions=[{"Name": k, "Value": v} for k, v in dims.items()], RecentlyActive="PT3H")
        others: dict[str, tuple] = {}
        for m in listed:
            other = str(m.get("MetricName") or "")
            same = {str(d.get("Name")): str(d.get("Value")) for d in m.get("Dimensions") or []} == dims
            if other and other != metric and same and len(others) < SIBLING_METRICS:
                others[f"alarm_sibling_{_key(ns.split('/')[-1])}_{_key(other)}"] = (ns, other, dims, "Maximum")
        out.metrics.update(self._cw_read(out, "alarm-siblings", alert, others))

    def _alarm_history(self, out: _Out, alert: Alert, name: str) -> None:
        """Research 2026-10-15, item 10: the alarm's own history in the ALARM_HISTORY before the alert, from AWS's
        structured fields only (never the summary text) - how often it changed state and went into ALARM (a flapping
        alarm), and when its settings last changed (a threshold moved under it)."""
        started = AwsBackend._started_at(alert)
        try:
            got = self._cw.describe_alarm_history(AlarmName=name, StartDate=started - ALARM_HISTORY,
                                                  EndDate=started + timedelta(minutes=5), MaxRecords=100,
                                                  ScanBy="TimestampDescending")
        except Exception as exc:  # noqa: BLE001 - the alarm and its metric stand without it
            out.lines.append(_partial("alarm history", exc))
            return
        items = got.get("AlarmHistoryItems") or []
        states = [i for i in items if i.get("HistoryItemType") == "StateUpdate"]

        def _new_state(item: dict) -> str:
            try:
                return str(((json.loads(item.get("HistoryData") or "{}").get("newState")) or {}).get("stateValue"))
            except (ValueError, AttributeError):
                return ""
        into = sum(_new_state(i) == "ALARM" for i in states)
        configs = [i for i in items if i.get("HistoryItemType") == "ConfigurationUpdate"]
        out.lines.append(f"ALARM history {int(ALARM_HISTORY.total_seconds() // 3600)}h before the alert: "
                         f"state_changes={len(states)} into_alarm={into} "
                         f"last_config_update={_z(_parse_time(configs[0].get('Timestamp'))) if configs else 'none'}"
                         + (" (more than one page)" if got.get("NextToken") else ""))

    def _read_appconfig(self, out: _Out, alarm_arn: str) -> None:
        """G9-D: the AppConfig configuration this alarm guards (its environment's monitors name the alarm) and that
        environment's latest deployment - what revert_config would stop and revert."""
        from . import aws_describe

        if not alarm_arn or ("appconfig" not in self._clients and not hasattr(self._clients, "__missing__")):
            return
        try:
            client = self._clients["appconfig"]
            pairs, _complete = aws_describe.appconfig_for_alarm(client, alarm_arn)
            for app, env in pairs[:3]:
                d = aws_describe.latest_deployment(client, app["Id"], env["Id"])
                if d:
                    done = d.get("CompletedAt")
                    out.lines.append(
                        f"CONFIG appconfig {_plain(app.get('Name'))}/{_plain(env.get('Name'))} monitors this alarm: "
                        f"deployment={d.get('DeploymentNumber')} state={_safe(d.get('State'))} "
                        f"version={_safe(d.get('VersionLabel') or d.get('ConfigurationVersion'))} completed="
                        f"{done.strftime('%Y-%m-%dT%H:%M:%SZ') if hasattr(done, 'strftime') else 'not yet'}")
        except Exception as exc:  # noqa: BLE001 - the alarm's own evidence stands without it
            out.lines.append(_partial("appconfig", exc))

    def _read_state(self, out: _Out, key: str, name: str) -> None:
        from . import aws_describe

        d = aws_describe.TABLE[key]
        if d.service not in self._clients and not hasattr(self._clients, "__missing__"):
            raise ToolError(f"no {d.service} client")
        out.lines.append(aws_describe.read(key, name, self._clients[d.service], self._account, self._cw.meta.region_name))

    def _account(self) -> str:
        if not self._account_id:
            self._account_id = str(self._sts.get_caller_identity()["Account"])
        return self._account_id

    def _read_changes(self, out: _Out, alert: Alert, dims: dict[str, str]) -> None:
        """Writes to the alarm's resource in the RECENT_DEPLOY_WINDOW before the alert (CloudTrail management events;
        change is the leading cause of outages - research 2026-10-10). A CloudTrail lookup takes one resource name
        per call and two calls a second per account, so the first CHANGE_NAMES names only."""
        from .resources import LABEL_KEYS

        started = AwsBackend._started_at(alert)
        # The alarm's resources first (their labels), never generic dimension values (`default`, a stage name).
        names = [v for k, v in sorted(alert.labels.items()) if k in LABEL_KEYS and k not in _NOT_RESOURCES and v]
        kind_of = {v: k for k, v in alert.labels.items() if k in UNNAMED_WRITES}
        names += [v for v in dims.values() if v not in names] if not names else []
        window = {"StartTime": started - RECENT_DEPLOY_WINDOW, "EndTime": started + timedelta(minutes=5)}
        for n in list(dict.fromkeys(names))[:CHANGE_NAMES]:
            events, broke, truncated = self._lookup_writes(n, window)
            if broke is None:
                broke, more = self._unnamed_writes(events, n, kind_of.get(n, ""), window)
                truncated = truncated or more
            if broke is None and alert.labels.get("sqs") == n:
                broke, more = self._queue_mapping_writes(events, n, window)
                truncated = truncated or more
            _change_lines(out, n, events, broke, truncated, started)

    def _lookup_writes(self, n: str, window: dict) -> tuple[list[dict], Exception | None, bool]:
        """CloudTrail's events on the resource named `n` in the window, CHANGE_PAGES pages at most: (the events read,
        the lookup's error or None, whether more pages were left unread)."""
        events: list[dict] = []
        kwargs = {"LookupAttributes": [{"AttributeKey": "ResourceName", "AttributeValue": n}], **window}
        for _ in range(CHANGE_PAGES):
            try:
                got = self._ct.lookup_events(**kwargs)
            except Exception as exc:  # noqa: BLE001 - CloudTrail allows 2 lookups a second; keep what was read
                return events, exc, False
            events += got.get("Events") or []
            if not got.get("NextToken"):
                return events, None, False
            kwargs["NextToken"] = got["NextToken"]
        return events, None, True

    def _unnamed_writes(self, events: list[dict], n: str, kind: str, window: dict) -> tuple[Exception | None, bool]:
        """The writes to a `kind` of resource whose CloudTrail record names no resource (UNNAMED_WRITES): looked up by
        event name and kept when the request names `n`. Added to `events`; (the lookup's error or None, whether a
        lookup had more than one page)."""
        event_names, fields = UNNAMED_WRITES.get(kind, ((), ()))
        truncated = False
        for event_name in event_names:
            try:
                got = self._ct.lookup_events(
                    LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}], **window)
            except Exception as exc:  # noqa: BLE001
                return exc, truncated
            truncated = truncated or bool(got.get("NextToken"))
            seen = {e.get("EventId") for e in events if e.get("EventId")}
            events += [e for e in got.get("Events") or []
                       if e.get("EventId") not in seen and _request_names(e, fields, n)]
        return None, truncated

    def _queue_mapping_writes(self, events: list[dict], n: str, window: dict) -> tuple[Exception | None, bool]:
        """The writes to the event source mappings AWS holds for queue `n` (they name the mapping, not the queue).
        Added to `events`; (the lookup's error or None, whether a lookup had more than one page)."""
        try:
            mine = self._queue_mappings(n)
        except Exception:  # noqa: BLE001 - the queue's own reader says its read failed; no change is ruled out
            mine = set()
        truncated = False
        try:
            for event_name in QUEUE_MAPPING_WRITES if mine else ():
                got = self._ct.lookup_events(
                    LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}], **window)
                truncated = truncated or bool(got.get("NextToken"))
                seen = {e.get("EventId") for e in events if e.get("EventId")}
                events += [e for e in got.get("Events") or [] if e.get("EventId") not in seen
                           and any(_request_names(e, ("uUID",), u) for u in mine)]
        except Exception as exc:  # noqa: BLE001 - CloudTrail allows 2 lookups a second; keep what was read
            return exc, truncated
        return None, truncated

    def _served_before(self, fn: str, candidates: list[str], before: datetime) -> str:
        """The version `live` last served while known-good in the SERVED_LOOKBACK before `before` (the current
        version's publish time), or "" when none was (last_known_good: the plan reads the same rule).

        ⛔ Not "the numerically previous version". A version that was deployed and rolled back is
        still the newest older one: Wave 4 (2026-09-26) rolled checkout back onto the previous
        fault's broken version twice (fs-01 -> 6, fs-02 -> 7) while version 3 had served the traffic
        for hours. Lambda keeps no alias history; its ExecutedVersion metric does.
        """
        cands = candidates[-SERVED_CANDIDATES:]
        if not cands:
            return ""
        try:
            resp = self._cw.get_metric_data(MetricDataQueries=served_queries(fn, "live", cands),
                                            StartTime=before - SERVED_LOOKBACK, EndTime=before)
        except Exception:  # noqa: BLE001 - no traffic data: the caller falls back; and says so
            return ""
        return last_known_good(resp.get("MetricDataResults") or [], cands)

    def _in_window(self, alert: Alert, at: datetime | None) -> bool:
        return deploy_in_window(alert, at, RECENT_DEPLOY_WINDOW)

    # ------------------------------------------------------------------ lambda

    def _read_lambda(self, out: _Out, alert: Alert, fn: str, sfx: str) -> None:
        # Logs first: they carry the traceback, and a failed config read must not cost them.
        self._lambda_logs(alert, fn, out)
        self._insights(out, alert, f"/aws/lambda/{fn}", f"lambda/{fn}", sfx)
        live, cfg = self._lambda_live_config(out, fn)
        conc = self._lambda.get_function_concurrency(FunctionName=fn).get("ReservedConcurrentExecutions")
        versions = self._lambda_versions(out, fn)
        self._lambda_config_lines(out, alert, fn, sfx, cfg, conc, versions, live)
        self._lambda_mappings(out, fn, sfx)
        self._lambda_deploy(out, alert, fn, versions, live)
        dims = {"FunctionName": fn}
        out.metrics.update(self._cw_read(out, f"lambda/{fn}", alert, {
            f"lambda_errors{sfx}": (LAMBDA_NAMESPACE, "Errors", dims, "Sum"),
            f"lambda_throttles{sfx}": (LAMBDA_NAMESPACE, "Throttles", dims, "Sum"),
            f"lambda_invocations{sfx}": (LAMBDA_NAMESPACE, "Invocations", dims, "Sum"),
            f"lambda_duration_max_ms{sfx}": (LAMBDA_NAMESPACE, "Duration", dims, "Maximum"),
            f"lambda_concurrent_executions{sfx}": (LAMBDA_NAMESPACE, "ConcurrentExecutions", dims, "Maximum"),
        }))

    def _lambda_live_config(self, out: _Out, fn: str) -> tuple[str | None, dict]:
        """(the version the `live` alias points at or None, the configuration it serves - else the function's)."""
        alias = None
        try:
            alias = self._lambda.get_alias(FunctionName=fn, Name="live")
        except Exception as exc:  # noqa: BLE001
            if _error_code(exc) != "ResourceNotFoundException":  # no alias is normal
                out.lines.append(_partial(f"lambda/{fn} alias", exc))
        live = (alias or {}).get("FunctionVersion")
        cfg = (self._lambda.get_function_configuration(FunctionName=fn, Qualifier="live")
               if live else self._lambda.get_function_configuration(FunctionName=fn))
        # G10-C2: a function that cannot run says why in two closed codes (an ENI limit, a deleted image, a KMS key
        # it may not use, a subnet out of addresses) - shown only when it is not simply Active and updated.
        if cfg.get("State", "Active") != "Active" or cfg.get("LastUpdateStatus", "Successful") == "Failed":
            out.lines.append(f"STATE lambda {fn} state={_safe(cfg.get('State'))} reason={_safe(cfg.get('StateReasonCode'))} "
                             f"last_update={_safe(cfg.get('LastUpdateStatus'))} "
                             f"update_reason={_safe(cfg.get('LastUpdateStatusReasonCode'))}")
        return live, cfg

    def _lambda_versions(self, out: _Out, fn: str) -> list[dict]:
        """The function's published versions, oldest first; none when there were more pages than read."""
        listed, cut = _pages(self._lambda.list_versions_by_function, "Versions", next_token="NextMarker",
                             FunctionName=fn)
        versions = sorted((v for v in listed if str(v.get("Version")).isdigit()), key=lambda v: int(v["Version"]))
        if cut:  # versions come oldest first: the newest were the ones not read
            out.lines.append(_partial(f"lambda/{fn} versions", f"[output truncated] more than {LIST_MAX_PAGES} pages; "
                                      "the newest versions were not read"))
            versions = []
        return versions

    def _lambda_config_lines(self, out: _Out, alert: Alert, fn: str, sfx: str, cfg: dict, conc: Any,
                             versions: list[dict], live: str | None) -> None:
        """The function's settings as metrics and one CONFIG line, the role it runs as, and its network's changes."""
        env = _env_items((cfg.get("Environment") or {}).get("Variables") or {})
        out.metrics[f"lambda_timeout_s{sfx}"] = float(cfg.get("Timeout") or 0)
        out.metrics[f"lambda_memory_mb{sfx}"] = float(cfg.get("MemorySize") or 0)
        if conc is not None:
            out.metrics[f"lambda_reserved_concurrency{sfx}"] = float(conc)
        latest = versions[-1]["Version"] if versions else LATEST_VERSION
        sgs = sorted((cfg.get("VpcConfig") or {}).get("SecurityGroupIds") or [])  # in-VPC functions only
        sg_part = f"sgs=[{','.join(sgs)}] " if sgs else ""
        out.lines.append(
            f"CONFIG lambda {fn} timeout={cfg.get('Timeout')}s memory={cfg.get('MemorySize')}MB "
            f"reserved_concurrency={'none' if conc is None else conc} env=[{','.join(env)}] "
            f"{sg_part}version={latest} alias_live={live or '-'}"
        )
        if cfg.get("Role"):  # the identity the function's code runs as: what a denied call must be granted back to
            out.lines.append(f"TASKROLE lambda/{fn} role={str(cfg['Role']).rsplit('/', 1)[-1]}")
        if sgs:
            self._read_network_changes(out, alert, sgs, (cfg.get("VpcConfig") or {}).get("SubnetIds") or [])

    def _lambda_mappings(self, out: _Out, fn: str, sfx: str) -> None:
        """The function's event source mappings: one ESM line each, and whether all are enabled."""
        esms, _ = _pages(self._lambda.list_event_source_mappings, "EventSourceMappings", next_token="NextMarker",
                         FunctionName=fn)
        for m in esms:
            source = str(m.get("EventSourceArn", "?")).rsplit(":", 1)[-1]
            out.lines.append(f"ESM {fn} <- {source} State={m.get('State')} BatchSize={m.get('BatchSize')} "
                             f"LastProcessingResult={m.get('LastProcessingResult')}")
        if esms:
            out.metrics[f"lambda_esm_enabled{sfx}"] = float(all(m.get("State") == "Enabled" for m in esms))

    def _lambda_deploy(self, out: _Out, alert: Alert, fn: str, versions: list[dict], live: str | None) -> None:
        """The function's deploy in the window, if any."""
        # A deploy: the version `live` points at (else the newest published one) was published
        # inside the window. Its publish time stands in for the alias move, which has no timestamp.
        if live:
            target = next((v for v in versions if v["Version"] == live), None)
        else:
            target = versions[-1] if versions else None
        at = _parse_time(target.get("LastModified")) if target else None
        if not (target and self._in_window(alert, at)):
            return
        older = [v["Version"] for v in versions if int(v["Version"]) < int(target["Version"])]
        served = self._served_before(fn, older, at) if live else ""
        out.deploys.append({"kind": "lambda", "service": fn, "at": _z(at),
                            "version": target["Version"],
                            "previous": served or (older[-1] if older else ""),
                            "previous_basis": ("served live traffic before this version" if served
                                               else "numerically previous version (no per-version traffic)")})

    def _lambda_logs(self, alert: Alert, fn: str, out: _Out) -> None:
        group_alert = alert.model_copy(update={"labels": {"log_group": f"/aws/lambda/{fn}"}})
        physical: list[tuple[str, str]] = []  # (line, version from the stream name)
        for raw in self._aws.logs(group_alert):
            if raw.startswith(PARTIAL_PREFIX):
                out.lines.append(_partial(f"lambda/{fn} logs", raw))
                continue
            stream, stamp, message = (raw.removeprefix("LOG ").split(" ", 2) + ["", ""])[:3]
            m = _STREAM_VERSION.search(stream)
            version = m.group(1) if m else LATEST_VERSION
            for part in message.splitlines():
                if part.startswith(("START RequestId", "END RequestId")):
                    continue
                out.lines.append(_retag_aws_line(f"lambda/{fn}", f"{stream} {stamp} {part}"))
                physical.append((part, version))
        self._code_lines(out, fn, physical)

    def _code_lines(self, out: _Out, fn: str, physical: list[tuple[str, str]]) -> None:
        """The first MAX_CODE_FRAMES distinct tracebacks in the logs: a CODE line each, with the source around it read
        from the deployment package of the version that ran it."""
        seen, packages = set(), {}
        for tb in parse_tracebacks(physical):
            sig = (tb["path"], tb["line"], tb["exception"], tb["version"])
            if sig in seen or len(seen) >= MAX_CODE_FRAMES:
                continue
            seen.add(sig)
            out.lines.append(f"CODE {fn} {tb['path']}:{tb['line']} in {tb['func']}: {tb['exception']}")
            try:
                v = tb["version"]
                if v not in packages:
                    packages[v] = self._package(fn, v)
                out.lines += source_excerpt(fn, packages[v], tb["path"], tb["line"])
            except Exception as exc:  # noqa: BLE001 - the frame stands without its source
                out.lines.append(_partial(f"lambda/{fn} code", exc))

    def _package(self, fn: str, version: str) -> bytes:
        """The deployment package of one version of the function (or of $LATEST), downloaded."""
        resp = (self._lambda.get_function(FunctionName=fn, Qualifier=version) if version != LATEST_VERSION
                else self._lambda.get_function(FunctionName=fn))
        return self._download(resp["Code"]["Location"])

    # ------------------------------------------------------------------ sqs

    def _queue_mappings(self, name: str) -> set[str]:
        """The ids of the event source mappings AWS holds for exactly this queue (by its ARN)."""
        arn = self._queue_attrs(name, ["QueueArn"]).get("QueueArn")
        if not arn:
            return set()
        esms, _ = _pages(self._lambda.list_event_source_mappings, "EventSourceMappings", next_token="NextMarker",
                         EventSourceArn=arn)
        return {str(m["UUID"]) for m in esms if m.get("UUID")}

    def _queue_attrs(self, name: str, attrs: list[str]) -> dict:
        url = self._sqs.get_queue_url(QueueName=name)["QueueUrl"]
        return self._sqs.get_queue_attributes(QueueUrl=url, AttributeNames=attrs).get("Attributes") or {}

    def _read_consumers(self, out: _Out, alert: Alert, q: str, arn: str | None, sfx: str) -> None:
        """The queue's consumers: the event source mappings AWS holds for exactly this queue (first live run,
        2026-10-12: a queue's alarm showed nothing of the mapping that had been switched off, and the model proposed
        a restart). A function the alert names itself is read, mappings and all, by its own reader."""
        if not arn:
            return
        try:
            esms, _ = _pages(self._lambda.list_event_source_mappings, "EventSourceMappings", next_token="NextMarker",
                             EventSourceArn=arn)
        except Exception as exc:  # noqa: BLE001
            out.lines.append(_partial(f"sqs/{q} consumers", exc))
            return
        named = set(_names(alert, "lambda"))
        for m in esms:
            fn = str(m.get("FunctionArn", "?")).split(":function:")[-1].split(":")[0]
            if fn not in named:
                out.lines.append(f"ESM {fn} <- {q} State={m.get('State')} BatchSize={m.get('BatchSize')} "
                                 f"LastProcessingResult={m.get('LastProcessingResult')}")
        if esms:
            out.metrics[f"sqs_consumers_enabled{sfx}"] = float(sum(m.get("State") == "Enabled" for m in esms))

    def _read_sqs(self, out: _Out, alert: Alert, q: str, sfx: str) -> None:
        a = self._queue_attrs(q, ["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible",
                                  "VisibilityTimeout", "RedrivePolicy", "QueueArn"])
        visible, in_flight = a.get("ApproximateNumberOfMessages"), a.get("ApproximateNumberOfMessagesNotVisible")
        for key, val in ((f"sqs_visible{sfx}", visible), (f"sqs_in_flight{sfx}", in_flight),
                         (f"sqs_visibility_timeout_s{sfx}", a.get("VisibilityTimeout"))):
            if val is not None:
                out.metrics[key] = float(val)
        dlq, dlq_visible, max_receive = "none", "-", "-"
        if a.get("RedrivePolicy"):
            redrive = json.loads(a["RedrivePolicy"])
            dlq = str(redrive.get("deadLetterTargetArn", "?")).rsplit(":", 1)[-1]
            max_receive = redrive.get("maxReceiveCount", "-")
            if max_receive != "-":
                out.metrics[f"sqs_max_receive_count{sfx}"] = float(max_receive)
            try:
                dlq_visible = self._queue_attrs(dlq, ["ApproximateNumberOfMessages"])["ApproximateNumberOfMessages"]
                out.metrics[f"dlq_visible{sfx}"] = float(dlq_visible)
            except Exception as exc:  # noqa: BLE001
                out.lines.append(_partial(f"sqs/{q} dlq {dlq}", exc))
        out.lines.append(f"QUEUE {q} visible={visible} in_flight={in_flight} dlq={dlq} "
                         f"dlq_visible={dlq_visible} max_receive={max_receive}")
        self._read_consumers(out, alert, q, a.get("QueueArn"), sfx)
        out.metrics.update(self._cw_read(out, f"sqs/{q}", alert, {
            f"sqs_oldest_age_s{sfx}": ("AWS/SQS", "ApproximateAgeOfOldestMessage", {"QueueName": q}, "Maximum"),
        }))

    # ------------------------------------------------------------------ dynamodb

    def _read_dynamodb(self, out: _Out, alert: Alert, table: str) -> None:
        t = self._ddb.describe_table(TableName=table)["Table"]
        billing = (t.get("BillingModeSummary") or {}).get("BillingMode") or "PROVISIONED"
        pt = t.get("ProvisionedThroughput") or {}
        rcu, wcu = pt.get("ReadCapacityUnits"), pt.get("WriteCapacityUnits")
        if billing == "PROVISIONED":
            out.metrics["ddb_provisioned_rcu"] = float(rcu or 0)
            out.metrics["ddb_provisioned_wcu"] = float(wcu or 0)
        out.lines.append(f"TABLE {table} billing={billing} rcu={rcu} wcu={wcu} status={t.get('TableStatus')}")
        dims = {"TableName": table}
        got = self._cw_read(out, "dynamodb", alert, {
            "ddb_consumed_rcu": (DYNAMODB_NAMESPACE, "ConsumedReadCapacityUnits", dims, SUM_PER_SECOND),
            "ddb_consumed_wcu": (DYNAMODB_NAMESPACE, "ConsumedWriteCapacityUnits", dims, SUM_PER_SECOND),
            "ddb_read_throttle_events": (DYNAMODB_NAMESPACE, "ReadThrottleEvents", dims, "Sum"),
            "ddb_write_throttle_events": (DYNAMODB_NAMESPACE, "WriteThrottleEvents", dims, "Sum"),
            # Published per (TableName, Operation) only; SEARCH sums the operations.
            "ddb_throttled_requests": ("expr", (
                f"SUM(SEARCH('{{AWS/DynamoDB,Operation,TableName}} MetricName=\"ThrottledRequests\" "
                f"TableName=\"{table}\"', 'Sum', {METRIC_PERIOD_S}))"), "Sum"),
        })
        out.metrics.update(got)

    # ------------------------------------------------------------------ elasticache

    def _read_elasticache(self, out: _Out, alert: Alert, rg: str) -> None:
        group = self._ec.describe_replication_groups(ReplicationGroupId=rg)["ReplicationGroups"][0]
        members = list(group.get("MemberClusters") or [])
        # Each member by its id: the account-wide listing was read one page deep (audit A-B-M8).
        clusters = [c for m in members
                    for c in self._ec.describe_cache_clusters(CacheClusterId=m).get("CacheClusters") or []
                    if c.get("ReplicationGroupId") == rg]
        out.metrics["redis_nodes_total"] = float(len(members))
        out.metrics["redis_nodes_available"] = float(
            sum(1 for c in clusters if c.get("CacheClusterStatus") == "available"))
        self._cache_events(out, alert, rg, members)
        queries = _elasticache_queries(members)
        # ⭐ The network path, as evidence. Without these lines an "unreachable cache" report could
        # only say "check the security group" - with them it can name the rule that is missing.
        node_type = next((c.get("CacheNodeType") for c in clusters if c.get("CacheNodeType")), "?")
        sgs = sorted({g["SecurityGroupId"] for c in clusters for g in c.get("SecurityGroups") or []})
        out.lines.append(f"REPLGROUP {rg} node_type={node_type} sgs=[{','.join(sgs)}]")
        if sgs:
            ng = (group.get("NodeGroups") or [{}])[0]
            port = int((ng.get("PrimaryEndpoint") or {}).get("Port") or 6379)
            for g in self._ec2.describe_security_groups(GroupIds=sgs).get("SecurityGroups") or []:
                out.lines.append(f"SG {g['GroupId']} ingress tcp/{port} from=[{','.join(_ingress_sources(g, port))}]")
        got = self._cw_read(out, "elasticache", alert, queries)
        # Across nodes: the worst node for percentages and lag, the total for counts.
        for key, metric, agg in (("redis_memory_pct", "DatabaseMemoryUsagePercentage", max),
                                 ("redis_evictions", "Evictions", sum),
                                 ("redis_curr_connections", "CurrConnections", sum),
                                 ("redis_engine_cpu_pct", "EngineCPUUtilization", max),
                                 ("redis_replication_lag_s", "ReplicationLag", max)):
            vals = [v for k, v in got.items() if k.split("#")[0] == metric]
            if vals:
                out.metrics[key] = float(agg(vals))

    def _cache_events(self, out: _Out, alert: Alert, rg: str, members: list[str]) -> None:
        """ElastiCache's events for the replication group and its nodes around the alert, oldest first."""
        started = AwsBackend._started_at(alert)
        # By source, every page (audit A-B-L4): the whole account's events, one page of them, could hold none of ours.
        sources = [(rg, "replication-group"), *((m, "cache-cluster") for m in members)]
        events = [e for sid, kind in sources for e in _pages(
            self._ec.describe_events, "Events", SourceIdentifier=sid, SourceType=kind,
            StartTime=started - LOG_LOOKBACK, EndTime=started + LOG_LOOKBACK)[0]]
        for e in sorted(events, key=lambda e: str(e.get("Date"))):
            if e.get("SourceIdentifier") in {rg, *members}:
                out.lines.append(f"EVENT elasticache {rg} {_z(e.get('Date'))} {_one_line(e.get('Message', ''))}")

    # ------------------------------------------------------------------ aurora

    def _read_aurora(self, out: _Out, alert: Alert, cluster: str) -> None:
        c = self._rds.describe_db_clusters(DBClusterIdentifier=cluster)["DBClusters"][0]
        members = c.get("DBClusterMembers") or []
        writer = [m["DBInstanceIdentifier"] for m in members if m.get("IsClusterWriter")]
        readers = [m["DBInstanceIdentifier"] for m in members if not m.get("IsClusterWriter")]
        out.lines.append(f"CLUSTER aurora {cluster} writer={','.join(writer) or '-'} "
                         f"readers=[{','.join(readers)}] status={c.get('Status')}")
        instances = self._rds.describe_db_instances(
            Filters=[{"Name": "db-cluster-id", "Values": [cluster]}]).get("DBInstances") or []
        out.metrics["aurora_members_available"] = float(
            sum(1 for i in instances if i.get("DBInstanceStatus") == "available"))
        self._db_load(out, alert, instances)
        for name in writer[:1]:
            self._db_log(out, alert, name)
        started = AwsBackend._started_at(alert)
        sources = [(cluster, "db-cluster"), *((i, "db-instance") for i in [*writer, *readers])]
        events = [e for sid, kind in sources for e in _pages(
            self._rds.describe_events, "Events", SourceIdentifier=sid, SourceType=kind,
            StartTime=started - LOG_LOOKBACK, EndTime=started + LOG_LOOKBACK)[0]]
        for e in sorted(events, key=lambda e: str(e.get("Date"))):
            if e.get("SourceIdentifier") in {cluster, *writer, *readers}:
                out.lines.append(f"EVENT aurora {cluster} {_z(e.get('Date'))} {_one_line(e.get('Message', ''))}")
        d = {"DBClusterIdentifier": cluster}
        queries = {
            "aurora_connections": (RDS_NAMESPACE, "DatabaseConnections", d, "Maximum"),
            "aurora_acu_utilization_pct": (RDS_NAMESPACE, "ACUUtilization", d, "Maximum"),
            "aurora_cpu_pct": (RDS_NAMESPACE, "CPUUtilization", d, "Maximum"),
            "aurora_deadlocks": (RDS_NAMESPACE, "Deadlocks", d, "Maximum"),
        }
        for i, r in enumerate(readers):
            queries[f"lag#{i}"] = (RDS_NAMESPACE, "AuroraReplicaLag", {"DBInstanceIdentifier": r}, "Maximum")
        got = self._cw_read(out, "aurora", alert, queries)
        lags = [v for k, v in got.items() if k.startswith("lag#")]
        out.metrics.update({k: v for k, v in got.items() if not k.startswith("lag#")})
        if lags:
            out.metrics["aurora_replica_lag_ms"] = max(lags)

    def _db_log(self, out: _Out, alert: Alert, instance: str) -> None:
        """The database's own error log (2026-10-15): the newest file written in the alert window, its last lines, and
        of those only the ERROR, FATAL and PANIC ones - "password authentication failed for user ...", "database ...
        does not exist" name causes the applications' own logs only echo. Untrusted text, as any log line: redacted,
        quarantined, scanned."""
        started = AwsBackend._started_at(alert)
        try:
            files = self._rds.describe_db_log_files(
                DBInstanceIdentifier=instance, FileLastWritten=int((started - LOG_LOOKBACK).timestamp() * 1000)
            ).get("DescribeDBLogFiles") or []
            if not files:
                return
            newest = max(files, key=lambda f: f.get("LastWritten") or 0)
            data = self._rds.download_db_log_file_portion(
                DBInstanceIdentifier=instance, LogFileName=newest["LogFileName"], NumberOfLines=DB_LOG_LINES
            ).get("LogFileData") or ""
        except Exception as exc:  # noqa: BLE001 - the other reads go on
            out.lines.append(_partial("aurora logs", exc))
            return
        hits = [ln for ln in data.splitlines() if _DB_LOG_ERROR.search(ln)][-DB_LOG_KEEP:]
        out.lines += [f"LOG rds/{_one_line(instance)} {ln[:400]}" for ln in hits]

    def _db_load(self, out: _Out, alert: Alert, instances: list[dict]) -> None:
        """Performance Insights (requirement R22): each member's database load over the alert window, and that load
        by wait-event TYPE (CPU, Lock, IO, LWLock, Client, ...). Numbers under names from that closed list; no SQL
        text and no wait-event names reach the evidence. Free within PI's 7-day window and 1M API calls a month."""
        started = AwsBackend._started_at(alert)
        queries = [{"Metric": DB_LOAD_METRIC},
                   {"Metric": DB_LOAD_METRIC, "GroupBy": {"Group": "db.wait_event_type", "Limit": 6}},
                   {"Metric": DB_LOAD_METRIC, "GroupBy": {"Group": "db.sql_tokenized", "Limit": TOP_SQL}}]
        for inst in instances:
            name = inst.get("DBInstanceIdentifier", "?")
            if not inst.get("PerformanceInsightsEnabled") or not inst.get("DbiResourceId"):
                out.lines.append(_partial("aurora metrics", f"[not supported] Performance Insights is off on {_one_line(name)}"))
                continue
            try:
                got = self._pi.get_resource_metrics(
                    ServiceType="RDS", Identifier=inst["DbiResourceId"], MetricQueries=queries, PeriodInSeconds=60,
                    StartTime=started - LOG_LOOKBACK, EndTime=started + LOG_LOOKBACK)
            except Exception as exc:  # noqa: BLE001 - one member unread is data; the others still read
                out.lines.append(_partial("aurora metrics", exc))
                continue
            _member_load(out, name, got)

    def _insights(self, out: _Out, alert: Alert, group: str, tag: str, sfx: str) -> None:
        """CloudWatch Logs Insights (requirement R22): error lines per minute over the WHOLE alert window, counted by
        CloudWatch - complete where filter_log_events stopped at its page limit. Counts only: no log text from it
        reaches the evidence. Paid per GB scanned ($0.005/GB list price): one log group, alert time +/- 15 min."""
        started = AwsBackend._started_at(alert)
        try:
            qid = self._logs.start_query(
                logGroupName=group, queryString=INSIGHTS_QUERY, limit=100,
                startTime=int((started - LOG_LOOKBACK).timestamp()), endTime=int((started + LOG_LOOKBACK).timestamp()),
            )["queryId"]
            got = self._insights_results(out, qid, tag)
        except Exception as exc:  # noqa: BLE001 - the error counts are extra evidence; the logs above still stand
            out.lines.append(_partial(f"{tag} metrics", exc))
            return
        if got is None:
            return
        counts = _insights_counts(got)
        out.metrics[f"log_error_lines{sfx}"] = sum(counts)
        out.metrics[f"log_errors_peak_per_min{sfx}"] = max(counts, default=0.0)

    def _insights_results(self, out: _Out, qid: str, tag: str) -> dict | None:
        """The finished Logs Insights query's results, polled until INSIGHTS_WAIT_S; None (and a TOOL-PARTIAL saying
        why) when it failed, timed out or did not finish in time."""
        deadline = time.monotonic() + INSIGHTS_WAIT_S
        while True:
            got = self._logs.get_query_results(queryId=qid)
            status = got.get("status")
            if status == "Complete":
                return got
            if status not in ("Scheduled", "Running"):
                outcome = "timed out" if status == "Timeout" else "failed (unclassified)"
                out.lines.append(_partial(f"{tag} metrics", f"[{outcome} on GetQueryResults] the Logs Insights query "
                                                            f"ended {_one_line(status)}"))
                return None
            if time.monotonic() > deadline:
                self._logs.stop_query(queryId=qid)
                out.lines.append(_partial(f"{tag} metrics",
                                          f"[timed out on GetQueryResults] the Logs Insights query did not "
                                          f"finish in {INSIGHTS_WAIT_S:.0f}s"))
                return None
            self._sleep(0.5)

    def _read_db(self, out: _Out, env: str, prefix: str, alert: Alert) -> None:
        """The existing PostgreSQL backend on one Aurora endpoint, names unchanged (reader: `reader_`)."""
        dsn = settings.getenv(env)
        if not dsn:
            raise ToolError(f"{env} is not set; the {'reader' if prefix else 'writer'} sessions were not read")
        if os.environ.get("WARDEN_STACK_DB_IAM_AUTH") == "1":
            dsn = iam_dsn(self._rds, dsn)
        db = self._db_factory(dsn)
        role = "reader" if prefix else "writer"
        try:
            out.metrics.update({f"{prefix}{k}": v for k, v in db.metrics(alert).items()})
        except Exception as exc:  # noqa: BLE001 - the session lines below may still read
            out.lines.append(_partial(f"aurora-db-{role} metrics", exc))
        for line in db.logs(alert):
            if line.startswith(PARTIAL_PREFIX):
                out.lines.append(_partial(f"aurora-db-{role}", line))
            elif prefix and line.startswith("STATE postgres "):
                continue  # one cluster, one catalog: the writer's lines already hold it
            else:
                out.lines.append(f"[{role}] {line}" if prefix else line)

    # ------------------------------------------------------------------ alb / apigw

    def _read_alb(self, out: _Out, alert: Alert, tg_name: str) -> None:
        tg = self._elb.describe_target_groups(Names=[tg_name])["TargetGroups"][0]
        out.lines.append(f"TARGETGROUP {tg_name} health_path={tg.get('HealthCheckPath')} "
                         f"port={tg.get('HealthCheckPort')} matcher={(tg.get('Matcher') or {}).get('HttpCode')}")
        health = self._elb.describe_target_health(TargetGroupArn=tg["TargetGroupArn"]).get(
            "TargetHealthDescriptions") or []
        healthy = unhealthy = 0
        for h in health:
            th, tgt = h.get("TargetHealth") or {}, h.get("Target") or {}
            state = th.get("State")
            healthy += state == "healthy"
            unhealthy += state == "unhealthy"
            if state != "healthy":
                out.lines.append(f"TARGET {tg_name} {tgt.get('Id')}:{tgt.get('Port')} {state} "
                                 f"{th.get('Reason', '-')}: {th.get('Description', '')}")
        # Exact counts from the API rather than CloudWatch's sampled UnHealthyHostCount.
        out.metrics["alb_healthy_hosts"] = float(healthy)
        out.metrics["alb_unhealthy_hosts"] = float(unhealthy)
        lbs = tg.get("LoadBalancerArns") or []
        if lbs:
            self._read_alb_balancer(out, alert, tg, lbs[0])

    def _read_alb_balancer(self, out: _Out, alert: Alert, tg: dict, lb_arn: str) -> None:
        """The target group's (first) load balancer: its zones, and the 5xx, response time and hosts per zone."""
        lb = lb_arn.split(":loadbalancer/", 1)[-1]
        tgd = {"TargetGroup": tg["TargetGroupArn"].split(":", 5)[-1], "LoadBalancer": lb}
        # G9-D: the load balancer's zones and whether ARC may shift traffic away from one - and below, its hosts per
        # zone: an impaired zone shows as one zone with no healthy host while the others serve.
        zones = self._alb_zones(out, lb_arn, lb)
        per_zone = {}
        for z in zones:
            at = {**tgd, "AvailabilityZone": z}
            per_zone[f"alb_healthy_hosts_{z}"] = (ALB_NAMESPACE, "HealthyHostCount", at, "Minimum")
            per_zone[f"alb_unhealthy_hosts_{z}"] = (ALB_NAMESPACE, "UnHealthyHostCount", at, "Maximum")
        out.metrics.update(self._cw_read(out, "alb", alert, {
            "alb_target_5xx": (ALB_NAMESPACE, "HTTPCode_Target_5XX_Count", tgd, "Sum"),
            "alb_elb_5xx": (ALB_NAMESPACE, "HTTPCode_ELB_5XX_Count", {"LoadBalancer": lb}, "Sum"),
            "alb_target_response_time_s": (ALB_NAMESPACE, "TargetResponseTime", tgd, "Maximum"),
            **per_zone,
        }))

    def _alb_zones(self, out: _Out, lb_arn: str, lb: str) -> list[str]:
        """The load balancer's zones (six at most) and a CONFIG line with whether zonal shift is on; a failed read is a
        TOOL-PARTIAL, with the zones read before it failed."""
        zones: list[str] = []
        try:
            [desc] = self._elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"]
            zones = sorted(z["ZoneName"] for z in desc.get("AvailabilityZones") or [] if z.get("ZoneName"))[:6]
            attrs = {a.get("Key"): a.get("Value") for a in self._elb.describe_load_balancer_attributes(
                LoadBalancerArn=lb_arn).get("Attributes") or []}
            out.lines.append(f"CONFIG alb {lb.split('/')[1] if '/' in lb else lb} zones={','.join(zones) or 'none'} "
                             f"zonal_shift={attrs.get('zonal_shift.config.enabled') or 'false'}")
        except Exception as exc:  # noqa: BLE001 - the target health above stands without it
            out.lines.append(_partial("alb zones", exc))
        return zones

    def _read_apigw(self, out: _Out, alert: Alert, api_name: str) -> None:
        apis, _ = _pages(self._apigw.get_apis, "Items", token="NextToken")
        api = next((a for a in apis if a.get("Name") == api_name), None)
        if api is None:
            raise ToolError(f"no HTTP API named '{api_name}'")
        d = {"ApiId": api["ApiId"]}
        out.metrics.update(self._cw_read(out, "apigw", alert, {
            "apigw_5xx": (APIGW_NAMESPACE, "5xx", d, "Sum"),
            "apigw_4xx": (APIGW_NAMESPACE, "4xx", d, "Sum"),
            "apigw_latency_ms": (APIGW_NAMESPACE, "Latency", d, "Maximum"),
        }))

    # ------------------------------------------------------------------ ecs / k8s (reused)

    def _read_ecs(self, out: _Out, alert: Alert) -> None:
        service = alert.labels["ecs_service"]
        a = alert.model_copy(update={"labels": {"cluster": alert.labels["ecs_cluster"],
                                                "ecs_service": service, "log_group": f"/ecs/{service}"}})
        for raw in self._aws.logs(a):
            out.lines.append(_partial("ecs logs", raw) if raw.startswith(PARTIAL_PREFIX)
                             else _retag_aws_line(f"ecs/{service}", raw))
        out.metrics.update(self._aws.metrics(a))
        self._insights(out, alert, f"/ecs/{service}", f"ecs/{service}", "")
        svc = (self._ecs.describe_services(cluster=alert.labels["ecs_cluster"], services=[service])
               .get("services") or [{}])[0]
        ecs_sgs = sorted(((svc.get("networkConfiguration") or {}).get("awsvpcConfiguration") or {})
                         .get("securityGroups") or [])
        if ecs_sgs:
            out.lines.append(f"APPSG ecs/{service} sgs=[{','.join(ecs_sgs)}]")
        self._ecs_task_role(out, service, svc)
        self._ecs_deploys(out, a, service)
        self._read_ecs_tasks(out, alert.labels["ecs_cluster"], service, svc, alert)
        net = (svc.get("networkConfiguration") or {}).get("awsvpcConfiguration") or {}
        if net.get("securityGroups"):
            self._read_network_changes(out, alert, net["securityGroups"], net.get("subnets") or [])

    def _ecs_deploys(self, out: _Out, a: Alert, service: str) -> None:
        """The service's deploys, read by AwsBackend; a failed read is a TOOL-PARTIAL."""
        for d in self._aws.deploys(a):
            if isinstance(d, str):
                out.lines.append(_partial("ecs deploys", d))
            else:
                out.deploys.append(_ecs_deploy(service, d))

    def _ecs_task_role(self, out: _Out, service: str, svc: dict) -> None:
        """The service's task role: a TASKROLE line."""
        # The identity the service's code runs as (not the execution role): what a denied database
        # login or API call must be granted back to. Absent when the task definition has none.
        if svc.get("taskDefinition"):
            td = self._ecs.describe_task_definition(taskDefinition=svc["taskDefinition"]).get("taskDefinition") or {}
            if td.get("taskRoleArn"):
                out.lines.append(f"TASKROLE ecs/{service} role={td['taskRoleArn'].rsplit('/', 1)[-1]}")

    def _read_network_changes(self, out: _Out, alert: Alert, sgs: list[str], subnets: list[str]) -> None:
        """G10-C4: writes to the network a workload depends on - its security groups, its subnets' route tables and
        network ACLs - in the RECENT_DEPLOY_WINDOW before the alert (recorded ecs-12 and ecs-13: a revoked egress rule,
        a deleted route, answered "no action" and "roll back"). Only on a network symptom in what was read: CloudTrail
        allows two lookups a second. Looked up by event NAME - the attribute AWS documents - and kept only when the
        event's own request names one of this workload's ids."""
        if not (out.metrics.get("ecs_stopped_network") or any(_NETWORK_SYMPTOM.search(x) for x in out.lines)):
            return
        ids = dict.fromkeys(sgs, "security group")
        try:
            if subnets:
                self._subnet_network_ids(ids, subnets)
        except Exception as exc:  # noqa: BLE001 - the security groups are still looked up
            out.lines.append(_partial("network workload", exc))
        started = AwsBackend._started_at(alert)
        found = 0
        for name in _NETWORK_EVENTS:
            try:
                got = self._ct.lookup_events(LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}],
                                             StartTime=started - RECENT_DEPLOY_WINDOW,
                                             EndTime=started + timedelta(minutes=5), MaxResults=50)
            except Exception as exc:  # noqa: BLE001 - CloudTrail allows 2 lookups a second; keep what was read
                out.lines.append(_partial("network changes", exc))
                break
            if got.get("NextToken"):
                out.lines.append(_partial("network changes", f"[output truncated on LookupEvents] more {name} events than one page in the window"))
            found += _network_change_lines(out, name, got.get("Events") or [], ids)
        out.metrics["network_changes_before_alert"] = float(found)

    def _subnet_network_ids(self, ids: dict[str, str], subnets: list[str]) -> None:
        """Adds to `ids` the route tables (a subnet with none of its own: its VPC's main one), the subnets' route table
        associations and their network ACLs, each with what it is."""
        vpcs = {s.get("VpcId") for s in self._ec2.describe_subnets(SubnetIds=subnets).get("Subnets") or []}
        tables = self._ec2.describe_route_tables(
            Filters=[{"Name": "association.subnet-id", "Values": subnets}]).get("RouteTables") or []
        if len(tables) < len(subnets):  # a subnet with no table of its own uses its VPC's main table
            tables += self._ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": sorted(vpcs)},
                                                               {"Name": "association.main", "Values": ["true"]}]
                                                      ).get("RouteTables") or []
        ids.update(dict.fromkeys((t["RouteTableId"] for t in tables), "route table"))
        ids.update(dict.fromkeys((a["RouteTableAssociationId"] for t in tables
                                  for a in t.get("Associations") or [] if a.get("SubnetId") in subnets),
                                 "route table association"))
        acls = self._ec2.describe_network_acls(
            Filters=[{"Name": "association.subnet-id", "Values": subnets}]).get("NetworkAcls") or []
        ids.update(dict.fromkeys((a["NetworkAclId"] for a in acls), "network ACL"))

    def _read_ecs_tasks(self, out: _Out, cluster: str, service: str, svc: dict, alert: Alert) -> None:
        """G10-C1: what the console shows first and the evidence lacked (miss analysis 2026-10-10: ecs-06, -07, -12,
        -13 were answered with the service "at its desired count, nothing failed"). Each deployment's counts; the
        service's own events, counted by kind; and the last stopped tasks - AWS's stop code and its stoppedReason
        classified into a closed set of causes. The reason text itself reaches the model only as quarantined facts."""
        for d in svc.get("deployments") or []:
            out.lines.append(
                f"STATE ecs/{service} deployment {_safe(d.get('status'))} rollout={_safe(d.get('rolloutState'))} "
                f"revision={_safe(str(d.get('taskDefinition', '')).rsplit('/', 1)[-1])} desired={int(d.get('desiredCount') or 0)} "
                f"running={int(d.get('runningCount') or 0)} pending={int(d.get('pendingCount') or 0)} "
                f"failed={int(d.get('failedTasks') or 0)} at={_z(_parse_time(d.get('createdAt')))}")
        started = AwsBackend._started_at(alert)
        kinds = _ecs_event_kinds(svc, started)
        if kinds:
            counted = " ".join(f"{k}={n}" for k, n in sorted(kinds.items()))
            out.lines.append(f"STATE ecs/{service} service events in the hour before the alert: {counted}")
        try:
            arns = self._ecs.list_tasks(cluster=cluster, serviceName=service, desiredStatus="STOPPED",
                                        maxResults=STOPPED_TASKS).get("taskArns") or []
            tasks = (self._ecs.describe_tasks(cluster=cluster, tasks=arns).get("tasks") or []) if arns else []
        except Exception as exc:  # noqa: BLE001 - the rest of the service's evidence stands
            out.lines.append(_partial("ecs stopped tasks", exc))
            return
        causes: dict[str, int] = {}
        for t in sorted(tasks, key=lambda t: _parse_time(t.get("stoppedAt")) or started, reverse=True):
            cause = _stopped_task_lines(out, service, t)
            causes[cause] = causes.get(cause, 0) + 1
        out.metrics["ecs_stopped_tasks"] = float(len(tasks))
        out.metrics["ecs_tasks_failed_to_start"] = float(sum(1 for t in tasks if t.get("stopCode") == "TaskFailedToStart"))
        for cause, n in causes.items():
            out.metrics[f"ecs_stopped_{cause}"] = float(n)

    def _read_eks(self, out: _Out, cluster: str) -> None:
        vpc = self._eks.describe_cluster(name=cluster)["cluster"].get("resourcesVpcConfig") or {}
        sgs = sorted({*(vpc.get("securityGroupIds") or []), *([vpc["clusterSecurityGroupId"]]
                                                              if vpc.get("clusterSecurityGroupId") else [])})
        if sgs:
            out.lines.append(f"APPSG eks/{cluster} sgs=[{','.join(sgs)}]")
        # G10-C2: a node group that cannot launch nodes names why in a closed code (AsgInstanceLaunchFailures,
        # InsufficientFreeAddresses, IamNodeRoleNotFound, ...); the message is AWS's words, quarantined.
        try:
            for ng in (self._eks.list_nodegroups(clusterName=cluster, maxResults=NODEGROUPS).get("nodegroups") or []):
                g = self._eks.describe_nodegroup(clusterName=cluster, nodegroupName=ng).get("nodegroup") or {}
                issues = (g.get("health") or {}).get("issues") or []
                if issues or g.get("status") not in (None, "ACTIVE"):
                    codes = ",".join(sorted({_safe(i.get("code")) for i in issues}))
                    out.lines.append(f"STATE eks/{cluster} nodegroup {_safe(ng)} status={_safe(g.get('status'))} "
                                     f"issues=[{codes}]")
                    out.lines += [f"EVENT eks/{cluster} nodegroup issue: {str(i.get('message', ''))[:300]}"
                                  for i in issues[:3] if i.get("message")]
        except Exception as exc:  # noqa: BLE001 - the cluster's other evidence stands
            out.lines.append(_partial("eks nodegroups", exc))

    def _read_asg_activity(self, out: _Out, alert: Alert, group: str) -> None:
        """G10-C2: the group's scaling activities in the hour before the alert - held-out asg-scheduled-scale-in read a
        planned scale-in as a shortage. AWS's Cause names a scheduled action, a policy, a health check or a person."""
        started = AwsBackend._started_at(alert)
        acts = self._asg.describe_scaling_activities(
            AutoScalingGroupName=group, MaxRecords=ASG_ACTIVITIES).get("Activities") or []
        for a in acts:
            at = _parse_time(a.get("StartTime"))
            if at is None or not started - ECS_EVENT_WINDOW <= at <= started + timedelta(minutes=5):
                continue
            cause = str(a.get("Cause") or "")
            kind = next((k for k, rx in _ASG_CAUSES if rx.search(cause)), "other")
            moved = _CAPACITY_CHANGE.search(cause)
            out.lines.append(f"STATE asg {_safe(group)} activity at={_z(at)} status={_safe(a.get('StatusCode'))} "
                             f"cause={kind}" + (f" capacity={moved.group(1)}->{moved.group(2)}" if moved else ""))
            if cause:
                out.lines.append(f"EVENT asg {_safe(group)} activity: {cause[:300]}")

    def _read_sfn_failures(self, out: _Out, machine: str) -> None:
        """G10-C2: the last failed executions and the error each failed with (States.Timeout, Lambda.ServiceException,
        a task's own error name); the cause text is the task's words, quarantined."""
        arn = f"arn:aws:states:{self._cw.meta.region_name}:{self._account()}:stateMachine:{machine}"
        for e in self._sfn.list_executions(stateMachineArn=arn, statusFilter="FAILED",
                                     maxResults=SFN_FAILURES).get("executions") or []:
            d = self._sfn.describe_execution(executionArn=e["executionArn"])
            out.lines.append(f"STATE states {_safe(machine)} failed execution at={_z(_parse_time(d.get('stopDate')))} "
                             f"error={_safe(d.get('error'))}")
            if d.get("cause"):
                out.lines.append(f"EVENT states {_safe(machine)} failure: {str(d['cause'])[:300]}")

    def _read_k8s(self, out: _Out, alert: Alert, ns: str, dep: str, sfx: str) -> None:
        cluster = alert.labels.get("eks_cluster", "") or eks_cluster_of(alert.environment)
        if cluster and self._k8s_factory is _default_k8s and "eks" in self._clients and "sts" in self._clients:
            # The cluster the alert names, in this backend's own role (the incident's reader role in the cloud).
            from .k8s_backend import eks_backend

            k8s = eks_backend(self._clients["eks"], self._clients["sts"], cluster)
        else:
            k8s = self._k8s_factory()
        # ponytail: assumes the Deployment's pods carry app=<deployment> (true for the shop manifests).
        a = alert.model_copy(update={"labels": {"namespace": ns, "deployment": dep, "selector": f"app={dep}"}})
        for raw in k8s.logs(a):
            out.lines.append(_partial(f"k8s/{dep}", raw) if raw.startswith(PARTIAL_PREFIX)
                             else f"LOG k8s/{ns}/{dep} {raw}")
        out.metrics.update({f"{k}{sfx}": v for k, v in k8s.metrics(a).items()})
        for d in k8s.deploys(a):
            out.deploys.append({"kind": "k8s", "service": dep, "at": _z(_parse_time(d["at"])),
                                "image": d.get("image", ""), "previous": d.get("previous_image", ""),
                                "revision": d.get("revision", "")})

    # ------------------------------------------------------------------ secret / sns / events

    def _read_secret(self, out: _Out, alert: Alert, name: str) -> None:
        meta = self._sm.describe_secret(SecretId=name)  # metadata only - never the value
        changed = _aware(meta.get("LastChangedDate"))
        # A secret scheduled for deletion fails every read of its value (G10 held-out set, 2026-10-10: the model was
        # never told, and RestoreSecret can bring it back inside the recovery window).
        deleted = _aware(meta.get("DeletedDate"))
        if deleted is not None:
            out.lines.append(f"SECRET {name} scheduled for deletion {_z(deleted)} (metadata only)")
        if changed is None:
            return
        out.lines.append(f"SECRET {name} changed {_z(changed)} (metadata only)")
        out.metrics["secret_changed_age_s"] = (AwsBackend._started_at(alert) - changed).total_seconds()
        if self._in_window(alert, changed):
            # Not a code deploy: P5 must not roll it back (contract D).
            out.deploys.append({"kind": "secret", "service": name, "at": _z(changed),
                                "version": "", "previous": ""})

    def _read_sns(self, out: _Out, alert: Alert, topic: str) -> None:
        account = self._sts.get_caller_identity()["Account"]
        arn = f"arn:aws:sns:{self._sns.meta.region_name}:{account}:{topic}"
        subs, _ = _pages(self._sns.list_subscriptions_by_topic, "Subscriptions", token="NextToken", TopicArn=arn)
        for s in subs:
            if s.get("Protocol") != "sqs":
                continue
            queue = str(s.get("Endpoint", "")).rsplit(":", 1)[-1]
            try:
                policy = self._queue_attrs(queue, ["Policy"]).get("Policy")
                ok = _policy_allows_topic(policy, arn)
                out.lines.append(f"POLICY sqs {queue} allows_sns_topic={topic}:{'yes' if ok else 'no'}")
            except Exception as exc:  # noqa: BLE001
                out.lines.append(_partial(f"sns policy {queue}", exc))
        out.metrics.update(self._cw_read(out, "sns", alert, {
            "sns_notifications_failed": ("AWS/SNS", "NumberOfNotificationsFailed", {"TopicName": topic}, "Sum"),
            "sns_notifications_delivered": ("AWS/SNS", "NumberOfNotificationsDelivered", {"TopicName": topic}, "Sum"),
        }))

    def _read_rule(self, out: _Out, alert: Alert, rule: str, sfx: str) -> None:
        # A rule on a custom bus is found only on that bus (G10 review, 2026-10-10: DescribeRule looked on the default
        # bus and failed): the alarm's EventBusName dimension names it.
        bus = (_names(alert, "event_bus") or [""])[0]
        on_bus = {"EventBusName": bus} if bus else {}
        r = self._events.describe_rule(Name=rule, **on_bus)
        out.lines.append(f"RULE {rule} State={r.get('State')} schedule={r.get('ScheduleExpression', '-')}"
                         + (f" bus={_safe(bus)}" if bus else ""))
        out.metrics[f"rule_enabled{sfx}"] = float(r.get("State") == "ENABLED")
        out.metrics.update(self._cw_read(out, f"eventbridge/{rule}", alert, {
            f"rule_invocations{sfx}": ("AWS/Events", "Invocations", {**on_bus, "RuleName": rule}, "Sum"),
        }))


def _policy_allows_topic(policy: str | None, topic_arn: str) -> bool:
    """Does a queue policy let this SNS topic SendMessage? An explicit Deny wins."""
    if not policy:
        return False
    statements = json.loads(policy).get("Statement") or []
    statements = [statements] if isinstance(statements, dict) else statements
    if any(st.get("Effect") == "Deny" and _statement_matches(st, topic_arn, unknown=True) for st in statements):
        return False
    return any(st.get("Effect") == "Allow" and _statement_matches(st, topic_arn, unknown=False) for st in statements)


def _statement_matches(st: dict, topic_arn: str, unknown: bool) -> bool:
    """Does one policy statement cover this topic sending to the queue? `unknown`: the answer for a condition
    operator not understood here."""
    actions = st.get("Action") or []
    actions = [actions] if isinstance(actions, str) else actions
    if not any(a in ("*", "sqs:*", "sqs:SendMessage") for a in actions):
        return False
    if not _from_sns(st.get("Principal")):
        return False
    return _conditions_hold(st, topic_arn, unknown)


def _from_sns(principal: Any) -> bool:
    """Does a statement's principal take in SNS: everyone, or a service or account list naming SNS or everyone?"""
    if principal == "*":
        return True
    p = (principal or {}).get("Service") or (principal or {}).get("AWS") or []
    p = [p] if isinstance(p, str) else p
    return any(x in ("*", "sns.amazonaws.com") for x in p)


def _conditions_hold(st: dict, topic_arn: str, unknown: bool) -> bool:
    """Do a statement's conditions on aws:SourceArn hold for the topic (others are not read)?"""
    # Each operator by its meaning (audit A-B-L5): `ArnNotEquals` was read as `ArnEquals`, so a Deny of every
    # topic BUT this one denied this one. An operator not understood here gives `unknown`: an Allow it cannot
    # prove does not allow, and a Deny it cannot read is taken to apply. The conditions all have to hold, so one
    # that does not decides first, wherever it is listed (PR 122 review: the unreadable one used to end the reading).
    undecided = False
    for op, test in (st.get("Condition") or {}).items():
        key = next((k for k in test if k.lower() == "aws:sourcearn"), None)
        if key is None:
            continue
        values = test[key] if isinstance(test[key], list) else [test[key]]
        ok = _source_arn_holds(op.split(":")[-1].removesuffix("IfExists"), values, topic_arn)
        if ok is None:
            undecided = True
        elif not ok:
            return False
    return unknown if undecided else True


def _source_arn_holds(base: str, values: list, topic_arn: str) -> bool | None:
    """Whether a condition on aws:SourceArn holds for the topic; None for an operator not understood here."""
    hit = any(fnmatch.fnmatchcase(topic_arn, str(v)) for v in values)
    if base in ("ArnEquals", "ArnLike", "StringEquals", "StringLike"):
        return hit
    if base in ("ArnNotEquals", "ArnNotLike", "StringNotEquals", "StringNotLike"):
        return not hit
    if base == "Null":  # SNS always sends the topic as the source: present, never null
        return str(values[0]).lower() == "false"
    return None


# The database's own error log: how many of its last lines are read, and how many error lines are kept.
DB_LOG_LINES, DB_LOG_KEEP = 400, 30
_DB_LOG_ERROR = re.compile(r"\b(?:ERROR|FATAL|PANIC):")
# Performance Insights' heaviest statements, as numbers and names only (2026-10-15: "do you see the queries").
TOP_SQL = 5
_SQL_WORD = re.compile(r"[A-Za-z]+")
_SQL_TABLE = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE|TABLE)\s+((?:[A-Z_][A-Z0-9_$]{0,62}\.)?[A-Z_][A-Z0-9_$]{0,62})",
                        re.IGNORECASE)
_SQL_VERBS = frozenset({"SELECT", "INSERT", "UPDATE", "DELETE", "WITH", "COPY", "VACUUM", "ANALYZE", "CREATE", "ALTER",
                        "DROP", "LOCK", "BEGIN", "COMMIT", "CALL", "MERGE", "SET", "SHOW", "TRUNCATE", "REFRESH"})


def _sql_verb(sql: str) -> str:
    """The statement's first word after any leading `/* */` comments, in one linear pass. CodeQL py/redos (alert 21,
    2026-10-15): the regex this replaces backtracked exponentially on a `/*` followed by many `*//*` - and the text is
    whatever a database client sent, so any client could stall WARDEN's reader."""
    i, n = 0, len(sql)
    while True:
        while i < n and sql[i].isspace():
            i += 1
        if not sql.startswith("/*", i):
            m = _SQL_WORD.match(sql, i)
            return m.group(0) if m else ""
        end = sql.find("*/", i + 2)
        if end < 0:
            return ""  # a comment that never closes holds no statement
        i = end + 2


def sql_shape(sql: str) -> str:
    """`kind=<verb> tables=<a,b>`: a statement as its kind and the tables it names - never its text, which a client
    writes and may carry words aimed at WARDEN (the reason this reader read no SQL before)."""
    verb = _sql_verb(sql).upper()
    tables = sorted({t.lower() for t in _SQL_TABLE.findall(sql)})[:4]
    return (f"kind={verb if verb in _SQL_VERBS else 'other'}"
            + (f" tables={','.join(tables)}" if tables else ""))


def iam_dsn(rds: Any, dsn: str, *, verify: bool = False) -> str:
    """The DSN with a 15-minute IAM token as its password, signed by `rds`'s own credentials - in the cloud runtime the
    incident's environment reader role - when the DSN carries no password: no database password exists anywhere,
    and the role's rds-db:connect on the read-only user decides (2026-10-15: the cloud read no database at all). The
    token lives only in this DSN, in memory. `verify`: the server's certificate and name are checked against Amazon
    RDS's own certificate authorities (data/rds-ca-bundle.crt, sslmode=verify-full) - the write path's (review, PR 48:
    a close must not go to a server that only claims to be the cluster)."""
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    parts = conninfo_to_dict(dsn)
    if parts.get("password") or not parts.get("host") or not parts.get("user"):
        return dsn
    token = rds.generate_db_auth_token(DBHostname=parts["host"], Port=int(parts.get("port") or 5432),
                                       DBUsername=parts["user"])
    if verify:
        from importlib import resources

        bundle = resources.files("warden") / "data" / "rds-ca-bundle.crt"
        return make_conninfo(dsn, password=token, sslmode="verify-full", sslrootcert=str(bundle))
    return make_conninfo(dsn, password=token, sslmode="require")


def eks_cluster_of(environment: str) -> str:
    """The environment's EKS cluster from WARDEN_EKS_CLUSTERS (`env=cluster[,env=cluster]`), or "". Configuration, so
    no cluster is named in code; a name that is not a plain identifier is ignored."""
    for pair in os.environ.get("WARDEN_EKS_CLUSTERS", "").split(","):
        env, _, cluster = pair.strip().partition("=")
        if env == environment and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", cluster):
            return cluster
    return ""


def _default_k8s():
    from .k8s_backend import KubernetesBackend

    return KubernetesBackend()


def _default_db(dsn: str):
    from .database import DatabaseBackend

    return DatabaseBackend(dsn=dsn, engine="postgres")
