"""The full-stack evidence backend (`WARDEN_BACKEND=stack`) - Wave 4, docs/WAVE4-FULLSTACK.md s5.

Same three-method contract as every other backend. The alert's labels name the application's
resources (docs/WAVE4-CONTRACT.md A); one READER per resource reads it, and the metric names and
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
from .tools import PARTIAL_PREFIX, ToolError, deploy_in_window, failure

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

_TRACEBACK = "Traceback (most recent call last):"
_FRAME = re.compile(r'File "([^"]+)", line (\d+), in (\S+)')
_EXCEPTION = re.compile(r"^(?:\[ERROR\]\s+)?([A-Za-z_][\w.]*)(?::\s*(.*))?$")
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


# The universal alarm reader (G9-A2a): how many of the resource's other metrics, and CloudTrail's limits.
SIBLING_METRICS = int(os.environ.get("WARDEN_ALARM_SIBLING_METRICS", "12"))
CHANGE_NAMES = 3
CHANGE_MAX = 20
_READ_VERBS = ("Describe", "Get", "List", "Lookup", "BatchGet", "Head", "Search", "Scan", "Query")


def _safe(value) -> str:
    """An AWS-returned name or code as one token: anything else becomes `_` (no space, no quote, no newline)."""
    return re.sub(r"[^A-Za-z0-9._:/@=+-]", "_", str(value if value is not None else "-"))[:120] or "-"


def _dims(dims: dict[str, str]) -> str:
    return ",".join(f"{_safe(k)}={_safe(v)}" for k, v in sorted(dims.items())) or "-"


def _key(name: str) -> str:
    """`ApproximateNumberOfMessagesVisible` -> `approximatenumberofmessagesvisible`; a metric key, never text."""
    return re.sub(r"[^a-z0-9]+", "_", str(name).lower()).strip("_")[:60] or "metric"


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
        frames: list[tuple[str, int, str]] = []
        j = i + 1
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
        exception = ""
        if j < len(lines) and frames:
            m = _EXCEPTION.match(lines[j][0].strip())
            if m:
                exception = lines[j][0].strip().removeprefix("[ERROR]").strip()
        if not exception:
            before = text[:at].strip() or (lines[i - 1][0].strip() if i else "")
            if before.startswith("[ERROR]"):
                exception = before.removeprefix("[ERROR]").strip()
        ours = [f for f in frames if f[0].startswith("/var/task/")]
        if ours:
            path, line_no, func = ours[-1]
            found.append({
                "path": path.removeprefix("/var/task/"), "line": line_no, "func": func,
                "exception": exception or "?", "version": version,
            })
        i = max(j, i + 1)
    return found


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


class StackBackend:
    """Reads every resource the alert's labels name, one isolated reader each."""
    reads_live_store = True  # its store receives log lines late: evidence waits for them (R23)


    name = "stack"

    def __init__(self, *, clients: dict | None = None, k8s_factory=None, db_factory=None,
                 download=None, region: str | None = None) -> None:
        # Injectable clients/factories so the unit tests need no AWS account, cluster or database.
        own = not clients  # nothing injected: this backend makes its clients (and, in the runtime, per incident)
        clients = dict(clients or {})
        needed = ("lambda", "logs", "cloudwatch", "ecs", "sqs", "dynamodb", "elasticache", "rds",
                  "elbv2", "apigatewayv2", "secretsmanager", "sns", "events", "sts", "ec2", "eks", "pi", "cloudtrail")
        missing = [n for n in needed if n not in clients]
        if missing:
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
        self._clients = clients  # every other service's client, made when an alarm names one (aws_describe.py)
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
        self._bound: dict[int, StackBackend] = {}
        if template and own:
            from .aws_backend import _reader_clients

            self._per_env = _reader_clients(session, cfg, template, needed)

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
        clients = self._per_env(alert.environment, alert.alert_id)
        with self._lock:
            bound = self._bound.get(id(clients))
            if bound is None:
                bound = StackBackend(clients=clients, k8s_factory=self._k8s_factory, db_factory=self._db_factory,
                                     download=self._download)
                self._bound = {id(clients): bound}  # one incident's at a time; the session itself is held 10 min
        return bound

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
        if lab.get("alarm"):
            readers.append(("alarm", lambda out: self._read_alarm(out, alert, lab["alarm"])))
        # The state of any other main service's resource the alarm names (G9-A2c): one closed table of reads.
        from . import aws_describe

        readers += [(key.replace("_", "-"), lambda out, key=key: self._read_state(out, key, lab[key]))
                    for key in aws_describe.TABLE if lab.get(key)]
        readers += [(f"lambda/{f}", lambda out, f=f: self._read_lambda(out, alert, f, _suffix(f, len(fns) > 1))) for f in fns]
        readers += [(f"sqs/{q}", lambda out, q=q: self._read_sqs(out, alert, q, _suffix(q, len(queues) > 1))) for q in queues]
        if lab.get("dynamodb_table"):
            readers.append(("dynamodb", lambda out: self._read_dynamodb(out, alert, lab["dynamodb_table"])))
        if lab.get("elasticache"):
            readers.append(("elasticache", lambda out: self._read_elasticache(out, alert, lab["elasticache"])))
        if lab.get("aurora_cluster"):
            readers.append(("aurora", lambda out: self._read_aurora(out, alert, lab["aurora_cluster"])))
            readers.append(("aurora-db-writer", lambda out: self._read_db(out, "WARDEN_STACK_DB_WRITER_DSN", "", alert)))
            readers.append(("aurora-db-reader", lambda out: self._read_db(out, "WARDEN_STACK_DB_READER_DSN", "reader_", alert)))
        if lab.get("alb_target_group"):
            readers.append(("alb", lambda out: self._read_alb(out, alert, lab["alb_target_group"])))
        if lab.get("apigw"):
            readers.append(("apigw", lambda out: self._read_apigw(out, alert, lab["apigw"])))
        if lab.get("ecs_cluster") and lab.get("ecs_service"):
            readers.append(("ecs", lambda out: self._read_ecs(out, alert)))
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
        return total

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
                out.lines.append(_partial(f"{reader} metrics", f"{ids[res['Id']][0]} {res['StatusCode']} "
                                          "(the series may be incomplete)"))
            if res.get("Id") in ids and values:
                key, stat = ids[res["Id"]]
                got[key] = float(sum(values) if stat == "Sum" else
                                 max(values) / METRIC_PERIOD_S if stat == "Sum/s" else max(values))
        return got

    def _read_alarm(self, out: _Out, alert: Alert, name: str) -> None:
        """Any alarm, any service (G9-A2a): the alarm exactly as CloudWatch defines it - never its name's or its
        description's text - its own metric over the window, the resource's other recently active metrics, and the
        writes to the resource in CloudTrail. Before this an alarm on anything but the named readers' resources read
        nothing (audit 2026-10-10)."""
        found = self._cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"]).get("MetricAlarms") or []
        if not found:
            raise ToolError("no metric alarm by that name (a composite alarm is read through the alarms it names)")
        a = found[0]
        ns, metric = a.get("Namespace"), a.get("MetricName")
        dims = {str(d.get("Name")): str(d.get("Value")) for d in a.get("Dimensions") or []}
        threshold = (f"threshold {_safe(a.get('ComparisonOperator'))} {a.get('Threshold')} "
                     f"datapoints={a.get('DatapointsToAlarm') or a.get('EvaluationPeriods')}/{a.get('EvaluationPeriods')} "
                     f"missing={_safe(a.get('TreatMissingData') or 'missing')} state={_safe(a.get('StateValue'))}")
        if not (ns and metric):  # metric math: the expression is the owner's text, not read
            out.lines.append(f"ALARM metric-math {threshold}")
            self._read_changes(out, alert, {})
            return
        stat = a.get("Statistic") or "Maximum"  # an extended statistic (p99) is read as the maximum
        out.lines.append(f"ALARM {_safe(ns)}/{_safe(metric)} {_dims(dims)} stat={_safe(a.get('Statistic') or a.get('ExtendedStatistic'))} "
                         f"period={a.get('Period')}s {threshold}")
        out.metrics.update(self._cw_read(out, "alarm", alert, {f"alarm_{_key(metric)}": (ns, metric, dims, stat)}))
        listed, _ = _pages(self._cw.list_metrics, "Metrics", token="NextToken", Namespace=ns,
                           Dimensions=[{"Name": k, "Value": v} for k, v in dims.items()], RecentlyActive="PT3H")
        others: dict[str, tuple] = {}
        for m in listed:
            other = str(m.get("MetricName") or "")
            same = {str(d.get("Name")): str(d.get("Value")) for d in m.get("Dimensions") or []} == dims
            if other and other != metric and same and len(others) < SIBLING_METRICS:
                others[f"{_key(ns.split('/')[-1])}_{_key(other)}"] = (ns, other, dims, "Maximum")
        out.metrics.update(self._cw_read(out, "alarm-siblings", alert, others))
        self._read_changes(out, alert, dims)

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
        names = sorted({v for k, v in alert.labels.items() if k in LABEL_KEYS and v} | set(dims.values()))
        for n in names[:CHANGE_NAMES]:
            try:
                events, _ = _pages(self._ct.lookup_events, "Events", token="NextToken",
                                   LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": n}],
                                   StartTime=started - RECENT_DEPLOY_WINDOW, EndTime=started + timedelta(minutes=5))
            except Exception as exc:  # noqa: BLE001
                out.lines.append(_partial("changes", exc))
                continue
            writes = [e for e in events if str(e.get("ReadOnly", "")).lower() == "false"
                      or (e.get("ReadOnly") is None and not str(e.get("EventName", "")).startswith(_READ_VERBS))]
            for e in writes[:CHANGE_MAX]:
                out.lines.append(f"CHANGE {_z(e.get('EventTime'))} {_safe(e.get('EventSource'))} "
                                 f"{_safe(e.get('EventName'))} on {_safe(n)} by {_safe(e.get('Username') or '?')}")

    def _served_before(self, fn: str, candidates: list[str], before: datetime) -> str:
        """The version that served the most `live` traffic in the SERVED_LOOKBACK before `before`
        (the current version's publish time), or "" when no candidate shows any.

        ⛔ Not "the numerically previous version". A version that was deployed and rolled back is
        still the newest older one: Wave 4 (2026-09-26) rolled checkout back onto the previous
        fault's broken version twice (fs-01 -> 6, fs-02 -> 7) while version 3 had served the traffic
        for hours. Lambda keeps no alias history; its ExecutedVersion metric does.
        """
        cands = candidates[-SERVED_CANDIDATES:]
        if not cands:
            return ""
        specs = [{"Id": f"v{i}", "ReturnData": True, "MetricStat": {
            "Metric": {"Namespace": "AWS/Lambda", "MetricName": "Invocations", "Dimensions": [
                {"Name": "FunctionName", "Value": fn}, {"Name": "Resource", "Value": f"{fn}:live"},
                {"Name": "ExecutedVersion", "Value": v}]},
            "Period": 300, "Stat": "Sum"}} for i, v in enumerate(cands)]
        try:
            resp = self._cw.get_metric_data(MetricDataQueries=specs, StartTime=before - SERVED_LOOKBACK,
                                            EndTime=before)
        except Exception:  # noqa: BLE001 - no traffic data: the caller falls back, and says so
            return ""
        served = {cands[int(r["Id"][1:])]: sum(r.get("Values") or [])
                  for r in resp.get("MetricDataResults") or [] if str(r.get("Id", "")).startswith("v")}
        best, calls = max(served.items(), key=lambda kv: (kv[1], int(kv[0])), default=("", 0.0))
        return best if calls > 0 else ""

    def _in_window(self, alert: Alert, at: datetime | None) -> bool:
        return deploy_in_window(alert, at, RECENT_DEPLOY_WINDOW)

    # ------------------------------------------------------------------ lambda

    def _read_lambda(self, out: _Out, alert: Alert, fn: str, sfx: str) -> None:
        # Logs first: they carry the traceback, and a failed config read must not cost them.
        self._lambda_logs(alert, fn, out)
        self._insights(out, alert, f"/aws/lambda/{fn}", f"lambda/{fn}", sfx)
        alias = None
        try:
            alias = self._lambda.get_alias(FunctionName=fn, Name="live")
        except Exception as exc:  # noqa: BLE001
            if _error_code(exc) != "ResourceNotFoundException":  # no alias is normal
                out.lines.append(_partial(f"lambda/{fn} alias", exc))
        live = (alias or {}).get("FunctionVersion")
        cfg = (self._lambda.get_function_configuration(FunctionName=fn, Qualifier="live")
               if live else self._lambda.get_function_configuration(FunctionName=fn))
        conc = self._lambda.get_function_concurrency(FunctionName=fn).get("ReservedConcurrentExecutions")

        listed, cut = _pages(self._lambda.list_versions_by_function, "Versions", next_token="NextMarker",
                             FunctionName=fn)
        versions = sorted((v for v in listed if str(v.get("Version")).isdigit()), key=lambda v: int(v["Version"]))
        if cut:  # versions come oldest first: the newest were the ones not read
            out.lines.append(_partial(f"lambda/{fn} versions", f"[output truncated] more than {LIST_MAX_PAGES} pages; "
                                      "the newest versions were not read"))
            versions = []

        env = _env_items((cfg.get("Environment") or {}).get("Variables") or {})
        out.metrics[f"lambda_timeout_s{sfx}"] = float(cfg.get("Timeout") or 0)
        out.metrics[f"lambda_memory_mb{sfx}"] = float(cfg.get("MemorySize") or 0)
        if conc is not None:
            out.metrics[f"lambda_reserved_concurrency{sfx}"] = float(conc)
        latest = versions[-1]["Version"] if versions else "$LATEST"
        sgs = sorted((cfg.get("VpcConfig") or {}).get("SecurityGroupIds") or [])  # in-VPC functions only
        sg_part = f"sgs=[{','.join(sgs)}] " if sgs else ""
        out.lines.append(
            f"CONFIG lambda {fn} timeout={cfg.get('Timeout')}s memory={cfg.get('MemorySize')}MB "
            f"reserved_concurrency={'none' if conc is None else conc} env=[{','.join(env)}] "
            f"{sg_part}version={latest} alias_live={live or '-'}"
        )

        esms, _ = _pages(self._lambda.list_event_source_mappings, "EventSourceMappings", next_token="NextMarker",
                         FunctionName=fn)
        for m in esms:
            source = str(m.get("EventSourceArn", "?")).rsplit(":", 1)[-1]
            out.lines.append(f"ESM {fn} <- {source} State={m.get('State')} BatchSize={m.get('BatchSize')} "
                             f"LastProcessingResult={m.get('LastProcessingResult')}")
        if esms:
            out.metrics[f"lambda_esm_enabled{sfx}"] = float(all(m.get("State") == "Enabled" for m in esms))

        # A deploy: the version `live` points at (else the newest published one) was published
        # inside the window. Its publish time stands in for the alias move, which has no timestamp.
        if live:
            target = next((v for v in versions if v["Version"] == live), None)
        else:
            target = versions[-1] if versions else None
        at = _parse_time(target.get("LastModified")) if target else None
        if target and self._in_window(alert, at):
            older = [v["Version"] for v in versions if int(v["Version"]) < int(target["Version"])]
            served = self._served_before(fn, older, at) if live else ""
            out.deploys.append({"kind": "lambda", "service": fn, "at": _z(at),
                                "version": target["Version"],
                                "previous": served or (older[-1] if older else ""),
                                "previous_basis": ("served live traffic before this version" if served
                                                   else "numerically previous version (no per-version traffic)")})

        dims = {"FunctionName": fn}
        out.metrics.update(self._cw_read(out, f"lambda/{fn}", alert, {
            f"lambda_errors{sfx}": ("AWS/Lambda", "Errors", dims, "Sum"),
            f"lambda_throttles{sfx}": ("AWS/Lambda", "Throttles", dims, "Sum"),
            f"lambda_invocations{sfx}": ("AWS/Lambda", "Invocations", dims, "Sum"),
            f"lambda_duration_max_ms{sfx}": ("AWS/Lambda", "Duration", dims, "Maximum"),
            f"lambda_concurrent_executions{sfx}": ("AWS/Lambda", "ConcurrentExecutions", dims, "Maximum"),
        }))

    def _lambda_logs(self, alert: Alert, fn: str, out: _Out) -> None:
        group_alert = alert.model_copy(update={"labels": {"log_group": f"/aws/lambda/{fn}"}})
        physical: list[tuple[str, str]] = []  # (line, version from the stream name)
        for raw in self._aws.logs(group_alert):
            if raw.startswith(PARTIAL_PREFIX):
                out.lines.append(_partial(f"lambda/{fn} logs", raw))
                continue
            stream, stamp, message = (raw.removeprefix("LOG ").split(" ", 2) + ["", ""])[:3]
            m = _STREAM_VERSION.search(stream)
            version = m.group(1) if m else "$LATEST"
            for part in message.splitlines():
                if part.startswith(("START RequestId", "END RequestId")):
                    continue
                out.lines.append(_retag_aws_line(f"lambda/{fn}", f"{stream} {stamp} {part}"))
                physical.append((part, version))

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
                    resp = (self._lambda.get_function(FunctionName=fn, Qualifier=v) if v != "$LATEST"
                            else self._lambda.get_function(FunctionName=fn))
                    packages[v] = self._download(resp["Code"]["Location"])
                out.lines += source_excerpt(fn, packages[v], tb["path"], tb["line"])
            except Exception as exc:  # noqa: BLE001 - the frame stands without its source
                out.lines.append(_partial(f"lambda/{fn} code", exc))

    # ------------------------------------------------------------------ sqs

    def _queue_attrs(self, name: str, attrs: list[str]) -> dict:
        url = self._sqs.get_queue_url(QueueName=name)["QueueUrl"]
        return self._sqs.get_queue_attributes(QueueUrl=url, AttributeNames=attrs).get("Attributes") or {}

    def _read_sqs(self, out: _Out, alert: Alert, q: str, sfx: str) -> None:
        a = self._queue_attrs(q, ["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible",
                                  "VisibilityTimeout", "RedrivePolicy"])
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
            "ddb_consumed_rcu": ("AWS/DynamoDB", "ConsumedReadCapacityUnits", dims, "Sum/s"),
            "ddb_consumed_wcu": ("AWS/DynamoDB", "ConsumedWriteCapacityUnits", dims, "Sum/s"),
            "ddb_read_throttle_events": ("AWS/DynamoDB", "ReadThrottleEvents", dims, "Sum"),
            "ddb_write_throttle_events": ("AWS/DynamoDB", "WriteThrottleEvents", dims, "Sum"),
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
        started = AwsBackend._started_at(alert)
        # By source, every page (audit A-B-L4): the whole account's events, one page of them, could hold none of ours.
        sources = [(rg, "replication-group"), *((m, "cache-cluster") for m in members)]
        events = [e for sid, kind in sources for e in _pages(
            self._ec.describe_events, "Events", SourceIdentifier=sid, SourceType=kind,
            StartTime=started - LOG_LOOKBACK, EndTime=started + LOG_LOOKBACK)[0]]
        for e in sorted(events, key=lambda e: str(e.get("Date"))):
            if e.get("SourceIdentifier") in {rg, *members}:
                out.lines.append(f"EVENT elasticache {rg} {_z(e.get('Date'))} {_one_line(e.get('Message', ''))}")
        queries = {}
        for i, node in enumerate(members):
            d = {"CacheClusterId": node}
            for metric, stat in (("DatabaseMemoryUsagePercentage", "Maximum"), ("Evictions", "Sum"),
                                 ("CurrConnections", "Maximum"), ("EngineCPUUtilization", "Maximum"),
                                 ("ReplicationLag", "Maximum")):
                queries[f"{metric}#{i}"] = ("AWS/ElastiCache", metric, d, stat)
        # ⭐ The network path, as evidence. Without these lines an "unreachable cache" report could
        # only say "check the security group" - with them it can name the rule that is missing.
        node_type = next((c.get("CacheNodeType") for c in clusters if c.get("CacheNodeType")), "?")
        sgs = sorted({g["SecurityGroupId"] for c in clusters for g in c.get("SecurityGroups") or []})
        out.lines.append(f"REPLGROUP {rg} node_type={node_type} sgs=[{','.join(sgs)}]")
        if sgs:
            ng = (group.get("NodeGroups") or [{}])[0]
            port = int((ng.get("PrimaryEndpoint") or {}).get("Port") or 6379)
            for g in self._ec2.describe_security_groups(GroupIds=sgs).get("SecurityGroups") or []:
                rules = [r for r in g.get("IpPermissions") or [] if r.get("IpProtocol") in ("-1", "tcp")
                         and (r.get("IpProtocol") == "-1" or r.get("FromPort", 0) <= port <= r.get("ToPort", 0))]
                # Groups, CIDR ranges and prefix lists alike (audit A-B-L5): a rule opening the port to a CIDR or a
                # prefix list was read as no rule at all.
                src = sorted({p["GroupId"] for r in rules for p in r.get("UserIdGroupPairs") or []}
                             | {x["CidrIp"] for r in rules for x in r.get("IpRanges") or [] if x.get("CidrIp")}
                             | {x["CidrIpv6"] for r in rules for x in r.get("Ipv6Ranges") or [] if x.get("CidrIpv6")}
                             | {x["PrefixListId"] for r in rules for x in r.get("PrefixListIds") or []
                                if x.get("PrefixListId")})
                out.lines.append(f"SG {g['GroupId']} ingress tcp/{port} from=[{','.join(src)}]")
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
            "aurora_connections": ("AWS/RDS", "DatabaseConnections", d, "Maximum"),
            "aurora_acu_utilization_pct": ("AWS/RDS", "ACUUtilization", d, "Maximum"),
            "aurora_cpu_pct": ("AWS/RDS", "CPUUtilization", d, "Maximum"),
            "aurora_deadlocks": ("AWS/RDS", "Deadlocks", d, "Maximum"),
        }
        for i, r in enumerate(readers):
            queries[f"lag#{i}"] = ("AWS/RDS", "AuroraReplicaLag", {"DBInstanceIdentifier": r}, "Maximum")
        got = self._cw_read(out, "aurora", alert, queries)
        lags = [v for k, v in got.items() if k.startswith("lag#")]
        out.metrics.update({k: v for k, v in got.items() if not k.startswith("lag#")})
        if lags:
            out.metrics["aurora_replica_lag_ms"] = max(lags)

    def _db_load(self, out: _Out, alert: Alert, instances: list[dict]) -> None:
        """Performance Insights (requirement R22): each member's database load over the alert window, and that load
        by wait-event TYPE (CPU, Lock, IO, LWLock, Client, ...). Numbers under names from that closed list; no SQL
        text and no wait-event names reach the evidence. Free within PI's 7-day window and 1M API calls a month."""
        started = AwsBackend._started_at(alert)
        queries = [{"Metric": "db.load.avg"},
                   {"Metric": "db.load.avg", "GroupBy": {"Group": "db.wait_event_type", "Limit": 6}}]
        for inst in instances:
            name = inst.get("DBInstanceIdentifier", "?")
            if not inst.get("PerformanceInsightsEnabled") or not inst.get("DbiResourceId"):
                out.lines.append(_partial("aurora metrics", f"Performance Insights is off on {_one_line(name)}"))
                continue
            try:
                got = self._pi.get_resource_metrics(
                    ServiceType="RDS", Identifier=inst["DbiResourceId"], MetricQueries=queries, PeriodInSeconds=60,
                    StartTime=started - LOG_LOOKBACK, EndTime=started + LOG_LOOKBACK)
            except Exception as exc:  # noqa: BLE001 - one member unread is data, the others still read
                out.lines.append(_partial("aurora metrics", exc))
                continue
            for m in got.get("MetricList") or []:
                values = [p["Value"] for p in m.get("DataPoints") or []
                          if isinstance(p.get("Value"), int | float) and not isinstance(p.get("Value"), bool)]
                if not values:
                    continue
                kind = ((m.get("Key") or {}).get("Dimensions") or {}).get("db.wait_event_type.name")
                key = "aurora_db_load" + (f"_{re.sub(r'[^a-z0-9]', '', str(kind).lower())[:20]}" if kind else "")
                out.metrics[key] = max(out.metrics.get(key, 0.0), float(max(values)))

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
            deadline = time.monotonic() + INSIGHTS_WAIT_S
            while True:
                got = self._logs.get_query_results(queryId=qid)
                status = got.get("status")
                if status == "Complete":
                    break
                if status not in ("Scheduled", "Running"):
                    out.lines.append(_partial(f"{tag} metrics", f"the Logs Insights query ended {_one_line(status)}"))
                    return
                if time.monotonic() > deadline:
                    self._logs.stop_query(queryId=qid)
                    out.lines.append(_partial(f"{tag} metrics",
                                              f"the Logs Insights query did not finish in {INSIGHTS_WAIT_S:.0f}s"))
                    return
                self._sleep(0.5)
        except Exception as exc:  # noqa: BLE001 - the error counts are extra evidence, the logs above still stand
            out.lines.append(_partial(f"{tag} metrics", exc))
            return
        counts = []
        for row in got.get("results") or []:
            for f in row:
                if f.get("field") == "n":
                    try:
                        counts.append(float(f.get("value")))
                    except (TypeError, ValueError):
                        continue
        out.metrics[f"log_error_lines{sfx}"] = sum(counts)
        out.metrics[f"log_errors_peak_per_min{sfx}"] = max(counts, default=0.0)

    def _read_db(self, out: _Out, env: str, prefix: str, alert: Alert) -> None:
        """The existing PostgreSQL backend on one Aurora endpoint, names unchanged (reader: `reader_`)."""
        dsn = os.environ.get(env)
        if not dsn:
            raise ToolError(f"{env} is not set; the {'reader' if prefix else 'writer'} sessions were not read")
        db = self._db_factory(dsn)
        role = "reader" if prefix else "writer"
        try:
            out.metrics.update({f"{prefix}{k}": v for k, v in db.metrics(alert).items()})
        except Exception as exc:  # noqa: BLE001 - the session lines below may still read
            out.lines.append(_partial(f"aurora-db-{role} metrics", exc))
        for line in db.logs(alert):
            if line.startswith(PARTIAL_PREFIX):
                out.lines.append(_partial(f"aurora-db-{role}", line))
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
            lb = lbs[0].split(":loadbalancer/", 1)[-1]
            tgd = {"TargetGroup": tg["TargetGroupArn"].split(":", 5)[-1], "LoadBalancer": lb}
            out.metrics.update(self._cw_read(out, "alb", alert, {
                "alb_target_5xx": ("AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", tgd, "Sum"),
                "alb_elb_5xx": ("AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", {"LoadBalancer": lb}, "Sum"),
                "alb_target_response_time_s": ("AWS/ApplicationELB", "TargetResponseTime", tgd, "Maximum"),
            }))

    def _read_apigw(self, out: _Out, alert: Alert, api_name: str) -> None:
        apis, _ = _pages(self._apigw.get_apis, "Items", token="NextToken")
        api = next((a for a in apis if a.get("Name") == api_name), None)
        if api is None:
            raise ToolError(f"no HTTP API named '{api_name}'")
        d = {"ApiId": api["ApiId"]}
        out.metrics.update(self._cw_read(out, "apigw", alert, {
            "apigw_5xx": ("AWS/ApiGateway", "5xx", d, "Sum"),
            "apigw_4xx": ("AWS/ApiGateway", "4xx", d, "Sum"),
            "apigw_latency_ms": ("AWS/ApiGateway", "Latency", d, "Maximum"),
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
        # The identity the service's code runs as (not the execution role): what a denied database
        # login or API call must be granted back to. Absent when the task definition has none.
        if svc.get("taskDefinition"):
            td = self._ecs.describe_task_definition(taskDefinition=svc["taskDefinition"]).get("taskDefinition") or {}
            if td.get("taskRoleArn"):
                out.lines.append(f"TASKROLE ecs/{service} role={td['taskRoleArn'].rsplit('/', 1)[-1]}")
        for d in self._aws.deploys(a):
            if isinstance(d, str):
                out.lines.append(_partial("ecs deploys", d))
            else:
                # `version`/`previous` are family:revision (what a rollback aims at); the images ride along.
                out.deploys.append({"kind": "ecs", "service": service, "at": _z(_parse_time(d["at"])),
                                    "version": d.get("task_definition", ""),
                                    "previous": d.get("previous_task_definition", ""),
                                    "image": d.get("image", ""), "previous_image": d.get("previous_image", ""),
                                    "revision": d.get("revision", ""),
                                    # a rollback: nothing to roll back to, and the evidence says so (audit A-B-M6)
                                    **({"rolled_back_from": d["rolled_back_from"]} if d.get("rolled_back_from") else {})})

    def _read_eks(self, out: _Out, cluster: str) -> None:
        vpc = self._eks.describe_cluster(name=cluster)["cluster"].get("resourcesVpcConfig") or {}
        sgs = sorted({*(vpc.get("securityGroupIds") or []), *([vpc["clusterSecurityGroupId"]]
                                                              if vpc.get("clusterSecurityGroupId") else [])})
        if sgs:
            out.lines.append(f"APPSG eks/{cluster} sgs=[{','.join(sgs)}]")

    def _read_k8s(self, out: _Out, alert: Alert, ns: str, dep: str, sfx: str) -> None:
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
        r = self._events.describe_rule(Name=rule)
        out.lines.append(f"RULE {rule} State={r.get('State')} schedule={r.get('ScheduleExpression', '-')}")
        out.metrics[f"rule_enabled{sfx}"] = float(r.get("State") == "ENABLED")
        out.metrics.update(self._cw_read(out, f"eventbridge/{rule}", alert, {
            f"rule_invocations{sfx}": ("AWS/Events", "Invocations", {"RuleName": rule}, "Sum"),
        }))


def _policy_allows_topic(policy: str | None, topic_arn: str) -> bool:
    """Does a queue policy let this SNS topic SendMessage? An explicit Deny wins."""
    if not policy:
        return False
    def matches(st, unknown: bool) -> bool:
        actions = st.get("Action") or []
        actions = [actions] if isinstance(actions, str) else actions
        if not any(a in ("*", "sqs:*", "sqs:SendMessage") for a in actions):
            return False
        principal = st.get("Principal")
        if principal != "*":
            p = (principal or {}).get("Service") or (principal or {}).get("AWS") or []
            p = [p] if isinstance(p, str) else p
            if not any(x in ("*", "sns.amazonaws.com") for x in p):
                return False
        # Each operator by its meaning (audit A-B-L5): `ArnNotEquals` was read as `ArnEquals`, so a Deny of every
        # topic BUT this one denied this one. An operator not understood here gives `unknown`: an Allow it cannot
        # prove does not allow, and a Deny it cannot read is taken to apply.
        for op, test in (st.get("Condition") or {}).items():
            key = next((k for k in test if k.lower() == "aws:sourcearn"), None)
            if key is None:
                continue
            values = test[key] if isinstance(test[key], list) else [test[key]]
            base = op.split(":")[-1].removesuffix("IfExists")
            hit = any(fnmatch.fnmatchcase(topic_arn, str(v)) for v in values)
            if base in ("ArnEquals", "ArnLike", "StringEquals", "StringLike"):
                ok = hit
            elif base in ("ArnNotEquals", "ArnNotLike", "StringNotEquals", "StringNotLike"):
                ok = not hit
            elif base == "Null":  # SNS always sends the topic as the source: present, never null
                ok = str(values[0]).lower() == "false"
            else:
                return unknown
            if not ok:
                return False
        return True

    statements = json.loads(policy).get("Statement") or []
    statements = [statements] if isinstance(statements, dict) else statements
    if any(st.get("Effect") == "Deny" and matches(st, unknown=True) for st in statements):
        return False
    return any(st.get("Effect") == "Allow" and matches(st, unknown=False) for st in statements)


def _default_k8s():
    from .k8s_backend import KubernetesBackend

    return KubernetesBackend()


def _default_db(dsn: str):
    from .database import DatabaseBackend

    return DatabaseBackend(dsn=dsn, engine="postgres")
