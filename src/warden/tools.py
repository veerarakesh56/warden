"""Context tools — the evidence layer.

Deliberate design choice: **the model does not call these.** They run first, deterministically, and
their output is redacted before it is shown. A model that chooses its own tool calls also chooses
what evidence to look at, and that turns "what happened?" into "what did it decide to look for?".

Every tool runs under a **real wall-clock timeout** and every failure is recorded rather than
swallowed, because a partial picture must be visible to the verifier (policy P8) instead of looking
like a complete one. A hung logging backend during an incident is the normal case, not the edge one.

The fixtures here stand in for real backends. Swapping `FixtureBackend` for a Loki, CloudWatch or
Datadog client is a change to one class, which is why the boundary is drawn here.
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
import re
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .models import Alert, ContextBundle

# A change made this long after the alert started still counts: clocks differ between a monitor and a control plane.
DEPLOY_AFTER_ALERT = timedelta(minutes=float(os.environ.get("WARDEN_DEPLOY_AFTER_ALERT_M", "2")))


def alert_time(alert: Alert) -> datetime:
    """The alert's own start time, or now if it cannot be parsed. Never raises: an unparseable timestamp must not
    lose the evidence, and `now` reads the most recent window rather than one from 1970."""
    raw = (alert.started_at or "").strip()
    if raw:
        try:
            parsed = datetime.fromisoformat(raw)  # 3.11+ parses a trailing Z natively
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(UTC)


def deploy_in_window(alert: Alert, at: datetime | None, window: timedelta) -> bool:
    """Whether a change reached production in the `window` before the alert started. Measured from the alert, not from
    now: a replayed or late incident took any change of the last hours, and one made AFTER the alert - often the first
    attempt at a fix - is no cause of it (audit A-B-M10)."""
    started = alert_time(alert)
    return at is not None and started - window <= at <= started + DEPLOY_AFTER_ALERT
from .observability import _safe_error, span

# Fixtures live INSIDE the package and are shipped as package data.
#
# ⛔ They used to sit at the repo root, found via `parents[2] / "fixtures"`. That works from a
# source checkout and silently breaks once the package is pip-installed: the path resolves to
# `<site-packages>/../../fixtures`, which does not exist. In the container every tool therefore
# failed, the context came back empty, and the demo returned AUTO_SAFE for all four incidents —
# wrong answers, exit code 0, and a green CI job that only checked the exit code.
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"

_log = logging.getLogger("warden.tools")

# Wall-clock ceiling per tool. Threads are used rather than signals because signal-based timeouts
# are POSIX-main-thread only, and this has to behave identically on Windows and in a container.
TOOL_TIMEOUT_S = float(os.environ.get("WARDEN_TOOL_TIMEOUT", "5.0"))


class ToolError(RuntimeError):
    """A read WARDEN could not do. `outcome` says how, in the fixed vocabulary of OUTCOMES, when WARDEN
    knows it (no live pods, an unsupported DSN); otherwise its cause decides (outcome_of)."""

    def __init__(self, message: str, *, outcome: str | None = None) -> None:
        super().__init__(message)
        self.outcome = outcome


# How a read can fail - the only words a T item may use for it (evidence.tool_error_text).
ACCESS_DENIED = "access denied"
CREDENTIALS_REJECTED = "credentials rejected or missing"
TIMED_OUT = "timed out"
CONNECTION_FAILED = "connection failed"
NOT_FOUND = "not found"
BAD_REQUEST = "rejected as a bad request"
OUTCOMES = (ACCESS_DENIED, CREDENTIALS_REJECTED, "throttled", TIMED_OUT, CONNECTION_FAILED,
            NOT_FOUND, "no live pods", "output truncated", "not supported", BAD_REQUEST,
            "failed (unclassified)")
# Structured codes and exception type names -> outcome. Matched against a botocore error CODE, a
# database SQLSTATE class or an exception's class names - never against a message, which can quote a
# log line (second independent review, 2026-09-30).
_CODE_OUTCOMES = (
    (ACCESS_DENIED, r"AccessDenied|UnauthorizedOperation|Forbidden|AuthorizationError|NotAuthorized"),
    (CREDENTIALS_REJECTED, (r"ExpiredToken|InvalidClientTokenId|UnrecognizedClient|"
                                        r"NoCredentials|PartialCredentials|CredentialRetrieval|InvalidSignature")),
    ("throttled", r"Throttl|TooManyRequests|RequestLimitExceeded|SlowDown|ProvisionedThroughputExceeded"),
    (TIMED_OUT, r"Timeout|TimedOut"),
    (CONNECTION_FAILED, (r"EndpointConnection|ConnectionRefused|ConnectionReset|ConnectionClosed|"
                          r"ConnectionError|gaierror|OperationalError")),
    (NOT_FOUND, r"NotFound|NoSuch"),
    (BAD_REQUEST, r"Validation|InvalidParameter|BadRequest|MalformedQuery"),
)
_HTTP_OUTCOMES = {400: BAD_REQUEST, 401: CREDENTIALS_REJECTED, 403: ACCESS_DENIED,
                  404: NOT_FOUND, 408: TIMED_OUT, 429: "throttled", 504: TIMED_OUT}
_SQLSTATE_OUTCOMES = {"28": CREDENTIALS_REJECTED, "42501": ACCESS_DENIED, "57014": TIMED_OUT,
                      "08": CONNECTION_FAILED, "53": "throttled"}


def outcome_of(exc: BaseException) -> str:
    """How a read failed, from the exception's TYPE and structured codes only."""
    import re

    if isinstance(exc, ToolError):
        if exc.outcome:
            return exc.outcome
        return outcome_of(exc.__cause__) if exc.__cause__ is not None else OUTCOMES[-1]
    code = _error_code(exc)
    status = getattr(exc, "status", None)
    if isinstance(status, int) and not code and status in _HTTP_OUTCOMES:
        return _HTTP_OUTCOMES[status]
    by_sqlstate = _sqlstate_outcome(getattr(exc, "sqlstate", None) or getattr(exc, "pgcode", None))
    if by_sqlstate:
        return by_sqlstate
    names = code or " ".join(t.__name__ for t in type(exc).__mro__)
    return next((word for word, rx in _CODE_OUTCOMES if re.search(rx, names)), OUTCOMES[-1])


def _error_code(exc: BaseException) -> str:
    """A botocore error's structured code (`response["Error"]["Code"]`); "" for anything else."""
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return ""
    return str((response.get("Error") or {}).get("Code") or "")


def _sqlstate_outcome(sqlstate: Any) -> str | None:
    """The outcome a database SQLSTATE (or its class) names, or None."""
    if not isinstance(sqlstate, str) or not sqlstate:
        return None
    return next((outcome for prefix, outcome in _SQLSTATE_OUTCOMES.items() if sqlstate.startswith(prefix)), None)


def failure_tag(exc: BaseException) -> str:
    """`[<outcome>[ on <operation>]]` - the only part of a tool error a T item reads."""
    op = getattr(exc, "operation_name", None)
    return "[" + outcome_of(exc) + (f" on {op}" if isinstance(op, str) and op.isidentifier() else "") + "]"


def status_tag(status: str) -> str:
    """The tag for a GetMetricData series CloudWatch did not finish, from its StatusCode (G10 review, 2026-10-10: an
    untagged `PartialData` reached the model as "failed (unclassified)")."""
    outcome = {"PartialData": "output truncated", "Forbidden": ACCESS_DENIED}.get(status, "failed (unclassified)")
    return f"[{outcome} on GetMetricData]"


def failure(exc: BaseException) -> str:
    """The tag, then the exception's first line (redacted later, shown to people, never to the model)."""
    text = str(exc).strip()
    return f"{failure_tag(exc)} {(text.splitlines()[0] if text else '')[:200]}"


# A backend that reads many things (several pods' logs, say) may succeed on most and fail on one.
# Raising would lose the successes; returning the failure as a plain line lets the verifier count
# it as EVIDENCE. So: a line carrying this prefix is a partial failure. `gather()` moves every such
# line out of the result and into `tool_errors`, where policy P8 reads it.
PARTIAL_PREFIX = "TOOL-PARTIAL "


# Backend name -> engine key. `db`/`database` map to None: the engine is then read from the DSN
# scheme (postgresql:// mysql:// redis:// mongodb:// mssql://), so one setting covers a mixed estate.
_DB_BACKENDS: dict[str, str | None] = {
    "db": None, "database": None,
    "postgres": "postgres", "postgresql": "postgres",
    "mysql": "mysql", "mariadb": "mysql",
    "redis": "redis", "rediss": "redis",
    "mongo": "mongo", "mongodb": "mongo",
    "mssql": "mssql", "sqlserver": "mssql",
}


def resolve_backend(name: str | None = None):
    """The evidence source `_base_backend` picks - with Grafana (or a company's own Loki, Tempo and Prometheus) and
    Datadog beside it, each when its read keys are set (grafana.py, datadog.py). Never beside the recorded fixtures."""
    base = _base_backend(name)
    if isinstance(base, FixtureBackend):
        return base
    readers = evidence_tools(base)
    if readers:
        from .grafana import WithSources

        return WithSources(base, readers)
    return base


def github_read_token() -> str:
    """The read zone's read-only GitHub token (warden/<env>/github-read-token): the deploy's commits and the findings on
    its pull request; "" reads a public repository unauthenticated. The one place it is taken: a GitHub App's
    short-lived installation token (register B4) replaces this when the App exists."""
    return os.environ.get("WARDEN_GITHUB_READ_TOKEN", "").strip()


def _change_repo() -> str:
    """The repository whose deploys and pull requests are read: WARDEN_CHANGE_REPO, else environments.yaml's."""
    from .environments import default_environment_policies

    return (os.environ.get("WARDEN_CHANGE_REPO", "").strip()
            or str(default_environment_policies().github.get("repository", "")))


def _env_count(name: str, default: int, ceiling: int) -> int:
    """A count from the environment: ASCII digits only (`isdigit` also takes "²", which int() refuses), at most
    `ceiling`; a long string is never converted to find out (CodeRabbit, PR 41)."""
    raw = os.environ.get(name, "").strip()
    if not (raw.isascii() and raw.isdecimal()):
        return default
    digits = raw.lstrip("0") or "0"
    return ceiling if len(digits) > len(str(ceiling)) else min(int(digits), ceiling)


def _findings_reader(base: Any) -> Any:
    """Code review's findings on the deploy's pull request (findings.py), read in the read zone like the commits."""
    from .findings import CEILING_PER_PR, CEILING_PRS, MAX_PER_PR, MAX_PRS, FindingsReader

    return FindingsReader(
        base, repo=_change_repo(), token=github_read_token(),
        sonar_project=os.environ.get("WARDEN_SONAR_PROJECT", "").strip(),
        sonar_token=os.environ.get("WARDEN_SONAR_TOKEN", "").strip(),
        max_prs=_env_count("WARDEN_FINDINGS_MAX_PRS", MAX_PRS, CEILING_PRS),
        max_per_pr=_env_count("WARDEN_FINDINGS_MAX_PER_PR", MAX_PER_PR, CEILING_PER_PR))


def evidence_tools(base: Any) -> list[Any]:
    """The observability tools read beside AWS: each that is configured - X-Ray (WARDEN_XRAY=1, over the incident's
    reader role), Grafana, Datadog - narrowed to WARDEN_EVIDENCE_TOOLS when it names some (the live comparison runs
    each tool alone: "xray", "grafana", "datadog"; "none" reads AWS alone)."""
    from . import datadog, grafana

    chosen = {t.strip() for t in os.environ.get("WARDEN_EVIDENCE_TOOLS", "").lower().split(",") if t.strip()}
    readers: list[Any] = []
    if os.environ.get("WARDEN_XRAY", "").strip() == "1" and hasattr(base, "_incident"):
        from .xray import XRayReader

        readers.append(XRayReader(lambda alert: base._incident(alert)._clients["xray"]))
    if os.environ.get("WARDEN_COMMITS", "").strip() == "1":
        from .timeline import CommitReader

        readers.append(CommitReader(base, repo=_change_repo(), token=github_read_token()))
    if os.environ.get("WARDEN_FINDINGS", "").strip() == "1":
        readers.append(_findings_reader(base))
    if grafana.configured():
        readers.append(grafana.GrafanaReader())
    if datadog.configured():
        readers.append(datadog.DatadogReader())
    if os.environ.get("WARDEN_QUOTAS", "").strip() == "1" and hasattr(base, "_incident"):
        # B14: service quotas and their usage, over the incident's reader role.
        from .quotas import QuotaReader

        readers.append(QuotaReader(lambda alert: base._incident(alert)._clients))
    return [r for r in readers if not chosen or r.source in chosen]


def _base_backend(name: str | None = None):
    """Pick the evidence source from `WARDEN_BACKEND`.

        fixture     recorded incidents shipped with the package (default; what CI uses)
        k8s         a live Kubernetes cluster via kubeconfig or in-cluster credentials
        aws         a live AWS account: CloudWatch Logs, CloudWatch metrics and ECS, read-only
        stack       every AWS/k8s/Aurora resource the alert's labels name (Wave 4), read-only
        postgres | mysql | redis | mongo | mssql   a live database, read-only
                    (or `db`/`database` to pick the engine from the DSN scheme itself)

    Same shape as `providers.resolve()`: the optional client is imported lazily, so the core
    package installs and runs with no cluster library present.
    """
    name = (name or os.environ.get("WARDEN_BACKEND") or "fixture").lower()
    if name in ("fixture", "fixtures", "mock"):
        return FixtureBackend()
    if name in ("k8s", "kubernetes"):
        try:
            from .k8s_backend import KubernetesBackend
        except ImportError as exc:  # the `kubernetes` client is an optional extra
            raise ToolError(
                "WARDEN_BACKEND=k8s needs the Kubernetes client: pip install -e '.[k8s]'"
            ) from exc
        return KubernetesBackend()
    if name in ("aws", "cloudwatch", "ecs"):
        try:
            from .aws_backend import AwsBackend
        except ImportError as exc:  # boto3 is an optional extra
            raise ToolError(
                "WARDEN_BACKEND=aws needs the AWS SDK: pip install -e '.[aws]'"
            ) from exc
        return AwsBackend()
    if name in ("stack", "fullstack"):
        try:
            from .aws_stack import StackBackend
        except ImportError as exc:  # boto3 is an optional extra
            raise ToolError(
                "WARDEN_BACKEND=stack needs the AWS SDK: pip install -e '.[aws]'"
            ) from exc
        return StackBackend()
    if name in _DB_BACKENDS:
        # The driver itself (psycopg / pymysql / redis / pymongo / pymssql) is imported lazily inside
        # the engine adapter at CONNECT time, so a missing extra surfaces as a readable error from the
        # engine you actually asked for - not an ImportError for four you never wanted.
        from .database import DatabaseBackend

        return DatabaseBackend(engine=_DB_BACKENDS[name])
    raise ToolError(
        f"unknown backend '{name}'. Known: fixture, k8s, aws, stack, "
        "db/database, postgres, mysql, redis, mongo, mssql"
    )


@dataclass
class ToolResult:
    name: str
    ok: bool
    payload: object
    error: str | None = None


class FixtureBackend:
    """Reads recorded incident data. Real deployments substitute a live client here."""

    name = "fixture"

    def __init__(self, root: pathlib.Path | None = None) -> None:
        self.root = root or FIXTURES

    def _load(self, alert_id: str) -> dict:
        # ⛔ Contained (2026-09-27 audit): the MCP tool passes a caller's alert_id straight here, and
        # an absolute path or `..` read any *.json on the machine, metrics and all.
        root = self.root.resolve()
        path = (root / f"{alert_id}.json").resolve()
        if path.parent != root or not path.exists():
            raise ToolError(f"no fixture for alert {alert_id!r}")
        return json.loads(path.read_text(encoding="utf-8"))

    def logs(self, alert: Alert) -> list[str]:
        return self._load(alert.alert_id).get("logs", [])

    def metrics(self, alert: Alert) -> dict[str, float]:
        return self._load(alert.alert_id).get("metrics", {})

    def deploys(self, alert: Alert) -> list[dict[str, str]]:
        return self._load(alert.alert_id).get("recent_deploys", [])


def _call_with_timeout(fn, alert: Alert, timeout: float):
    """Run one tool under a wall-clock ceiling.

    ⚠ A timed-out worker thread is abandoned, not killed — Python cannot force-stop a thread. That
    is acceptable here because the caller stops waiting, which is what the deadline is for. A real
    deployment should also set a socket timeout on the backend client so the thread actually ends.

    ⛔ The executor is shut down with `wait=False` deliberately. Using `ThreadPoolExecutor` as a
    context manager calls `shutdown(wait=True)` on exit, which blocks until the hung thread
    finishes — so the deadline fired and the caller waited the full duration anyway. The timeout
    looked implemented and did nothing. Caught by `test_a_hanging_tool_does_not_hang_the_run`.
    """
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        return pool.submit(fn, alert).result(timeout=timeout)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


# Bounds on what one incident may carry (2026-09-27 audit): 150 lines of 64 KB each made a 9.7M-char
# prompt, and redaction time grows with lines x distinct identifiers. Backends already cap lines;
# this is the ceiling whatever the backend. A cut is recorded as a failed read, never silent.
MAX_LINE_CHARS = int(os.environ.get("WARDEN_MAX_LINE_CHARS", "2000"))
MAX_LOG_LINES = int(os.environ.get("WARDEN_MAX_LOG_LINES", "2000"))


def _bounded(lines: list, tool_errors: list[str]) -> list[str]:
    lines = [str(x) for x in lines]
    long = sum(1 for x in lines if len(x) > MAX_LINE_CHARS)
    if len(lines) > MAX_LOG_LINES:
        tool_errors.append(f"logs: [output truncated] kept the newest {MAX_LOG_LINES} of {len(lines)} lines")
        lines = lines[-MAX_LOG_LINES:]
    if long:
        tool_errors.append(f"logs: [output truncated] {long} line(s) cut to {MAX_LINE_CHARS} characters")
        lines = [x[:MAX_LINE_CHARS] for x in lines]
    return lines


class Metrics(dict):
    """A metrics result that can say what it could not read: `partial` lines go to tool_errors as a list result's do.
    A failed or partial metric read vanished, and its absence read as "no such signal" (audit A-B-M18)."""

    def __init__(self, *args, partial: list[str] | None = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.partial = list(partial or [])


def _numbers(metrics: object) -> dict[str, float]:
    """Metrics are numbers. `setattr` bypasses pydantic, so a backend (or a fixture file) returning a
    string or a nested secret under a metric name put it into the prompt and the MCP payload as-is."""
    out: dict[str, float] = {}
    for key, value in (metrics or {}).items() if isinstance(metrics, dict) else ():
        try:
            out[str(key)[:120]] = float(value)
        except (TypeError, ValueError):
            continue
    return out


# A third-party source that answered and found nothing (datadog.py, grafana.py, xray.py: "no error lines for ...",
# "no failed traces/spans for ..."). Not a failed read: an EMPTY one - unknown, never a sign of health (P23 still
# refuses "no action" on it), re-read once while the alert is young (item 3), and no longer a reason for P8 to hold
# every fix (fs-22 run 2, 2026-10-15: Grafana's empty answer held the plan). The segments before it are WARDEN's own
# reader tags; an application's text never starts a TOOL-PARTIAL line.
_NOTHING_FOUND = re.compile(r"^(?:[a-z0-9/_.-]+(?: [a-z]+)?: )*?(datadog|grafana|xray) (logs|traces): "
                            r"no (?:error lines|failed traces|failed spans) for \S+ between ")


def _log_failed_reads(errors: list[str]) -> None:
    """One WARNING per incident naming each read that failed and how, in OUTCOMES' words only - never the error's
    text, which can quote a log line. The cloud's failed reads were visible only inside each incident's record
    (2026-10-15: "every log/telemetry source failed", with nothing in the worker's log)."""
    from .evidence import tool_error_text

    failed, cut = set(), set()
    for e in errors:
        # `<reader>[ <source>]: <outcome>[ on <operation>]`, from fixed words and WARDEN's own reader names only - the
        # T item's own text (the first version named only the tool, "logs", for every stack read).
        text = tool_error_text(e)
        if any(f"[{o}" in e for o in OUTCOMES):
            failed.add(text)
        else:
            # A cut or partial read: no outcome to name, but the verifier counts it (P8), so the log names WHERE -
            # 2026-10-15, fs-22 run 2: P8-PARTIAL-CONTEXT fired and the worker's log said nothing at all.
            cut.add(text.removesuffix(": failed (unclassified)"))
    said = ([f"{len(failed)} read(s) failed: {'; '.join(sorted(failed))}"] if failed else []) + \
        ([f"{len(cut)} read(s) incomplete: {'; '.join(sorted(cut))}"] if cut else [])
    if said:
        _log.warning("%s", " | ".join(said))


_TOOL_OK = "warden.tool.ok"
_TOOL_ERROR = "warden.tool.error"


def _as_named(name: str, text: str) -> str:
    """A tool error line, starting with the tool's name once."""
    return text if text.startswith(f"{name}: ") else f"{name}: {text}"


def _without_partials(name: str, result: list, bundle: ContextBundle) -> tuple[list, int]:
    """(the result without its partial failures, how many there were)"""
    partial = [x for x in result if isinstance(x, str) and x.startswith(PARTIAL_PREFIX)]
    result = [x for x in result if x not in partial]
    for p in partial:
        # ⛔ Audit A-C-5: raw here, like the logs. node_redact scrubs tool errors with
        # the run's ONE placeholder map; scrubbing them here with a fresh map gave
        # `<IPV4_1>` two meanings - one host in a tool error, another in the logs.
        text = p[len(PARTIAL_PREFIX):]
        found = _NOTHING_FOUND.match(text)
        if found:
            source = f"{found.group(1)} {found.group(2)}"
            if source not in bundle.empty_reads:
                bundle.empty_reads.append(source)
            continue
        bundle.tool_errors.append(_as_named(name, text))
    return result, len(partial)


def _settled(name: str, sink: str, result: Any, bundle: ContextBundle, sp: Any) -> Any:
    """What a tool returned, with its partial failures moved into the bundle's tool errors."""
    if isinstance(result, list):
        # Partial failures travel in-band; route them to where the verifier looks.
        result, partials = _without_partials(name, result, bundle)
        sp.set_attribute("warden.tool.partial_failures", partials)
        if sink == "logs":
            result = _bounded(result, bundle.tool_errors)
    if sink == "metrics":
        for p in getattr(result, "partial", ()):
            bundle.tool_errors.append(_as_named(name, p.removeprefix(PARTIAL_PREFIX)))
        result = _numbers(result)
    return result


def gather(
    alert: Alert,
    backend: FixtureBackend | None = None,
    *,
    timeout: float | None = None,
) -> ContextBundle:
    """Run every tool, keep what worked, record what did not."""
    backend = backend or FixtureBackend()
    # A backend that reads many sources says how long its whole read may take (aws_stack.StackBackend.read_timeout_s);
    # the explicit argument still wins.
    timeout = max(TOOL_TIMEOUT_S, float(getattr(backend, "read_timeout_s", 0) or 0)) if timeout is None else timeout
    bundle = ContextBundle()

    for name, fn, sink in (
        ("logs", backend.logs, "logs"),
        ("metrics", backend.metrics, "metrics"),
        ("recent_deploys", backend.deploys, "recent_deploys"),
    ):
        with span(f"tool.{name}", tool=name, timeout_s=timeout) as sp:
            try:
                result = _settled(name, sink, _call_with_timeout(fn, alert, timeout), bundle, sp)
                setattr(bundle, sink, result)
                if not result and sink != "recent_deploys":  # no deploy in the window is a finding; no logs is not
                    bundle.empty_reads.append(name)
                sp.set_attribute(_TOOL_OK, True)
            except FutureTimeout:
                msg = f"{name}: [timed out] timed out after {timeout:.1f}s"
                bundle.tool_errors.append(msg)
                sp.set_attribute(_TOOL_OK, False)
                sp.set_attribute(_TOOL_ERROR, msg)
            except Exception as exc:  # noqa: BLE001 - a tool failing is data; not a crash
                msg = f"{name}: {failure(exc)}"
                bundle.tool_errors.append(msg)  # raw, like the logs: node_redact scrubs it (A-C-5)
                sp.set_attribute(_TOOL_OK, False)
                # The span leaves for a tracing backend on its own: scrubbed, stripped of control
                # characters and bounded, like a span's exception event (review 2A defect 5).
                sp.set_attribute(_TOOL_ERROR, f"{name}: {_safe_error(exc)}")
    _log_failed_reads(bundle.tool_errors)

    return bundle
