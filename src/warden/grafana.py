"""Grafana Cloud - or a company's own Loki, Tempo and Prometheus - as a second evidence source beside AWS (owner,
2026-10-14: "most companies use them ... connect to ours ... logs, traces, metrics ... timestamps can be a bit
different so need to be careful").

Researched the same day: Grafana Cloud's Free tier is free for ever, has a Mumbai region, and answers the open
query APIs - LogQL (Loki), TraceQL (Tempo), PromQL (Prometheus) - to an access-policy token with read scopes only.
The same calls work against self-hosted Loki, Tempo and Prometheus/Mimir. Read live beside Datadog and X-Ray in the
owner's comparison (2026-10-14: "use all 3 of them ... compare"); off unless its settings are given.

What it reads, around the alarm, for the service the alert names: the service's error log lines, its failed traces
(and from them which downstream service failed first - the dependency walk), and a few fixed metrics. Every line it
returns is untrusted text (an application wrote it): prefixed GRAFANA, it is never a trusted CONFIG line, and it goes
through redaction, the quarantine and the tripwire like CloudWatch's. Times are each source's own, in UTC - Loki and
Tempo in nanoseconds, Prometheus in seconds - never re-stamped; the model is told that two sources' events in the
same minute have no known order. A source that answers nothing says so: "no data" is never health.
"""

from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any

from . import web
from .models import Alert

TIMEOUT_S = 8.0
LOG_LOOKBACK = timedelta(minutes=15)
METRIC_WINDOW = timedelta(minutes=10)
MAX_LOG_LINES = 200
MAX_TRACES = 20
MAX_LINE = 600
PARTIAL = "TOOL-PARTIAL "  # tools.PARTIAL_PREFIX: an unanswered read, never a healthy one
# A service name as the read queries it: copied from the alert, never from a log line (a name in a query is code).
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")
# The fixed metrics, per service: what each means is fixed here, not by the data. Empty answers add nothing.
QUERIES = {
    "grafana_error_rate": ('sum(rate(traces_spanmetrics_calls_total{{service="{s}",status_code="STATUS_CODE_ERROR"}}[5m]))'
                           ' / sum(rate(traces_spanmetrics_calls_total{{service="{s}"}}[5m]))'),
    "grafana_p95_latency_ms": ('1000 * histogram_quantile(0.95, sum by (le) (rate('
                               'traces_spanmetrics_latency_bucket{{service="{s}"}}[5m])))'),
    "grafana_pod_restarts": 'sum(increase(kube_pod_container_status_restarts_total{{container="{s}"}}[15m]))',
}


def configured() -> bool:
    return bool(os.environ.get("WARDEN_GRAFANA_READ_TOKEN", "").strip()) and any(
        os.environ.get(f"WARDEN_GRAFANA_{s}_URL", "").strip() for s in ("LOGS", "TRACES", "METRICS"))


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _alert_time(alert: Alert) -> datetime:
    try:
        t = datetime.fromisoformat(alert.started_at)
    except (ValueError, AttributeError):
        return datetime.now(UTC)
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def services(alert: Alert) -> list[str]:
    """The names to read: the alert's service and the workloads its labels name - nothing from evidence text. A label
    may list several (`deployment: catalog-api,cart-worker`, a team's service map): each is read, up to four names."""
    names = [alert.service] + [part for k in ("deployment", "ecs_service", "lambda")
                               for part in str(alert.labels.get(k) or "").split(",")]
    out: list[str] = []
    for n in names:
        n = n.rsplit("/", 1)[-1].strip()
        if n and _NAME.match(n) and n not in out:
            out.append(n)
    return out[:4]


class GrafanaReader:
    """Reads Loki, Tempo and Prometheus over HTTP with one read-only token (HTTP Basic: each source's own user id and
    the token). `get` is injectable so the tests need no Grafana."""

    source = "grafana"

    def __init__(self, *, env: dict[str, str] | None = None, get: Any = None) -> None:
        env = env if env is not None else dict(os.environ)
        self.token = env.get("WARDEN_GRAFANA_READ_TOKEN", "").strip()
        self.src = {s: (env.get(f"WARDEN_GRAFANA_{s}_URL", "").strip().rstrip("/"),
                        env.get(f"WARDEN_GRAFANA_{s}_USER", "").strip()) for s in ("LOGS", "TRACES", "METRICS")}
        self._get = get or self._http

    def _http(self, url: str, user: str) -> dict:
        auth = base64.b64encode(f"{user}:{self.token}".encode()).decode()
        req = urllib.request.Request(url, headers={"Authorization": f"Basic {auth}", "Accept": "application/json"})
        with web.urlopen(req, timeout=TIMEOUT_S) as resp:
            return json.loads(resp.read() or b"{}")

    def _ask(self, source: str, path: str, params: dict[str, Any]) -> tuple[dict | None, str]:
        base, user = self.src[source]
        if not base or not self.token:
            return None, ""
        if not base.startswith("https://"):
            return None, f"{PARTIAL}grafana {source.lower()}: its address is not https, so it was not read"
        try:
            return self._get(f"{base}{path}?{urllib.parse.urlencode(params)}", user), ""
        except urllib.error.HTTPError as exc:
            return None, f"{PARTIAL}grafana {source.lower()}: HTTP {exc.code} - not read (late, limited or refused)"
        except (OSError, ValueError) as exc:  # URLError and timeouts are OSErrors
            return None, f"{PARTIAL}grafana {source.lower()}: {type(exc).__name__} - not read"

    # ------------------------------------------------------------------ logs

    def logs(self, alert: Alert) -> list[str]:
        at = _alert_time(alert)
        start, end = at - LOG_LOOKBACK, at + LOG_LOOKBACK
        out: list[str] = []
        for svc in services(alert):
            got, problem = self._ask("LOGS", "/loki/api/v1/query_range", {
                "query": f'{{service_name="{svc}"}} |~ "(?i)error|exception|fail|timeout|panic|refused"',
                "start": int(start.timestamp() * 1e9), "end": int(end.timestamp() * 1e9),
                "limit": MAX_LOG_LINES, "direction": "backward"})
            if problem:
                out.append(problem)
                continue
            if got is None:
                continue
            lines = []
            for stream in (got.get("data") or {}).get("result") or []:
                for ns, text in stream.get("values") or []:
                    when = datetime.fromtimestamp(int(ns) / 1e9, UTC)
                    lines.append((when, " ".join(str(text).split())[:MAX_LINE]))
            if not lines:
                out.append(f"{PARTIAL}grafana logs: no error lines for {svc} between {_iso(start)} and {_iso(end)} "
                           "(late, not instrumented, or none) - not a sign of health")
            out += [f"GRAFANA log {svc} {_iso(w)} {t}" for w, t in sorted(lines)[-MAX_LOG_LINES:]]
        return out

    # ------------------------------------------------------------------ traces, and the dependency walk

    def traces(self, alert: Alert) -> list[str]:
        at = _alert_time(alert)
        start, end = at - LOG_LOOKBACK, at + LOG_LOOKBACK
        out: list[str] = []
        for svc in services(alert):
            out += self._traces_of(svc, start, end)
        return out

    def _traces_of(self, svc: str, start: datetime, end: datetime) -> list[str]:
        """One service's failed traces, then the services they fail in."""
        got, problem = self._ask("TRACES", "/api/search", {
            # Traces through the service that failed anywhere - its own spans or downstream - with the names
            # each failed span carries, so the walk can say where (Tempo returns only what `select` asks for).
            "q": (f'{{ resource.service.name = "{svc}" }} && {{ status = error }} | select(resource.service.name, '
                  "span.peer.service, span.db.system, span.server.address)"),
            "start": int(start.timestamp()), "end": int(end.timestamp()), "limit": MAX_TRACES, "spss": 5})
        if problem:
            return [problem]
        if got is None:
            return []
        found = got.get("traces") or []
        if not found:
            return [(f"{PARTIAL}grafana traces: no failed traces for {svc} between {_iso(start)} and "
                     f"{_iso(end)} (late, not instrumented, or none) - not a sign of health")]
        out: list[str] = []
        downstream: dict[str, int] = {}
        for t in found[:MAX_TRACES]:
            when = datetime.fromtimestamp(int(t.get("startTimeUnixNano") or 0) / 1e9, UTC)
            root = " ".join(str(t.get("rootTraceName") or "?").split())[:120]
            failed = _failed_in(t, svc)
            # Once per trace, in span order: a set's order changes with each process's hash seed, and among peers
            # failing equally often the cut to three then kept a different one for the same answer.
            for peer in dict.fromkeys(failed):
                downstream[peer] = downstream.get(peer, 0) + 1
            out.append(f"GRAFANA trace {svc} {_iso(when)} {root} duration_ms={t.get('durationMs', '?')} "
                       f"failed_in={','.join(sorted(set(failed))) or svc}")
        # The dependency walk: which service the failed traces fail in, other than the alert's own - where to
        # look next. A count over what Tempo returned (not a rate: its search is the first N, not all).
        for peer, n in sorted(downstream.items(), key=lambda kv: -kv[1])[:3]:
            out.append(f"GRAFANA dependency {svc} -> {peer}: failing in {n} of {len(found[:MAX_TRACES])} "
                       "failed traces read")
        return out

    # ------------------------------------------------------------------ metrics

    def metrics(self, alert: Alert) -> dict[str, float]:
        at = _alert_time(alert)
        start = (at - METRIC_WINDOW).replace(second=0, microsecond=0)  # minute buckets, as CloudWatch's
        end = at + METRIC_WINDOW
        out: dict[str, float] = {}
        for svc in services(alert)[:1]:
            for name, query in QUERIES.items():
                got, _ = self._ask("METRICS", "/api/v1/query_range", {
                    "query": query.format(s=svc), "start": int(start.timestamp()), "end": int(end.timestamp()),
                    "step": 60})
                values = [float(v) for series in ((got or {}).get("data") or {}).get("result") or []
                          for _, v in series.get("values") or [] if v not in ("NaN", "+Inf", "-Inf")]
                if values:
                    out[name] = round(max(values), 4)
        return out


def _failed_in(trace: dict, svc: str) -> list[str]:
    """The services other than `svc` that a trace's failed spans name, in span order (a name once per span)."""
    failed = []
    for ss in trace.get("spanSets") or ([trace["spanSet"]] if trace.get("spanSet") else []):
        for sp in ss.get("spans") or []:
            peer = _span_peer(sp)
            if peer and peer != svc:
                failed.append(peer[:80])
    return failed


def _span_peer(span: dict) -> str:
    """The first service name a span carries, of the ones Tempo is asked to `select`, or ""."""
    attrs = {a.get("key"): (a.get("value") or {}) for a in span.get("attributes") or []}
    return next((str(v.get("stringValue")) for k, v in attrs.items()
                 if k in ("service.name", "peer.service", "db.system", "server.address")
                 and v.get("stringValue")), "")


class WithSources:
    """An evidence backend with observability tools beside it (Grafana, Datadog): the AWS reads as they are, and each
    tool's logs, traces and metrics added - every line tagged with its source, a failed read of one never failing
    another or the AWS one, an AWS metric never overwritten."""

    def __init__(self, base: Any, readers: list[Any]) -> None:
        self.base, self.readers = base, list(readers)
        self.name = "+".join([getattr(base, "name", "backend"), *(r.source for r in self.readers)])
        self.reads_live_store = getattr(base, "reads_live_store", False)

    def logs(self, alert: Alert) -> list[str]:
        lines = list(self.base.logs(alert))
        for reader in self.readers:
            for read in (reader.logs, reader.traces):
                try:
                    lines += read(alert)
                except Exception as exc:  # noqa: BLE001 - a second source never takes another down
                    lines.append(f"{PARTIAL}{reader.source}: {type(exc).__name__} - not read")
        return lines

    def metrics(self, alert: Alert) -> dict[str, float]:
        out = dict(self.base.metrics(alert))
        for reader in self.readers:
            try:
                out.update({k: v for k, v in reader.metrics(alert).items() if k not in out})
            except Exception:  # noqa: BLE001, S112 - the other sources' metrics stand
                continue
        return out

    def deploys(self, alert: Alert) -> list[dict]:
        return self.base.deploys(alert)

    def __getattr__(self, item: str) -> Any:  # everything else the base backend offers (stack snapshots, readers)
        return getattr(self.base, item)
