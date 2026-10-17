"""Datadog as an evidence source beside AWS and Grafana (owner, 2026-10-14: "do both at once grafana datadog" -
Datadog is the observability tool companies buy most; researched the same day: its full product is a 14-day trial,
read through scoped application keys - logs_read_data, apm_read, timeseries_query - on the account's own site).

What it reads, around the alarm, for the service the alert names: its error logs (Logs Search), its failed spans and
where they fail downstream (Spans Search - the dependency walk), and a few fixed metrics (timeseries query). Every
line it returns is untrusted text: prefixed DATADOG, never a trusted CONFIG line, redacted, quarantined and scanned
like CloudWatch's. Times are Datadog's own, in UTC, never re-stamped. A read that answers nothing says so - "no data"
is never health.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any

from . import web
from .grafana import PARTIAL, _alert_time, _iso, services
from .models import Alert

TIMEOUT_S = 8.0
LOOKBACK = timedelta(minutes=15)
METRIC_WINDOW = timedelta(minutes=10)
MAX_LINES = 200
MAX_SPANS = 50
MAX_LINE = 600
# The sites Datadog runs (docs.datadoghq.com/getting_started/site, read 2026-10-14): the API host is api.<site>.
SITES = frozenset({"datadoghq.com", "us3.datadoghq.com", "us5.datadoghq.com", "datadoghq.eu", "ap1.datadoghq.com",
                   "ap2.datadoghq.com", "uk1.datadoghq.com", "ddog-gov.com", "us2.ddog-gov.com"})
QUERIES = {
    "datadog_error_rate": ("sum:trace.http.request.errors{{service:{s}}}.as_rate() / "
                           "sum:trace.http.request.hits{{service:{s}}}.as_rate()"),
    "datadog_p95_latency_ms": "p95:trace.http.request{{service:{s}}} * 1000",
    "datadog_pod_restarts": "sum:kubernetes_state.container.restarts{{kube_container_name:{s}}}",
}
_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,126}$")


def configured() -> bool:
    return all(os.environ.get(n, "").strip() for n in ("WARDEN_DATADOG_SITE", "WARDEN_DATADOG_API_KEY",
                                                       "WARDEN_DATADOG_APP_KEY"))


class DatadogReader:
    """Datadog's read APIs with an API key and a scoped application key, on the account's own site. `call` is
    injectable so the tests need no Datadog."""

    source = "datadog"

    def __init__(self, *, env: dict[str, str] | None = None, call: Any = None) -> None:
        env = env if env is not None else dict(os.environ)
        self.site = env.get("WARDEN_DATADOG_SITE", "").strip().lower()
        self.keys = (env.get("WARDEN_DATADOG_API_KEY", "").strip(), env.get("WARDEN_DATADOG_APP_KEY", "").strip())
        self._call = call or self._http

    def _http(self, method: str, url: str, body: dict | None) -> dict:
        req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body else None, headers={
            "DD-API-KEY": self.keys[0], "DD-APPLICATION-KEY": self.keys[1], "Content-Type": "application/json",
            "Accept": "application/json"})
        with web.urlopen(req, timeout=TIMEOUT_S) as resp:
            return json.loads(resp.read() or b"{}")

    def _ask(self, what: str, method: str, path: str, body: dict | None = None,
             query: dict | None = None) -> tuple[dict | None, str]:
        if not all(self.keys):
            return None, ""
        if self.site not in SITES:
            return None, f"{PARTIAL}datadog {what}: its site is not one of Datadog's, so it was not read"
        url = f"https://api.{self.site}{path}" + (f"?{urllib.parse.urlencode(query)}" if query else "")
        try:
            return self._call(method, url, body), ""
        except urllib.error.HTTPError as exc:
            return None, f"{PARTIAL}datadog {what}: HTTP {exc.code} - not read (late, limited or refused)"
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            return None, f"{PARTIAL}datadog {what}: {type(exc).__name__} - not read"

    def logs(self, alert: Alert) -> list[str]:
        at = _alert_time(alert)
        start, end = at - LOOKBACK, at + LOOKBACK
        out: list[str] = []
        for svc in services(alert):
            got, problem = self._ask("logs", "POST", "/api/v2/logs/events/search", {
                "filter": {"query": f"service:{svc} status:(error OR critical OR emergency)",
                           "from": _iso(start), "to": _iso(end)},
                "sort": "-timestamp", "page": {"limit": MAX_LINES}})
            if problem:
                out.append(problem)
                continue
            if got is None:
                continue
            lines = []
            for e in got.get("data") or []:
                a = e.get("attributes") or {}
                when = _when(a.get("timestamp"))
                if when:
                    lines.append((when, " ".join(str(a.get("message") or "").split())[:MAX_LINE]))
            if not lines:
                out.append(f"{PARTIAL}datadog logs: no error lines for {svc} between {_iso(start)} and {_iso(end)} "
                           "(late, not instrumented, or none) - not a sign of health")
            out += [f"DATADOG log {svc} {_iso(w)} {t}" for w, t in sorted(lines)]
        return out

    def traces(self, alert: Alert) -> list[str]:
        at = _alert_time(alert)
        start, end = at - LOOKBACK, at + LOOKBACK
        out: list[str] = []
        for svc in services(alert):
            got, problem = self._ask("traces", "POST", "/api/v2/spans/events/search", {"data": {"type": "search_request",
                "attributes": {"filter": {"query": f"service:{svc} status:error", "from": _iso(start),
                                          "to": _iso(end)}, "sort": "-timestamp", "page": {"limit": MAX_SPANS}}}})
            if problem:
                out.append(problem)
                continue
            if got is None:
                continue
            spans = got.get("data") or []
            if not spans:
                out.append(f"{PARTIAL}datadog traces: no failed spans for {svc} between {_iso(start)} and {_iso(end)}"
                           " (late, not instrumented, or none) - not a sign of health")
                continue
            downstream: dict[str, int] = {}
            for sp in spans[:MAX_SPANS]:
                a = sp.get("attributes") or {}
                tags = a.get("custom") or {}
                peer = str((tags.get("peer") or {}).get("service") or tags.get("peer.service")
                           or (tags.get("db") or {}).get("system") or "")[:80]
                when = _when(a.get("start_timestamp") or a.get("timestamp"))
                out.append(f"DATADOG span {svc} {_iso(when) if when else '?'} "
                           f"{' '.join(str(a.get('resource_name') or '?').split())[:120]} "
                           f"duration_ms={round(float(a.get('duration') or 0) / 1e6, 1)} failed_in={peer or svc}")
                if peer and peer != svc:
                    downstream[peer] = downstream.get(peer, 0) + 1
            for peer, n in sorted(downstream.items(), key=lambda kv: -kv[1])[:3]:
                out.append(f"DATADOG dependency {svc} -> {peer}: failing in {n} of {len(spans[:MAX_SPANS])} "
                           "failed spans read")
        return out

    def metrics(self, alert: Alert) -> dict[str, float]:
        at = _alert_time(alert)
        start, end = (at - METRIC_WINDOW).replace(second=0, microsecond=0), at + METRIC_WINDOW
        out: dict[str, float] = {}
        for svc in [s for s in services(alert) if _TAG.match(s)]:  # the first named workload Datadog has numbers for
            if out:
                break
            for name, query in QUERIES.items():
                got, _ = self._ask("metrics", "GET", "/api/v1/query", query={
                    "from": int(start.timestamp()), "to": int(end.timestamp()), "query": query.format(s=svc)})
                values = [float(v) for series in (got or {}).get("series") or []
                          for _, v in series.get("pointlist") or [] if v is not None]
                if values:
                    out[name] = round(max(values), 4)
        return out


def _when(value: Any) -> datetime | None:
    """A Datadog timestamp - ISO-8601 or epoch milliseconds - as UTC."""
    if value is None:
        return None
    try:
        if isinstance(value, int | float):
            return datetime.fromtimestamp(float(value) / 1000, UTC)
        t = datetime.fromisoformat(str(value))
        return t if t.tzinfo else t.replace(tzinfo=UTC)
    except (ValueError, OSError):
        return None
