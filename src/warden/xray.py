"""AWS X-Ray as an evidence source for what AWS's own reads miss: the apps' request-level traces, sent with
OpenTelemetry to X-Ray, read here, and compared live with Datadog's and Grafana's.

For the service the alert names, around the alarm: the traces that failed (errors and faults), each with its URL,
status and time, and X-Ray's own root cause of each fault - the downstream service it fails in (the dependency walk,
from AWS's analysis, not WARDEN's guess). Read in the incident's environment's reader role (xray:GetTraceSummaries);
every line untrusted (XRAY ...), X-Ray's own times in UTC, "no traces" never health.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

from .grafana import PARTIAL, _alert_time, _iso, services
from .models import Alert

LOOKBACK = timedelta(minutes=15)
MAX_TRACES = 25
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")


class XRayReader:
    """Failed traces for the alert's services. `client` makes the X-Ray client for an alert - in the runtime, the one
    over the incident's environment's reader role (the stack backend's)."""

    source = "xray"

    def __init__(self, client: Any) -> None:
        self._client = client

    def logs(self, alert: Alert) -> list[str]:
        """The evidence-source contract's logs view. X-Ray holds traces: the logs for the alert are CloudWatch's, read
        by the AWS backend, so none come from here."""
        return []  # X-Ray holds traces; the logs are CloudWatch's, read by the AWS backend

    def metrics(self, alert: Alert) -> dict[str, float]:
        """The evidence-source contract's metrics view. X-Ray holds traces: the metrics for the alert are CloudWatch's,
        so none come from here."""
        return {}

    def traces(self, alert: Alert) -> list[str]:
        at = _alert_time(alert)
        start, end = at - LOOKBACK, at + LOOKBACK
        out: list[str] = []
        try:
            xray = self._client(alert)
        except Exception as exc:  # noqa: BLE001 - no client is a read that did not happen; never health
            return [f"{PARTIAL}xray: {type(exc).__name__} - not read"]
        for svc in [s for s in services(alert) if _NAME.match(s)]:
            out += _traces_of(xray, svc, start, end)
        return out


def _traces_of(xray: Any, svc: str, start: datetime, end: datetime) -> list[str]:
    """One service's failed traces, then the services X-Ray names as their root cause."""
    try:
        got = xray.get_trace_summaries(StartTime=start, EndTime=end, Sampling=False,
                                       FilterExpression=f'service("{svc}") {{ error = true OR fault = true }}')
    except Exception as exc:  # noqa: BLE001  # a failed read is said as not read and never as health
        return [f"{PARTIAL}xray traces: {type(exc).__name__} - not read"]
    found = (got.get("TraceSummaries") or [])[:MAX_TRACES]
    if not found:
        return [(f"{PARTIAL}xray traces: no failed traces for {svc} between {_iso(start)} and {_iso(end)} "
                 "(late, not instrumented, or none) - not a sign of health")]
    out: list[str] = []
    roots: dict[str, int] = {}
    for t in found:
        causes = sorted({str(s.get("Name"))[:80] for rc in (t.get("FaultRootCauses") or [])
                         + (t.get("ErrorRootCauses") or []) for s in rc.get("Services") or [] if s.get("Name")})
        out.append(_trace_line(svc, t, causes))
        for c in causes:
            if c != svc:
                roots[c] = roots.get(c, 0) + 1
    for name, n in sorted(roots.items(), key=lambda kv: -kv[1])[:3]:
        out.append(f"XRAY dependency {svc} -> {name}: X-Ray's root cause in {n} of {len(found)} failed traces read")
    return out


def _trace_line(svc: str, t: dict, causes: list[str]) -> str:
    http = t.get("Http") or {}
    when = t.get("StartTime")
    return (f"XRAY trace {svc} {_iso(when) if when else '?'} "
            f"{http.get('HttpMethod') or ''!s} {str(http.get('HttpURL') or '?')[:160]} "
            f"status={http.get('HttpStatus', '?')} duration_ms={round(float(t.get('Duration') or 0) * 1000)} "
            f"root_cause={','.join(causes) or svc}")
