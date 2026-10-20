"""Success means the symptom is gone (B13), not only that the alarm left ALARM.

An alarm leaves ALARM for many reasons that are not a recovery: its metric stopped reporting, it went to
INSUFFICIENT_DATA, the evaluation window moved past one bad minute. And a fix can trade one failure for another: the
throttling stops and a new exception starts. So, after a fix, WARDEN reads the incident's own alarm itself:

- **The metric is no worse for N periods.** The alarm's own metric, statistic and period (a CloudWatch metric alarm;
  a Datadog metric monitor's query and evaluation window), read from the moment the fix was applied: every one of the
  last N complete periods must be on the healthy side of the alarm's own threshold. A breach in any period since the
  fix is "present"; fewer than N periods with none breaching is "unknown"; N clean periods is "gone".
- **No new error class.** The error classes (`SomethingError`, `SomethingException`, ...) in the service's error logs
  after the fix, against the same span of logs before it: a class seen only after the fix is "present".

Deterministic: the same reads give the same answer, from fixed rules - no model is asked. N is WARDEN_SYMPTOM_PERIODS
(default 3). The reading, its N and its numbers are recorded on the check's audit row. "unknown" never fails a fix by
itself - a good fix is never rolled back for want of a reading - but "present" does; the re-checks after a verified
fix (15 and 60 minutes, register C18a) read again, by when N periods exist.
"""

from __future__ import annotations

import math
import operator
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .grafana import _iso
from .read_errors import READ_ERRORS

DEFAULT_PERIODS = 3
MAX_PERIODS = 20
LOG_GROUPS = 2
MAX_LOG_EVENTS = 200
MAX_LOG_PAGES = 5  # read to the end of a window, or the log comparison is unknown - never clean, never new
MAX_CLASSES = 10
BEFORE = timedelta(minutes=15)  # error logs before the fix are read from this long before the alarm
ERROR_PATTERN = "?Error ?Exception ?ERROR ?Fault ?Timeout"

GONE, PRESENT, UNKNOWN = "gone", "present", "unknown"

# CloudWatch's comparison operators and a Datadog monitor's, as the test "this value is bad". An anomaly band
# (LessThanLowerOrGreaterThanUpperThreshold) has no single threshold: not compared.
_BAD: dict[str, Callable[[float, float], bool]] = {
    "GreaterThanThreshold": operator.gt, "GreaterThanOrEqualToThreshold": operator.ge,
    "LessThanThreshold": operator.lt, "LessThanOrEqualToThreshold": operator.le,
    ">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le,
}
# An error class as code names it: a word ending in Error, Exception, Fault or Timeout, not part of a longer name.
# A module path before it (`botocore.exceptions.ClientError`) is the same class as the bare name.
_CLASS = re.compile(r"(?<!\w)([A-Z][A-Za-z0-9]{1,60}(?:Error|Exception|Fault|Timeout))\b")
# A Datadog metric monitor: `<agg>(last_<n><unit>):<metric query> <comparator> <threshold>` (docs.datadoghq.com,
# "Metric monitor" query syntax). Only the four aggregations whose meaning over a window is plain are compared.
_DD_QUERY = re.compile(r"^(avg|sum|min|max)\(last_(\d{1,4})([mhd])\):(.{1,1000}?)\s*(>=|<=|>|<)\s*(-?\d+(?:\.\d+)?)$")
_DD_UNIT = {"m": 60, "h": 3600, "d": 86400}
_DD_AGG: dict[str, Callable[[list[float]], float]] = {"avg": lambda v: sum(v) / len(v), "sum": sum, "min": min,
                                                     "max": max}




def now() -> datetime:
    """The time a check reads up to (one place, so a test can move it)."""
    return datetime.now(UTC)


def periods() -> int:
    """N: WARDEN_SYMPTOM_PERIODS, a whole number from 1 to MAX_PERIODS; anything else is the default."""
    raw = os.environ.get("WARDEN_SYMPTOM_PERIODS", "").strip()
    n = int(raw) if raw.isdigit() else DEFAULT_PERIODS
    return n if 1 <= n <= MAX_PERIODS else DEFAULT_PERIODS


@dataclass
class Reading:
    """What the symptom check found, as the audit records it."""

    source: str
    state: str = UNKNOWN
    why: str = ""
    periods: int = DEFAULT_PERIODS
    values: list[float] = field(default_factory=list)
    new_errors: list[str] = field(default_factory=list)
    errors_read: bool = False

    def row(self) -> dict[str, Any]:
        return {"source": self.source, "state": self.state, "why": self.why[:300], "periods": self.periods,
                "values": [round(v, 6) for v in self.values[-self.periods:]], "new_errors": self.new_errors,
                "errors_read": self.errors_read}


def judge(values: list[float], comparison: str, threshold: float, n: int) -> tuple[str, str]:
    """The metric's verdict from the values of the complete periods since the fix, oldest first."""
    bad = _BAD.get(comparison)
    if bad is None:
        return UNKNOWN, f"the alarm compares with {comparison or 'no threshold'}: no single threshold to judge"
    if not values:
        return UNKNOWN, f"no complete period since the fix (0 of {n})"
    breached = [v for v in values if bad(v, threshold)]
    if breached:
        return PRESENT, (f"{len(breached)} of {len(values)} periods since the fix still breach {comparison} "
                         f"{threshold:g} (latest {values[-1]:g})")
    if len(values) < n:
        return UNKNOWN, f"{len(values)} of {n} periods since the fix, none breaching"
    return GONE, f"the last {n} periods are all within {comparison} {threshold:g}"


def error_classes(lines: list[str]) -> set[str]:
    return {m.group(1)[:120] for line in lines for m in _CLASS.finditer(line)}


def new_classes(before: list[str], after: list[str]) -> list[str]:
    """The error classes seen after the fix and not in the same span of logs before it."""
    return sorted(error_classes(after) - error_classes(before))[:MAX_CLASSES]


def combine(reading: Reading, before: list[str] | None, after: list[str] | None) -> Reading:
    """Add the error-class check to a metric reading. A new class makes the symptom present whatever the metric says;
    logs that could not be read leave the metric's verdict as it is."""
    if before is None or after is None:
        reading.why += "; error logs not read"
        return reading
    reading.errors_read = True
    reading.new_errors = new_classes(before, after)
    if reading.new_errors:
        reading.state = PRESENT
        reading.why += f"; new error class since the fix: {', '.join(reading.new_errors)}"
    return reading


def before_start(alert_at: datetime, applied: datetime, now: datetime) -> datetime:
    """Where the logs before the fix start: BEFORE ahead of the alarm (or of the fix, if that came first), so every
    class the incident itself showed is known before the fix - and not called new after it - and never a shorter span
    than the one read after the fix (an error that comes once an hour is not new at the 60-minute re-check)."""
    return min(min(alert_at, applied) - BEFORE, applied - (now - applied))


def _ms(t: datetime) -> int:
    return int(t.timestamp() * 1000)


def _aligned(t: datetime, period: int) -> datetime:
    """The first period boundary at or after `t`: a period that began before the fix is not judged."""
    s = math.ceil(t.timestamp() / period) * period
    return datetime.fromtimestamp(s, UTC)


# --------------------------------------------------------------------------- CloudWatch


def log_groups(labels: dict[str, Any]) -> list[str]:
    """The error logs to compare: the alarm's own log group, else a Lambda function's - from the incident's labels."""
    found = [str(labels["log_group"])] if labels.get("log_group") else []
    if labels.get("lambda"):
        found.append(f"/aws/lambda/{labels['lambda']}")
    return found[:LOG_GROUPS]


def cloudwatch_metric(cw: Any, alarm: str, applied: datetime, now: datetime, n: int) -> Reading:
    """The CloudWatch metric alarm's own metric, statistic and period since the fix, judged against its threshold."""
    reading = Reading(source="cloudwatch", periods=n)
    found = (cw.describe_alarms(AlarmNames=[alarm], AlarmTypes=["MetricAlarm"]).get("MetricAlarms") or [])
    a = found[0] if found else {}
    stat = a.get("Statistic") or a.get("ExtendedStatistic")
    period = int(a.get("Period") or 0)
    if not a.get("MetricName") or not stat or period <= 0:
        reading.why = "not a single-metric alarm (a metric-math or composite alarm, or not found)"
        return reading
    start, end = _aligned(applied, period), now
    values: list[float] = []
    if end - start >= timedelta(seconds=period):
        got = cw.get_metric_data(MetricDataQueries=[{"Id": "m", "ReturnData": True, "MetricStat": {
            "Metric": {"Namespace": a.get("Namespace"), "MetricName": a["MetricName"],
                       "Dimensions": a.get("Dimensions") or []}, "Period": period, "Stat": stat}}],
            StartTime=start, EndTime=end, ScanBy="TimestampAscending")
        result = (got.get("MetricDataResults") or [{}])[0]
        stamps = result.get("Timestamps") or []
        # Only periods that are over: the one still running would be judged on part of its data.
        values = [float(v) for t, v in zip(stamps, result.get("Values") or [], strict=False)
                  if t + timedelta(seconds=period) <= end]
    reading.values = values
    reading.state, reading.why = judge(values, str(a.get("ComparisonOperator") or ""),
                                       float(a.get("Threshold") or 0.0), n)
    return reading


def cloudwatch_errors(logs: Any, groups: list[str], start: datetime, end: datetime) -> list[str] | None:
    """The error lines of `groups` between start and end; None when any could not be read (unknown, never clean)."""
    lines: list[str] = []
    for group in groups:
        read = _group_errors(logs, group, start, end)
        if read is None:
            return None
        lines += read
    return lines


def _group_errors(logs: Any, group: str, start: datetime, end: datetime) -> list[str] | None:
    """One log group's error lines in the window, every page up to MAX_LOG_PAGES; None if it could not be read to
    the end (a page can come back empty with more to read)."""
    lines: list[str] = []
    token = ""
    for _ in range(MAX_LOG_PAGES):
        try:
            got = logs.filter_log_events(logGroupName=group, startTime=_ms(start), endTime=_ms(end),
                                         filterPattern=ERROR_PATTERN, limit=MAX_LOG_EVENTS,
                                         **({"nextToken": token} if token else {}))
        except READ_ERRORS:  # an unread log is unknown, never clean
            return None
        lines += [str(e.get("message") or "") for e in got.get("events") or []]
        token = str(got.get("nextToken") or "")
        if not token:
            return lines
    return None


def cloudwatch(read: Callable[[str], Any], alarm: str, labels: dict[str, Any], *, alert_at: datetime,
               applied: datetime, now: datetime, n: int) -> Reading:
    """The symptom of a CloudWatch alarm's incident, read through `read` (name -> boto3 client, the reader role)."""
    reading = cloudwatch_metric(read("cloudwatch"), alarm, applied, now, n)
    groups = log_groups(labels)
    if not groups:
        reading.why += "; no log group named"
        return reading
    logs = read("logs")
    before = cloudwatch_errors(logs, groups, before_start(alert_at, applied, now), applied)
    after = cloudwatch_errors(logs, groups, applied, now)
    return combine(reading, before, after)


# --------------------------------------------------------------------------- Datadog


def windows(points: list[tuple[float, float]], start: datetime, end: datetime, width: int,
            agg: Callable[[list[float]], float]) -> list[float]:
    """Each complete `width`-second window from `start`, aggregated as the monitor aggregates; empty windows skipped."""
    out: list[float] = []
    t = start.timestamp()
    while t + width <= end.timestamp():
        inside = [v for ts, v in points if t <= ts / 1000 < t + width]
        if inside:
            out.append(agg(inside))
        t += width
    return out


def datadog(ask: Callable[..., tuple[dict | None, str]], monitor: str, service: str, *, alert_at: datetime,
            applied: datetime, now: datetime, n: int) -> Reading:
    """The symptom of a Datadog monitor's incident. `ask(what, method, path, body=None, query=None)` is
    DatadogReader._ask: (answer, problem)."""
    reading = Reading(source="datadog", periods=n)
    got, problem = ask("monitor", "GET", f"/api/v1/monitor/{monitor}")
    if got is None:
        reading.why = problem or "the monitor was not read"
        return reading
    state = str(got.get("overall_state") or "")
    m = _DD_QUERY.match(str(got.get("query") or "").strip())
    # The monitor's own state can lag its window - an Alert that has not re-evaluated since the fix - and No Data is no
    # evidence either way: its metric over whole windows since the fix decides, as for a CloudWatch alarm.
    if m is not None:
        reading = _datadog_metric(ask, m, reading, applied, now, n)
    else:
        reading.why = f"the monitor is {state or 'unknown'}; its query is not a metric query WARDEN compares"
    before = _datadog_errors(ask, service, before_start(alert_at, applied, now), applied)
    after = _datadog_errors(ask, service, applied, now)
    return combine(reading, before, after)


def _datadog_metric(ask: Callable[..., tuple[dict | None, str]], m: re.Match, reading: Reading, applied: datetime,
                    now: datetime, n: int) -> Reading:
    agg, count, unit, query, comparison, threshold = m.groups()
    width = int(count) * _DD_UNIT[unit]
    got, problem = ask("metrics", "GET", "/api/v1/query",
                       query={"from": int(applied.timestamp()), "to": int(now.timestamp()), "query": query})
    if got is None:
        reading.why = problem or "the monitor's metric was not read"
        return reading
    points = [(float(ts), float(v)) for s in got.get("series") or [] for ts, v in s.get("pointlist") or []
              if v is not None]
    reading.values = windows(points, applied, now, width, _DD_AGG[agg])
    reading.state, reading.why = judge(reading.values, comparison, float(threshold), n)
    return reading


def _datadog_errors(ask: Callable[..., tuple[dict | None, str]], service: str, start: datetime,
                    end: datetime) -> list[str] | None:
    """The service's error log lines in the window, every page up to MAX_LOG_PAGES; None if unread or not read to the
    end."""
    if not service or service == "unknown":
        return None
    lines: list[str] = []
    cursor = ""
    for _ in range(MAX_LOG_PAGES):
        page = _datadog_page(ask, service, start, end, cursor)
        if page is None:
            return None
        lines += page[0]
        cursor = page[1]
        if not cursor:
            return lines
    return None


def _datadog_page(ask: Callable[..., tuple[dict | None, str]], service: str, start: datetime, end: datetime,
                  cursor: str) -> tuple[list[str], str] | None:
    """One page of the service's error logs and the cursor to the next ("" at the end); None if it was not read."""
    body = {"filter": {"query": f"service:{service} status:(error OR critical OR emergency)", "from": _iso(start),
                       "to": _iso(end)}, "sort": "timestamp",
            "page": {"limit": MAX_LOG_EVENTS, **({"cursor": cursor} if cursor else {})}}
    try:
        got, _ = ask("logs", "POST", "/api/v2/logs/events/search", body)
        if got is None:
            return None
        lines = [str((e.get("attributes") or {}).get("message") or "") for e in got.get("data") or []]
        return lines, str(((got.get("meta") or {}).get("page") or {}).get("after") or "")
    except READ_ERRORS:  # a malformed answer is an unread log: the metric's verdict stands
        return None
