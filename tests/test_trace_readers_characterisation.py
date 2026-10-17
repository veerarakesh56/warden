"""Characterisation of the three trace readers' `traces` (Grafana Tempo, Datadog spans, AWS X-Ray), written BEFORE their
cognitive-complexity refactor (Sonar python:S3776) and passing on the code as it was: every line, its order, and the
reads made must stay the same."""
import urllib.error
from datetime import UTC, datetime

from warden import datadog, grafana
from warden.models import Alert, Severity
from warden.xray import XRayReader

AT = datetime(2026, 10, 17, 12, 0, tzinfo=UTC)
ENV = {"WARDEN_GRAFANA_READ_TOKEN": "t", "WARDEN_GRAFANA_TRACES_URL": "https://traces.example.test",
       "WARDEN_GRAFANA_TRACES_USER": "1"}
DD_ENV = {"WARDEN_DATADOG_SITE": "datadoghq.eu", "WARDEN_DATADOG_API_KEY": "a", "WARDEN_DATADOG_APP_KEY": "b"}


def alert(**labels):
    return Alert(alert_id="c-1", name="HighErrors", severity=Severity.high, service="checkout", environment="dev",
                 summary="errors", started_at=AT.isoformat(), labels=labels)


def ns(sec):
    return str(int((AT.timestamp() + sec) * 1e9))


def attr(k, v):
    return {"key": k, "value": {"stringValue": v}}


GRAFANA_TRACES = {"traces": [
    {"startTimeUnixNano": ns(-60), "rootTraceName": "GET  /pay\nnow", "durationMs": 120,
     "spanSets": [{"spans": [{"attributes": [attr("service.name", "payments"), attr("db.system", "postgres")]},
                             {"attributes": [attr("peer.service", "checkout")]}]},
                  {"spans": [{"attributes": [attr("server.address", "redis.internal")]},
                             {"attributes": [{"key": "service.name", "value": {}}, attr("peer.service", "payments")]}]}]},
    {"startTimeUnixNano": ns(-30), "spanSet": {"spans": [{"attributes": [attr("db.system", "postgres")]}]}},
    {"rootTraceName": "x", "durationMs": 5, "spanSets": [{"spans": [{"attributes": None}]}]},
    {"startTimeUnixNano": ns(-10), "spanSets": [], "spanSet": {"spans": [{"attributes": [attr("x", "y")]}]}},
]}


class GFake:
    def __init__(self, by_service):
        self.by_service, self.urls = by_service, []

    def __call__(self, url, user):
        self.urls.append(url)
        for svc, answer in self.by_service.items():
            if f"%22{svc}%22" in url:
                if isinstance(answer, BaseException):
                    raise answer
                return answer
        return {}


DD_SPANS = {"data": [
    {"attributes": {"start_timestamp": (AT.timestamp() - 60) * 1000, "resource_name": "GET  /pay\n", "duration": 1.5e8,
                    "custom": {"peer": {"service": "payments"}}}},
    {"attributes": {"timestamp": AT.isoformat(), "duration": 2e6, "custom": {"peer.service": "checkout"}}},
    {"attributes": {"custom": {"db": {"system": "postgres"}}}},
    {"attributes": {"timestamp": "not a time", "custom": {"peer": {}, "peer.service": "payments"}}},
    {},
]}


class DFake:
    def __init__(self, by_service):
        self.by_service, self.bodies = by_service, []

    def __call__(self, method, url, body):
        self.bodies.append(body)
        q = body["data"]["attributes"]["filter"]["query"]
        for svc, answer in self.by_service.items():
            if q.startswith(f"service:{svc} "):
                if isinstance(answer, BaseException):
                    raise answer
                return answer
        return {}


XRAY = {"TraceSummaries": [
    {"Http": {"HttpMethod": "GET", "HttpURL": "https://shop/pay", "HttpStatus": 502}, "StartTime": AT,
     "Duration": 0.25, "FaultRootCauses": [{"Services": [{"Name": "payments"}, {"Name": "checkout"}]}],
     "ErrorRootCauses": [{"Services": [{"Name": "db"}, {"Name": None}]}]},
    {"StartTime": None, "Duration": None, "FaultRootCauses": [{"Services": [{"Name": "payments"}]}]},
    {},
]}


class XFake:
    def __init__(self, by_service):
        self.by_service, self.calls = by_service, []

    def get_trace_summaries(self, **kw):
        self.calls.append(kw)
        for svc, answer in self.by_service.items():
            if f'service("{svc}")' in kw["FilterExpression"]:
                if isinstance(answer, BaseException):
                    raise answer
                return answer
        return {}


def _two():
    return alert(deployment="cart,payments")


def test_grafana_traces_lines_in_order():
    g = GFake({"checkout": GRAFANA_TRACES, "cart": {"traces": []},
               "payments": urllib.error.HTTPError("u", 429, "slow", {}, None)})
    lines = grafana.GrafanaReader(env=ENV, get=g).traces(_two())
    assert lines[:4] == [
        "GRAFANA trace checkout 2026-10-17T11:59:00.000Z GET /pay now duration_ms=120 failed_in=payments,redis.internal",
        "GRAFANA trace checkout 2026-10-17T11:59:30.000Z ? duration_ms=? failed_in=postgres",
        "GRAFANA trace checkout 1970-01-01T00:00:00.000Z x duration_ms=5 failed_in=checkout",
        "GRAFANA trace checkout 2026-10-17T11:59:50.000Z ? duration_ms=? failed_in=checkout"]
    # Three dependencies each failing once: their order among equals follows a set's, so compared as a set.
    assert set(lines[4:7]) == {f"GRAFANA dependency checkout -> {p}: failing in 1 of 4 failed traces read"
                               for p in ("redis.internal", "payments", "postgres")}
    assert lines[7:] == [
        ("TOOL-PARTIAL grafana traces: no failed traces for cart between 2026-10-17T11:45:00.000Z and "
         "2026-10-17T12:15:00.000Z (late, not instrumented, or none) - not a sign of health"),
        "TOOL-PARTIAL grafana traces: HTTP 429 - not read (late, limited or refused)"]
    assert len(g.urls) == 3


def test_grafana_traces_rank_dependencies_by_count_and_keep_three():
    def trace(*peers):
        return {"spanSets": [{"spans": [{"attributes": [attr("peer.service", p)]} for p in peers]}]}

    found = [trace("a", "b", "c", "d"), trace("b", "c", "d"), trace("c", "d", "d"), trace("d")]
    lines = grafana.GrafanaReader(env=ENV, get=GFake({"checkout": {"traces": found}})).traces(alert())
    assert lines[4:] == [f"GRAFANA dependency checkout -> {p}: failing in {n} of 4 failed traces read"
                         for p, n in (("d", 4), ("c", 3), ("b", 2))]
    assert lines[2].endswith("failed_in=c,d"), "a peer failing twice in one trace counts once"


def test_grafana_traces_are_capped(monkeypatch):
    monkeypatch.setattr(grafana, "MAX_TRACES", 2)
    lines = grafana.GrafanaReader(env=ENV, get=GFake({"checkout": GRAFANA_TRACES})).traces(alert())
    assert [ln.split()[1] for ln in lines] == ["trace", "trace", "dependency", "dependency", "dependency"]
    assert lines[-1].endswith("of 2 failed traces read")


def test_grafana_traces_unconfigured_or_unanswered_read_nothing():
    g = GFake({"checkout": GRAFANA_TRACES})
    assert grafana.GrafanaReader(env={}, get=g).traces(_two()) == [] and g.urls == []
    assert grafana.GrafanaReader(env=ENV, get=GFake({})).traces(alert()) == [
        ("TOOL-PARTIAL grafana traces: no failed traces for checkout between 2026-10-17T11:45:00.000Z and "
         "2026-10-17T12:15:00.000Z (late, not instrumented, or none) - not a sign of health")]


def test_datadog_traces_lines_in_order():
    d = DFake({"checkout": DD_SPANS, "cart": {"data": []}, "payments": TimeoutError()})
    assert datadog.DatadogReader(env=DD_ENV, call=d).traces(_two()) == [
        "DATADOG span checkout 2026-10-17T11:59:00.000Z GET /pay duration_ms=150.0 failed_in=payments",
        "DATADOG span checkout 2026-10-17T12:00:00.000Z ? duration_ms=2.0 failed_in=checkout",
        "DATADOG span checkout ? ? duration_ms=0.0 failed_in=postgres",
        "DATADOG span checkout ? ? duration_ms=0.0 failed_in=payments",
        "DATADOG span checkout ? ? duration_ms=0.0 failed_in=checkout",
        "DATADOG dependency checkout -> payments: failing in 2 of 5 failed spans read",
        "DATADOG dependency checkout -> postgres: failing in 1 of 5 failed spans read",
        ("TOOL-PARTIAL datadog traces: no failed spans for cart between 2026-10-17T11:45:00.000Z and "
         "2026-10-17T12:15:00.000Z (late, not instrumented, or none) - not a sign of health"),
        "TOOL-PARTIAL datadog traces: TimeoutError - not read"]
    assert [b["data"]["attributes"]["filter"]["query"] for b in d.bodies] == [
        "service:checkout status:error", "service:cart status:error", "service:payments status:error"]


def test_datadog_traces_are_capped_and_keep_three_dependencies(monkeypatch):
    monkeypatch.setattr(datadog, "MAX_SPANS", 6)
    spans = [{"attributes": {"custom": {"peer.service": p}}} for p in "aabbbcccdddd"]
    lines = datadog.DatadogReader(env=DD_ENV, call=DFake({"checkout": {"data": spans}})).traces(alert())
    assert len(lines) == 6 + 3
    assert lines[6:] == ["DATADOG dependency checkout -> b: failing in 3 of 6 failed spans read",
                         "DATADOG dependency checkout -> a: failing in 2 of 6 failed spans read",
                         "DATADOG dependency checkout -> c: failing in 1 of 6 failed spans read"]


def test_datadog_traces_without_keys_read_nothing():
    d = DFake({"checkout": DD_SPANS})
    assert datadog.DatadogReader(env={}, call=d).traces(_two()) == [] and d.bodies == []


def test_xray_traces_lines_in_order():
    x = XFake({"checkout": XRAY, "cart": {"TraceSummaries": []}, "payments": RuntimeError("x")})
    assert XRayReader(lambda a: x).traces(_two()) == [
        ("XRAY trace checkout 2026-10-17T12:00:00.000Z GET https://shop/pay status=502 duration_ms=250 "
         "root_cause=checkout,db,payments"),
        "XRAY trace checkout ?  ? status=? duration_ms=0 root_cause=payments",
        "XRAY trace checkout ?  ? status=? duration_ms=0 root_cause=checkout",
        "XRAY dependency checkout -> payments: X-Ray's root cause in 2 of 3 failed traces read",
        "XRAY dependency checkout -> db: X-Ray's root cause in 1 of 3 failed traces read",
        ("TOOL-PARTIAL xray traces: no failed traces for cart between 2026-10-17T11:45:00.000Z and "
         "2026-10-17T12:15:00.000Z (late, not instrumented, or none) - not a sign of health"),
        "TOOL-PARTIAL xray traces: RuntimeError - not read"]
    assert [c["FilterExpression"] for c in x.calls] == [
        f'service("{s}") {{ error = true OR fault = true }}' for s in ("checkout", "cart", "payments")]
    assert {(c["StartTime"], c["EndTime"], c["Sampling"]) for c in x.calls} == {
        (datetime(2026, 10, 17, 11, 45, tzinfo=UTC), datetime(2026, 10, 17, 12, 15, tzinfo=UTC), False)}


def test_xray_traces_are_capped_and_keep_three_dependencies(monkeypatch):
    from warden import xray

    monkeypatch.setattr(xray, "MAX_TRACES", 5)
    found = [{"FaultRootCauses": [{"Services": [{"Name": n}]}]} for n in "aabbbcccdddd"]
    lines = XRayReader(lambda a: XFake({"checkout": {"TraceSummaries": found}})).traces(alert())
    assert len(lines) == 5 + 2
    assert lines[5:] == ["XRAY dependency checkout -> b: X-Ray's root cause in 3 of 5 failed traces read",
                         "XRAY dependency checkout -> a: X-Ray's root cause in 2 of 5 failed traces read"]
    four = XRayReader(lambda a: XFake({"checkout": {"TraceSummaries": found[2:]}})).traces(alert())
    assert [ln.split(" -> ")[1].split(":")[0] for ln in four if "dependency" in ln] == ["b", "c"]
    monkeypatch.setattr(xray, "MAX_TRACES", 25)
    every = XRayReader(lambda a: XFake({"checkout": {"TraceSummaries": found}})).traces(alert())
    assert [ln.split(" -> ")[1].split(":")[0] for ln in every if "dependency" in ln] == ["d", "b", "c"]


def test_xray_traces_no_client_is_one_partial():
    def boom(a):
        raise PermissionError("no")

    assert XRayReader(boom).traces(_two()) == ["TOOL-PARTIAL xray: PermissionError - not read"]
