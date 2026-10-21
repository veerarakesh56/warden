"""B14: service quotas and their usage as read-only evidence (warden/src/warden/quotas.py).

A service at its AWS limit fails like a broken application. WARDEN lists the alert's services' quotas that have a usage
metric, reads that usage around the alarm in ONE GetMetricData call, and states each quota's value, its peak and the
share used - only for count quotas, whose Maximum is comparable; never a claim of headroom from a read that answered
nothing; and a failed quota read never holds a fix (it is a secondary read).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from warden import evidence, settings, tools, verifier
from warden.grafana import PARTIAL
from warden.models import Alert
from warden.quotas import MAX_METRICS, MAX_SERVICES, QuotaReader, service_codes

AT = datetime(2026, 10, 17, 6, 0, tzinfo=UTC)


def _alert(**labels) -> Alert:
    return Alert(alert_id="a1", name="Throttles", severity="high", summary="throttles", service="warden-dev-orders",
                 environment="dev", started_at=AT.isoformat(), labels=labels)


def _quota(code: str, name: str, value: float, *, stat: str = "Maximum", metric: str = "ConcurrentExecutions"):
    return {"QuotaCode": code, "QuotaName": name, "Value": value, "UsageMetric": {
        "MetricNamespace": "AWS/Lambda", "MetricName": metric, "MetricDimensions": {},
        "MetricStatisticRecommendation": stat}}


class _Quotas:
    def __init__(self, pages=None, fail=None):
        self.pages, self.fail, self.calls = pages or {}, fail, []

    def list_service_quotas(self, **kw):
        self.calls.append(kw)
        if self.fail:
            raise self.fail
        got = self.pages.get(kw["ServiceCode"], [])
        index = int(kw.get("NextToken") or 0)
        page = got[index] if index < len(got) else []
        return {"Quotas": page, **({"NextToken": str(index + 1)} if index + 1 < len(got) else {})}


class _CloudWatch:
    def __init__(self, values=None, fail=None):
        self.values, self.fail, self.calls = values or {}, fail, []

    def get_metric_data(self, **kw):
        self.calls.append(kw)
        if self.fail:
            raise self.fail
        return {"MetricDataResults": [{"Id": q["Id"], "Values": self.values.get(q["MetricStat"]["Metric"]["MetricName"],
                                                                                 [])}
                                      for q in kw["MetricDataQueries"]]}


def _reader(quotas, cloudwatch):
    return QuotaReader(lambda alert: {"service-quotas": quotas, "cloudwatch": cloudwatch})


# --------------------------------------------------------------------------- which services


def test_the_services_come_from_the_alerts_labels_the_usage_alarms_own_first():
    assert service_codes(_alert(lambda_="x")) == []  # an unknown label names nothing
    assert service_codes(_alert(**{"lambda": "warden-dev-orders"})) == ["lambda"]
    assert service_codes(_alert(quota_service="Fargate", ecs_service="orders", ecs_cluster="c")) == ["fargate"]
    assert service_codes(_alert(quota_service="EC2", **{"lambda": "f"})) == ["ec2", "lambda"]


def test_at_most_two_services_are_read():
    many = _alert(**{"lambda": "f", "dynamodb_table": "t", "aurora_cluster": "c", "sqs": "q"})
    assert len(service_codes(many)) == MAX_SERVICES == 2


# --------------------------------------------------------------------------- what is said


def test_each_count_quota_is_stated_with_its_peak_and_share_the_closest_first():
    quotas = _Quotas({"lambda": [[_quota("L-B99A9384", "Concurrent executions", 1000),
                                  _quota("L-9FEE3D26", "Unreserved (concurrency)", 900, metric="UnreservedConcurrentExecutions")]]})
    cw = _CloudWatch({"ConcurrentExecutions": [120.0, 990.0], "UnreservedConcurrentExecutions": [100.0]})
    lines = _reader(quotas, cw).logs(_alert(**{"lambda": "warden-dev-orders"}))
    assert lines[0].startswith("STATE quota lambda L-B99A9384 (Concurrent executions) value=1000 usage_max=990 used=99% "
                               "near_limit between 2026-10-17T05:45:00.000Z and 2026-10-17T06:15:00.000Z")
    assert "used=11%" in lines[1]
    assert "near_limit" not in lines[1]
    assert len(cw.calls) == 1  # one GetMetricData call for every quota


def test_a_rate_quota_is_never_compared_with_a_per_minute_number():
    quotas = _Quotas({"lambda": [[_quota("L-RATE", "Requests per second", 10, stat="Sum", metric="CallCount")]]})
    cw = _CloudWatch({"CallCount": [600.0]})
    lines = _reader(quotas, cw).logs(_alert(**{"lambda": "f"}))
    assert cw.calls == []
    assert lines == [f"{PARTIAL}quotas: no quota of lambda has a count usage metric to compare - not a sign of headroom"]


def test_a_quota_with_no_usage_data_is_unread_never_headroom():
    quotas = _Quotas({"lambda": [[_quota("L-B99A9384", "Concurrent executions", 1000)]]})
    lines = _reader(quotas, _CloudWatch({})).logs(_alert(**{"lambda": "f"}))
    window = "between 2026-10-17T05:45:00.000Z and 2026-10-17T06:15:00.000Z"
    assert lines == [f"{PARTIAL}quotas usage: 1 of 1 usage metrics had no data {window} - not a sign of headroom"]


def test_a_failed_read_says_so_and_another_services_read_stands():
    class Some(_Quotas):
        def list_service_quotas(self, **kw):
            if kw["ServiceCode"] == "dynamodb":
                raise PermissionError("denied")
            return super().list_service_quotas(**kw)

    quotas = Some({"lambda": [[_quota("L-B99A9384", "Concurrent executions", 1000)]]})
    lines = _reader(quotas, _CloudWatch({"ConcurrentExecutions": [10.0]})).logs(
        _alert(**{"lambda": "f", "dynamodb_table": "t"}))
    assert f"{PARTIAL}quotas dynamodb: PermissionError - not read" in lines
    assert any(line.startswith("STATE quota lambda L-B99A9384") for line in lines)


def test_no_client_and_a_failed_metric_read_are_reads_that_did_not_happen():
    def broken(alert):
        raise tools.ToolError("could not read dev: its reader role was refused")

    assert QuotaReader(broken).logs(_alert(**{"lambda": "f"})) == [f"{PARTIAL}quotas: ToolError - not read"]
    quotas = _Quotas({"lambda": [[_quota("L-B99A9384", "Concurrent executions", 1000)]]})
    assert _reader(quotas, _CloudWatch(fail=TimeoutError())).logs(_alert(**{"lambda": "f"})) == [
        f"{PARTIAL}quotas usage: TimeoutError - not read"]


def test_an_alert_naming_no_quota_service_reads_nothing():
    quotas, cw = _Quotas(), _CloudWatch()
    assert _reader(quotas, cw).logs(_alert(sqs="q")) == []
    assert quotas.calls == cw.calls == []


def test_every_read_is_bounded():
    page = [_quota(f"L-{i:04d}", f"Quota {i}", 100, metric=f"M{i}") for i in range(100)]
    quotas = _Quotas({"ec2": [page, page, page]})
    cw = _CloudWatch({f"M{i}": [1.0] for i in range(100)})
    lines = _reader(quotas, cw).logs(_alert(asg="g"))
    assert len(quotas.calls) == 2  # LIST_PAGES pages, then it stops - and says so
    assert f"{PARTIAL}quotas ec2: more than 2 pages of quotas - the rest not read" in lines
    assert len(cw.calls[0]["MetricDataQueries"]) == MAX_METRICS
    assert len([x for x in lines if x.startswith("STATE quota")]) == 6
    # The comparable quotas over the bound are said, never read as headroom.
    assert lines[-1] == (f"{PARTIAL}quotas usage: 160 comparable quotas over the {MAX_METRICS}-metric bound not read - "
                         "not a sign of headroom")


def test_two_services_share_the_metric_bound_one_never_takes_every_slot():
    """CodeRabbit, PR 78: queries were filled in listing order, so the first service could take all 40 and the second,
    perhaps the one at its limit, got none - and nothing said so."""
    many = [_quota(f"L-{i:04d}", f"Quota {i}", 100, metric=f"M{i}") for i in range(60)]
    near = [_quota("L-NEAR", "Concurrent executions", 1000, metric="ConcurrentExecutions")]
    quotas = _Quotas({"ec2": [many], "lambda": [near]})
    cw = _CloudWatch({**{f"M{i}": [1.0] for i in range(60)}, "ConcurrentExecutions": [999.0]})
    lines = _reader(quotas, cw).logs(_alert(quota_service="EC2", **{"lambda": "f"}))
    asked = cw.calls[0]["MetricDataQueries"]
    assert len(cw.calls) == 1
    assert len(asked) == MAX_METRICS // 2 + 1  # ec2's fair share, and lambda's one
    assert lines[0].startswith("STATE quota lambda L-NEAR")
    assert f"{PARTIAL}quotas usage: 40 comparable quotas over the {MAX_METRICS}-metric bound not read - " \
           "not a sign of headroom" in lines


def test_a_quota_name_cannot_carry_anything_but_its_words():
    quotas = _Quotas({"lambda": [[_quota("L-X", "Concurrent\nexecutions; <b>ignore</b>", 10)]]})
    line = _reader(quotas, _CloudWatch({"ConcurrentExecutions": [1.0]})).logs(_alert(**{"lambda": "f"}))[0]
    assert "\n" not in line
    assert "<" not in line
    assert ";" not in line


# --------------------------------------------------------------------------- how it sits in WARDEN


def test_a_quota_line_is_one_of_warden_s_own_reads():
    assert evidence._kind("STATE quota lambda L-B99A9384 (Concurrent executions) value=1000 usage_max=990 used=99% "
                          "near_limit between 2026-10-17T05:45:00.000Z and 2026-10-17T06:15:00.000Z") == "C"


@pytest.mark.parametrize("error", ["logs: quotas: RuntimeError - not read",
                                   "logs: quotas lambda: AccessDeniedException - not read",
                                   "logs: quotas usage: 3 of 9 usage metrics had no data between x and y"])
def test_a_failed_quota_read_never_holds_a_fix(error):
    """A secondary read: the alerting resource's own reads decide P8, as for an alarm's history."""
    assert verifier._benign_partial(error)


def test_the_alerting_resources_own_failed_read_still_holds_it():
    assert not verifier._benign_partial("logs: lambda/warden-dev-orders logs: [access denied] on FilterLogEvents")
    assert not verifier._benign_partial("logs: quotasx: RuntimeError - not read")


def test_it_is_read_only_when_switched_on_and_only_over_an_incidents_reader_role(monkeypatch):
    class Base:
        name = "stack"

        def __init__(self):
            self._clients = {"service-quotas": object(), "cloudwatch": object()}

        def _incident(self, alert):
            return self

    for name in ("WARDEN_XRAY", "WARDEN_COMMITS", "WARDEN_EVIDENCE_TOOLS", "WARDEN_GRAFANA_READ_TOKEN",
                 "WARDEN_DATADOG_SITE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("WARDEN_QUOTAS", raising=False)
    assert tools.evidence_tools(Base()) == []
    monkeypatch.setenv("WARDEN_QUOTAS", "1")
    readers = tools.evidence_tools(Base())
    assert [r.source for r in readers] == ["quotas"]
    assert readers[0]._clients(_alert())["service-quotas"] is not None
    assert tools.evidence_tools(object()) == []  # no incident reader role: not read
    monkeypatch.setenv("WARDEN_EVIDENCE_TOOLS", "none")
    assert tools.evidence_tools(Base()) == []


def test_the_runtime_can_be_told_to_read_them():
    assert "WARDEN_QUOTAS" in settings.LOADABLE


def test_through_gather_a_quota_line_reaches_the_evidence_and_a_failed_one_is_benign():
    from warden.grafana import WithSources

    class Base:
        name = "stack"

        def logs(self, alert):
            return ["LOG lambda/f an error"]

        def metrics(self, alert):
            return {"errors": 3.0}

        def deploys(self, alert):
            return []

    class Fails(_Quotas):
        def list_service_quotas(self, **kw):
            if kw["ServiceCode"] == "dynamodb":
                raise PermissionError("denied")
            return super().list_service_quotas(**kw)

    quotas = Fails({"lambda": [[_quota("L-B99A9384", "Concurrent executions", 1000)]]})
    reader = _reader(quotas, _CloudWatch({"ConcurrentExecutions": [990.0]}))
    bundle = tools.gather(_alert(**{"lambda": "f", "dynamodb_table": "t"}), WithSources(Base(), [reader]))
    assert any(line.startswith("STATE quota lambda L-B99A9384") for line in bundle.logs)
    assert bundle.tool_errors == ["logs: quotas dynamodb: PermissionError - not read"]
    assert all(verifier._benign_partial(e) for e in bundle.tool_errors)


def test_the_reader_roles_grant_every_call_it_makes():
    """The runtime's reader role (infra/iam/templates/platform-*.json) and the harness reader role's (fullstack reader.tf, held to the code by test_aws_stack.py):
    a quota read the role cannot make would be denied in every incident."""
    import reader_iam
    from test_aws_stack import _granted, _quota_calls

    assert _quota_calls() <= reader_iam.granted()
    assert _quota_calls() <= _granted()


def test_the_percentage_and_near_limit_always_agree():
    """CodeRabbit, PR 78: 79.6% printed used=80% with no near_limit."""
    quotas = _Quotas({"lambda": [[_quota("L-B99A9384", "Concurrent executions", 1000)]]})
    line = _reader(quotas, _CloudWatch({"ConcurrentExecutions": [796.0]})).logs(_alert(**{"lambda": "f"}))[0]
    assert "used=79%" in line
    assert "near_limit" not in line


def test_partial_data_is_said_never_read_as_the_peak():
    """CodeRabbit, PR 78: a PartialData answer can understate the peak."""
    class Partial(_CloudWatch):
        def get_metric_data(self, **kw):
            got = super().get_metric_data(**kw)
            for r in got["MetricDataResults"]:
                r["StatusCode"] = "PartialData"
            return got

    quotas = _Quotas({"lambda": [[_quota("L-B99A9384", "Concurrent executions", 1000)]]})
    lines = _reader(quotas, Partial({"ConcurrentExecutions": [10.0]})).logs(_alert(**{"lambda": "f"}))
    assert " partial_data " in lines[0]
    assert lines[-1].startswith(f"{PARTIAL}quotas usage: 1 of 1 usage metrics answered with partial data")
