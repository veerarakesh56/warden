"""B13: success means the symptom is gone - the alarm's own metric no worse for N periods since the fix, and no new
error class - not only that the alarm left ALARM. CloudWatch alarms and Datadog monitors alike; deterministic; N
configurable; the reading recorded on the check's audit row; "unknown" never fails a fix, "present" does."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from warden import approvals, audit, bounds, symptom
from warden.activities import Plan, RemediationActivities

APPLIED = datetime(2026, 10, 20, 6, 0, 30, tzinfo=UTC)
ALERT_AT = APPLIED - timedelta(minutes=10)
ALARM = "warden-dev-orders-errors"


# --------------------------------------------------------------------------- the rule


@pytest.mark.parametrize(("values", "state"), [
    ([1.0, 2.0, 3.0], symptom.GONE),
    ([1.0, 2.0, 3.0, 4.0], symptom.GONE),  # more than N, every one clean
    ([1.0, 9.0, 3.0], symptom.PRESENT),  # one breach since the fix is not "no worse"
    ([9.0], symptom.PRESENT),  # a breach is known before N periods exist
    ([1.0, 2.0], symptom.UNKNOWN),  # clean so far, but not N periods yet
    ([], symptom.UNKNOWN),
])
def test_the_metric_must_be_within_the_threshold_for_n_periods(values, state):
    assert symptom.judge(values, "GreaterThanThreshold", 5.0, 3)[0] == state


def test_each_comparison_is_the_alarms_own():
    assert symptom.judge([5.0] * 3, "GreaterThanOrEqualToThreshold", 5.0, 3)[0] == symptom.PRESENT
    assert symptom.judge([5.0] * 3, "GreaterThanThreshold", 5.0, 3)[0] == symptom.GONE
    assert symptom.judge([1.0] * 3, "LessThanThreshold", 2.0, 3)[0] == symptom.PRESENT
    assert symptom.judge([1.0] * 3, "<=", 1.0, 3)[0] == symptom.PRESENT
    # An anomaly band has no single threshold: never judged, never guessed.
    assert symptom.judge([1.0] * 3, "LessThanLowerOrGreaterThanUpperThreshold", 0.0, 3)[0] == symptom.UNKNOWN


@pytest.mark.parametrize(("raw", "n"), [("", 3), ("5", 5), ("1", 1), ("20", 20), ("0", 3), ("21", 3), ("x", 3),
                                        ("-2", 3)])
def test_n_is_configurable_and_bounded(monkeypatch, raw, n):
    monkeypatch.setenv("WARDEN_SYMPTOM_PERIODS", raw)
    assert symptom.periods() == n


def test_the_runtime_can_be_told_n():
    from warden import settings

    assert "WARDEN_SYMPTOM_PERIODS" in settings.LOADABLE


def test_a_new_error_class_is_one_not_seen_before_the_fix():
    before = ["ERROR botocore.exceptions.ClientError: ThrottlingException", "Task timed out"]
    after = ["ClientError again", "psycopg.errors.UniqueViolation", "KeyError: 'sku'", "ValueError: bad",
             "ThrottlingException"]
    assert symptom.new_classes(before, after) == ["KeyError", "ValueError"]
    assert symptom.new_classes(after, before) == []  # a module path is the same class as the bare name
    assert symptom.new_classes([], []) == []


# --------------------------------------------------------------------------- CloudWatch


class _CloudWatch:
    def __init__(self, values, *, alarm=None, period=60):
        self.values, self.period, self.asked = values, period, []
        self.alarm = alarm if alarm is not None else {
            "AlarmName": ALARM, "Namespace": "AWS/Lambda", "MetricName": "Errors", "Statistic": "Sum",
            "Period": period, "Threshold": 5.0, "ComparisonOperator": "GreaterThanThreshold",
            "Dimensions": [{"Name": "FunctionName", "Value": "warden-dev-orders"}]}

    def describe_alarms(self, **kw):
        return {"MetricAlarms": [self.alarm] if self.alarm else []}

    def get_metric_data(self, **kw):
        self.asked.append((kw["MetricDataQueries"], kw["StartTime"], kw["EndTime"]))
        stamps = [kw["StartTime"] + timedelta(seconds=self.period * i) for i in range(len(self.values))]
        return {"MetricDataResults": [{"Id": "m", "Timestamps": stamps, "Values": self.values}]}


class _Logs:
    def __init__(self, before, after, fail=None):
        self.before, self.after, self.fail = before, after, fail

    def filter_log_events(self, **kw):
        if self.fail:
            raise self.fail
        lines = self.after if kw["startTime"] >= int(APPLIED.timestamp() * 1000) else self.before
        return {"events": [{"message": m} for m in lines]}


def _read(cw, logs):
    return lambda name: {"cloudwatch": cw, "logs": logs}[name]


def test_the_alarms_own_metric_is_read_from_the_first_whole_period_after_the_fix():
    cw = _CloudWatch([1.0, 2.0, 3.0, 99.0])
    now = APPLIED + timedelta(minutes=4)
    r = symptom.cloudwatch_metric(cw, ALARM, APPLIED, now, 3)
    queries, start, end = cw.asked[0]
    assert start == datetime(2026, 10, 20, 6, 1, tzinfo=UTC)  # the period that began before the fix is not judged
    assert end == now
    stat = queries[0]["MetricStat"]
    assert (stat["Period"], stat["Stat"], stat["Metric"]["MetricName"]) == (60, "Sum", "Errors")
    # 06:01, 06:02 and 06:03 are over; 06:04 is still running at 06:04:30, so its 99 is not judged.
    assert r.values == [1.0, 2.0, 3.0]
    assert r.state == symptom.GONE


def test_a_metric_math_or_missing_alarm_is_unknown_never_gone():
    r = symptom.cloudwatch_metric(_CloudWatch([1.0], alarm={}), ALARM, APPLIED, APPLIED + timedelta(hours=1), 3)
    assert r.state == symptom.UNKNOWN
    assert "single-metric" in r.why


def test_no_whole_period_yet_reads_nothing_and_is_unknown():
    cw = _CloudWatch([1.0], period=300)
    r = symptom.cloudwatch_metric(cw, ALARM, APPLIED, APPLIED + timedelta(minutes=2), 3)
    assert cw.asked == []
    assert r.state == symptom.UNKNOWN


def test_a_new_error_class_makes_the_symptom_present_whatever_the_metric_says():
    logs = _Logs(before=["ThrottlingException"], after=["ThrottlingException", "KeyError: 'sku'"])
    r = symptom.cloudwatch(_read(_CloudWatch([0.0, 0.0, 0.0]), logs), ALARM, {"lambda": "warden-dev-orders"},
                           alert_at=ALERT_AT, applied=APPLIED, now=APPLIED + timedelta(minutes=5), n=3)
    assert r.state == symptom.PRESENT
    assert r.new_errors == ["KeyError"]
    assert r.errors_read is True


def test_unread_logs_leave_the_metrics_verdict_and_say_so():
    logs = _Logs([], [], fail=OSError("denied"))
    r = symptom.cloudwatch(_read(_CloudWatch([0.0, 0.0, 0.0]), logs), ALARM, {"lambda": "warden-dev-orders"},
                           alert_at=ALERT_AT, applied=APPLIED, now=APPLIED + timedelta(minutes=5), n=3)
    assert (r.state, r.errors_read) == (symptom.GONE, False)
    assert "error logs not read" in r.why


def test_the_logs_before_the_fix_start_before_the_alarm():
    assert symptom.before_start(ALERT_AT, APPLIED) == ALERT_AT - symptom.BEFORE
    assert symptom.log_groups({"log_group": "/ecs/warden-dev-orders", "lambda": "f", "x": "y"}) == [
        "/ecs/warden-dev-orders", "/aws/lambda/f"]
    assert symptom.log_groups({}) == []


# --------------------------------------------------------------------------- Datadog


def _ask(monitor, points=(), errors_before=(), errors_after=()):
    asked = []

    def ask(what, method, path, body=None, query=None):
        asked.append(what)
        if what == "monitor":
            return monitor, ""
        if what == "metrics":
            return {"series": [{"pointlist": [list(p) for p in points]}]}, ""
        before = body["filter"]["to"] <= APPLIED.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        lines = errors_before if before else errors_after
        return {"data": [{"attributes": {"message": m}} for m in lines]}, ""

    return ask, asked


def _ms(minutes: float) -> float:
    return (APPLIED + timedelta(minutes=minutes)).timestamp() * 1000


def test_a_datadog_monitor_still_alerting_is_present():
    ask, _ = _ask({"overall_state": "Alert", "query": "avg(last_5m):avg:trace.errors{service:orders} > 0.05"})
    r = symptom.datadog(ask, "123", "orders", alert_at=ALERT_AT, applied=APPLIED, now=APPLIED + timedelta(minutes=20),
                        n=3)
    assert r.state == symptom.PRESENT
    assert r.source == "datadog"


def test_a_datadog_metric_monitor_is_judged_over_its_own_windows():
    monitor = {"overall_state": "OK", "query": "max(last_5m):avg:trace.errors{service:orders} > 0.05"}
    clean = [(_ms(m), 0.01) for m in range(16)]
    ask, _ = _ask(monitor, clean)
    r = symptom.datadog(ask, "123", "orders", alert_at=ALERT_AT, applied=APPLIED, now=APPLIED + timedelta(minutes=16),
                        n=3)
    assert (r.state, len(r.values)) == (symptom.GONE, 3)
    ask, _ = _ask(monitor, [*clean, (_ms(7), 0.2)])
    r = symptom.datadog(ask, "123", "orders", alert_at=ALERT_AT, applied=APPLIED, now=APPLIED + timedelta(minutes=16),
                        n=3)
    assert r.state == symptom.PRESENT


def test_a_datadog_monitor_whose_query_is_not_compared_is_unknown_and_its_new_errors_still_count():
    monitor = {"overall_state": "OK", "query": "logs(\"service:orders\").index(\"*\").rollup(\"count\").last(\"5m\") > 3"}
    ask, _ = _ask(monitor, errors_before=["TimeoutError"], errors_after=["TimeoutError"])
    r = symptom.datadog(ask, "123", "orders", alert_at=ALERT_AT, applied=APPLIED, now=APPLIED + timedelta(minutes=5),
                        n=3)
    assert (r.state, r.errors_read) == (symptom.UNKNOWN, True)
    ask, _ = _ask(monitor, errors_after=["ConnectionRefusedError"])
    r = symptom.datadog(ask, "123", "orders", alert_at=ALERT_AT, applied=APPLIED, now=APPLIED + timedelta(minutes=5),
                        n=3)
    assert (r.state, r.new_errors) == (symptom.PRESENT, ["ConnectionRefusedError"])


def test_an_unread_datadog_monitor_is_unknown():
    r = symptom.datadog(lambda *a, **k: (None, "TOOL-PARTIAL datadog monitor: HTTP 403 - not read"), "123", "orders",
                        alert_at=ALERT_AT, applied=APPLIED, now=APPLIED + timedelta(minutes=5), n=3)
    assert r.state == symptom.UNKNOWN
    assert "403" in r.why


# --------------------------------------------------------------------------- the check after a fix


class _Platform:
    def __init__(self, cw, logs):
        self.cw, self.logs, self.environments = cw, logs, []

    def healthy(self, service):
        return True

    def alarm_state(self, alarm, environment=None):
        return "OK"  # the alarm left ALARM: before B13 this alone was a recovery

    def reader(self, environment=None):
        self.environments.append(environment)
        return _read(self.cw, self.logs)


def _check(tmp_path, cw, logs, *, via="cloudwatch", applied=True, later=timedelta(minutes=10)):
    real = datetime.now(UTC)
    symptom_now = real + later  # the check runs this long after the fix the audit row records now
    import warden.symptom as module

    module_now, module.now = module.now, lambda: symptom_now
    try:
        return _run(tmp_path, cw, logs, via=via, applied=applied)
    finally:
        module.now = module_now


def _run(tmp_path, cw, logs, *, via, applied):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    log.append("inc-1", "incident.alert", {"alert": {"name": ALARM, "service": "warden-dev-orders",
                                                     "started_at": ALERT_AT.isoformat(),
                                                     "labels": {"alarm": ALARM, "via": via,
                                                                "lambda": "warden-dev-orders"}}})
    plan = Plan(workflow_id="rem-dev-1", incident_id="inc-1", entry="lambda_move_alias", tier="T2", params={},
                plan_hash="h", created_at=datetime.now(UTC), target="lambda/warden-dev-orders", environment="dev")
    if applied:
        log.append("inc-1", bounds.APPLIED, {"workflow_id": plan.workflow_id, "run_id": "", "plan_hash": "h"})
    platform = _Platform(cw, logs)
    acts = RemediationActivities(audit=log, policy=approvals.ApproverPolicy(approvers={}), platform=platform)
    ok = acts.check_success(plan, "warden-dev-orders")
    return ok, log.entries("inc-1", kinds=("remediation.check",))[-1]["body"], platform


def test_an_alarm_out_of_alarm_with_its_metric_still_breaching_is_not_a_recovery(tmp_path):
    ok, row, platform = _check(tmp_path, _CloudWatch([50.0] * 10), _Logs([], []))
    assert ok is False
    assert row["healthy"] is False
    assert row["alarm_state"] == "OK"
    assert row["symptom"]["state"] == symptom.PRESENT
    assert row["symptom"]["periods"] == 3
    assert platform.environments == ["dev"]


def test_a_new_error_class_after_the_fix_is_not_a_recovery(tmp_path):
    ok, row, _ = _check(tmp_path, _CloudWatch([]), _Logs(["Throttling"], ["KeyError: 'sku'"]))
    assert ok is False
    assert row["symptom"]["new_errors"] == ["KeyError"]


def test_an_unknown_reading_never_fails_a_good_fix_and_is_recorded(tmp_path):
    ok, row, _ = _check(tmp_path, _CloudWatch([]), _Logs([], []))
    assert ok is True
    assert row["symptom"]["state"] == symptom.UNKNOWN


def test_a_failed_read_is_unknown_and_says_why(tmp_path):
    class Broken(_CloudWatch):
        def describe_alarms(self, **kw):
            raise OSError("connection reset")

    ok, row, _ = _check(tmp_path, Broken([]), _Logs([], []))
    assert ok is True
    assert row["symptom"] == {**row["symptom"], "state": symptom.UNKNOWN, "why": "not read: OSError"}


def test_n_clean_periods_and_no_new_error_is_a_recovery(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_SYMPTOM_PERIODS", "2")
    ok, row, _ = _check(tmp_path, _CloudWatch([0.0] * 10), _Logs(["ThrottlingException"], []))
    assert ok is True
    assert row["symptom"]["state"] == symptom.GONE
    assert row["symptom"]["periods"] == 2


def test_nothing_is_read_before_this_run_applied_the_fix(tmp_path):
    ok, row, platform = _check(tmp_path, _CloudWatch([50.0] * 10), _Logs([], []), applied=False)
    assert ok is True
    assert "symptom" not in row
    assert platform.environments == []


def test_a_datadog_monitors_incident_is_judged_too(tmp_path, monkeypatch):
    seen = []

    class Reader:
        def _ask(self, what, method, path, body=None, query=None):
            seen.append(path)
            if what == "monitor":
                return {"overall_state": "Alert", "query": "avg(last_5m):x{a:b} > 1"}, ""
            return {"data": [], "series": []}, ""

    from warden import datadog

    monkeypatch.setattr(datadog, "configured", lambda: True)
    monkeypatch.setattr(datadog, "DatadogReader", Reader)
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    log.append("inc-1", "incident.alert", {"alert": {"name": "m", "service": "orders",
                                                     "started_at": ALERT_AT.isoformat(),
                                                     "labels": {"datadog_monitor": "123", "via": "datadog"}}})
    plan = Plan(workflow_id="rem-dev-1", incident_id="inc-1", entry="lambda_move_alias", tier="T2", params={},
                plan_hash="h", created_at=datetime.now(UTC), target="lambda/warden-dev-orders", environment="dev")
    log.append("inc-1", bounds.APPLIED, {"workflow_id": plan.workflow_id, "run_id": "", "plan_hash": "h"})
    acts = RemediationActivities(audit=log, policy=approvals.ApproverPolicy(approvers={}),
                                 platform=_Platform(None, None))
    assert acts.check_success(plan, "orders") is False
    assert "/api/v1/monitor/123" in seen
    assert log.entries("inc-1", kinds=("remediation.check",))[-1]["body"]["symptom"]["source"] == "datadog"


def test_the_platform_registry_hands_the_aws_reader_in_the_plans_environment():
    from warden.platforms import RoutedPlatform

    class Aws:
        def __init__(self, env=""):
            self.env = env
            self._read = lambda name: (env, name)

        def alarm_state(self, alarm):
            return "OK"

        def for_environment(self, env):
            return Aws(env)

        def knows(self, service):
            return False

    read = RoutedPlatform(aws=Aws()).reader(environment="dev")
    assert read("cloudwatch") == ("dev", "cloudwatch")
    assert RoutedPlatform().reader(environment="dev") is None
