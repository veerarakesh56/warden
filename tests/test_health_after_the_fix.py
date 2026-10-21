"""Scenario fs-01, live: WARDEN moved the checkout alias back to the good version at 07:59:41Z and both alarms were
OK at 08:01Z - and at 08:04:45Z it judged its fix "did not recover within 5 min" and undid it, breaking checkout
again. Its Lambda health check summed the last five minutes, which held the errors from before the fix, inside a
five-minute verify window: a working fix could never pass. A fix is now judged only on the whole minutes after it
settled, and a fix judged by metrics is given the time that takes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from test_aws_platform_g6 import FN, NOW, aws  # noqa: F401
from warden import catalog
from warden.platforms import aws as aws_mod

FIXED = NOW - timedelta(minutes=4, seconds=20)  # the alias moved 4m20s before the check


def _by_minute(f, before, after):
    """CloudWatch as it was: errors in every minute that began before the fix, none after."""
    def get_metric_data(MetricDataQueries, StartTime, EndTime, **kw):
        # CloudWatch answers even a window under a minute with the minute in progress.
        minutes = [StartTime + timedelta(minutes=i) for i in range(max(1, int((EndTime - StartTime).total_seconds() // 60)))]
        out = []
        for q in MetricDataQueries:
            name = q["MetricStat"]["Metric"]["MetricName"]
            vals = [(before if m < FIXED else after).get(name, 0.0) for m in minutes]
            out.append({"Id": q["Id"], "StatusCode": "Complete", "Values": vals})
        return {"MetricDataResults": out}
    f.get_metric_data = get_metric_data


def test_errors_from_before_the_fix_do_not_fail_it(aws):  # noqa: F811
    f, p = aws
    _by_minute(f, before={"Invocations": 10.0, "Errors": 5.0}, after={"Invocations": 10.0, "Errors": 0.0})
    params = {"function": FN, "alias": "live", "to_version": "3"}
    assert p.healthy(FN, entry="lambda_move_alias", params=params) is False  # the old window: the bug, kept visible
    params[catalog.APPLIED_AT] = FIXED.isoformat()
    assert p.healthy(FN, entry="lambda_move_alias", params=params) is True


def test_errors_after_the_fix_still_fail_it_and_too_soon_is_unknown(aws):  # noqa: F811
    f, p = aws
    _by_minute(f, before={"Invocations": 10.0, "Errors": 5.0}, after={"Invocations": 10.0, "Errors": 2.0})
    params = {"function": FN, "alias": "live", "to_version": "3", catalog.APPLIED_AT: FIXED.isoformat()}
    assert p.healthy(FN, entry="lambda_move_alias", params=params) is False
    params[catalog.APPLIED_AT] = (NOW - timedelta(seconds=40)).isoformat()  # no whole minute after it has ended yet
    _by_minute(f, before={}, after={"Invocations": 10.0})
    assert p.healthy(FN, entry="lambda_move_alias", params=params) is False


@pytest.mark.parametrize("at, first", [
    (datetime(2026, 10, 16, 7, 59, 41, tzinfo=UTC), datetime(2026, 10, 16, 8, 1, tzinfo=UTC)),
    (datetime(2026, 10, 16, 7, 59, 30, tzinfo=UTC), datetime(2026, 10, 16, 8, 0, tzinfo=UTC)),
])
def test_no_minute_that_began_before_the_fix_settled_is_counted(aws, at, first):  # noqa: F811
    f, p = aws
    seen = []
    f.get_metric_data = lambda MetricDataQueries, StartTime, EndTime, **kw: seen.append(StartTime) or {
        "MetricDataResults": [{"Id": q["Id"], "StatusCode": "Complete", "Values": [1.0]} for q in MetricDataQueries]}
    p._now = lambda: first + timedelta(minutes=3)
    p._metric_sums("AWS/Lambda", [], ("Invocations",), since=at)
    assert seen == [first]


def test_a_fix_judged_by_metrics_gets_the_time_that_takes(aws):  # noqa: F811
    _, p = aws
    live = p.live("lambda_move_alias", {"function": FN, "alias": "live", "to_version": "3"})
    assert live
    assert live["recover_minutes"] >= aws_mod.METRIC_SETTLE_MINUTES


def test_check_success_hands_the_platform_the_time_this_run_applied_the_fix(tmp_path):
    from warden import approvals, audit, bounds
    from warden.activities import Plan, RemediationActivities

    seen = []

    class Platform:
        def healthy_for(self, entry, service, params=None, environment=None):
            seen.append(params)
            return True

    log = audit.AuditLog(tmp_path / "a.db", key=None)
    plan = Plan(workflow_id="rem-dev-0123456789abcdef", incident_id="inc-1", entry="lambda_move_alias", tier="T2",
                params={"function": FN, "alias": "live", "to_version": "3"}, plan_hash="p" * 64,
                created_at=datetime.now(UTC), target=f"dev/lambda:{FN}", environment="dev")
    acts = RemediationActivities(audit=log, policy=approvals.ApproverPolicy(approvers={}), platform=Platform())
    acts.check_success(plan, FN)
    assert catalog.APPLIED_AT not in seen[-1]  # nothing applied in this run: nothing handed
    log.append("inc-1", bounds.APPLIED, {"workflow_id": plan.workflow_id, "run_id": "", "plan_hash": plan.plan_hash})
    log.append("inc-1", bounds.APPLIED, {"workflow_id": plan.workflow_id, "run_id": "", "plan_hash": "q" * 64})
    acts.check_success(plan, FN)
    ours = [e["at"] for e in log.entries("inc-1", kinds=(bounds.APPLIED,)) if e["body"]["plan_hash"] == plan.plan_hash]
    assert seen[-1][catalog.APPLIED_AT] == ours[-1].isoformat()  # this plan's apply, not the other plan's later one
    assert catalog.APPLIED_AT not in plan.params
