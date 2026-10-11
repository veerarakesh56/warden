"""A fix judged by its alarm is verified for as long as that alarm can take to read OK (2026-10-11). The workflow's
verify window was a fixed five minutes: an alarm of three 5-minute periods clears no sooner than fifteen, so a right
restore behind it was rolled back as "not recovered". The platform's live read now gives the alarm's own evaluation
time, and the resolver carries it in the request - never under the default, never over what a request may ask."""

from __future__ import annotations

import pytest

from test_revert_config_history_g10d3 import ALARM, ASG, ECS, FN, Fake, Groups, _p
from warden import activities, resolver
from warden.models import ActionKind, Alert, RemediationProposal, Severity


class Timed(Fake):
    def __init__(self, **alarm):
        super().__init__()
        self.alarm = alarm

    def describe_alarms(self, AlarmNames, AlarmTypes):
        out = super().describe_alarms(AlarmNames, AlarmTypes)
        out["MetricAlarms"][0].update(self.alarm)
        return out


MATH = {"EvaluationPeriods": 2, "Metrics": [{"Id": "e", "Expression": "a/b"}, {"Id": "a", "MetricStat": {"Period": 300}},
                                            {"Id": "b", "MetricStat": {"Period": 60}}]}


@pytest.mark.parametrize("alarm, minutes", [
    ({"Period": 300, "EvaluationPeriods": 3}, 18),
    ({"Period": 60, "EvaluationPeriods": 1}, 4),
    ({"Period": 90, "EvaluationPeriods": 1}, 5),  # a part of a minute is a whole one
    (MATH, 13),  # a metric-math alarm: its slowest metric
    ({}, None), ({"Period": 300}, None), ({"Period": 0, "EvaluationPeriods": 3}, None),
    ({"Period": 300, "EvaluationPeriods": 0}, None), ({"Period": "300", "EvaluationPeriods": 3}, None),
])
def test_the_live_read_gives_the_time_its_alarm_can_take_to_clear(alarm, minutes):
    live = _p(Timed(**alarm)).live("ecs_restore_desired", ECS)
    assert live["event"] == {"e-1"} and live.get("recover_minutes") == minutes


def test_only_a_read_that_names_an_alarm_is_timed_by_one_and_a_failed_timing_voids_nothing():
    f = Timed(Period=300, EvaluationPeriods=3)
    live = _p(f).live("lambda_set_reserved_concurrency", {"function": FN})
    assert live["function"] == {FN} and "recover_minutes" not in live
    assert "recover_minutes" not in _p(f).live("ecs_restore_desired", {"cluster": "c1", "service": "x"})  # nothing read
    p = _p(f)
    p._alarm_clear_minutes = lambda alarm: 1 / 0
    live = p.live("ecs_restore_desired", ECS)
    assert live["event"] == {"e-1"} and "recover_minutes" not in live


class SlowGroups(Groups, Timed):
    def __init__(self, grace, **alarm):
        Groups.__init__(self)
        self.alarm, self.grace = alarm, grace

    def describe_auto_scaling_groups(self, AutoScalingGroupNames):
        out = super().describe_auto_scaling_groups(AutoScalingGroupNames)
        out["AutoScalingGroups"][0]["HealthCheckGracePeriod"] = self.grace
        return out


@pytest.mark.parametrize("grace, minutes", [(300, 10), (301, 11), (0, 5), (None, 5), ("300", 5)])
def test_a_groups_new_instances_get_their_own_grace_period_on_top(grace, minutes):
    live = _p(SlowGroups(grace, Period=60, EvaluationPeriods=2)).live("asg_restore_capacity", ASG)
    assert live["event"] == {"a-1"} and live["recover_minutes"] == minutes and "slow_start_s" not in live
    assert "slow_start_s" not in _p(SlowGroups(grace)).live("asg_restore_capacity", ASG)  # the alarm's timing unread


def _request(minutes):
    alert = Alert(alert_id="a1", name="n", service="warden-dev-orders", environment="dev", severity=Severity.high,
                  summary="", started_at="2026-10-10T00:00:00+00:00",
                  labels={"alarm": ALARM, "ecs_cluster": "c1", "ecs_service": "warden-dev-orders"})
    proposal = RemediationProposal(action=ActionKind.revert_change, target="warden-dev-orders", reasoning="r",
                                   expected_effect="e", blast_radius="single_service", reversible=True)
    platform = _p(Fake())

    def live(entry, params):
        state = platform.live(entry, params)
        return state if minutes is None else {**state, "recover_minutes": minutes}

    request, why = resolver.request_for(alert, proposal, live)
    assert why == "" and request["entry"] == "ecs_restore_desired", why
    return request


@pytest.mark.parametrize("minutes, window", [(18, 18), (4, 5), (5, 5), (120, 120), (121, 120), (100000, 120)])
def test_the_request_carries_the_platforms_window_inside_what_a_request_may_ask(minutes, window):
    request = _request(minutes)
    assert request["recover_within_minutes"] == window
    assert activities.FixRequest.model_validate(request).recover_within_minutes == window


@pytest.mark.parametrize("minutes", [None, True, "18", 18.0])
def test_a_window_the_platform_did_not_give_as_a_whole_number_leaves_the_default(minutes):
    request = _request(minutes)
    assert "recover_within_minutes" not in request
    assert activities.FixRequest.model_validate(request).recover_within_minutes == resolver.RECOVER_MINUTES[0]


def test_the_resolvers_bounds_are_the_requests_own():
    field = activities.FixRequest.model_fields["recover_within_minutes"]
    assert resolver.RECOVER_MINUTES == (field.default, activities.MAX_RECOVER_WITHIN_MINUTES)
