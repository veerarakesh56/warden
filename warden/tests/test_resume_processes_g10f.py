"""The processes ONE recorded SuspendProcesses stopped on an Auto Scaling group, resumed (2026-10-11; held-out g10-103:
a person suspended Launch, Terminate and ReplaceUnhealthy, forgot them, and the group could no longer replace two
failed instances - the right undo had no entry). The event itself names what to resume; a SuspendProcesses that names
no process suspends them all (AWS API reference, read 2026-10-11)."""

from __future__ import annotations

import pytest

from test_aws_platform_g6 import WHO
from test_revert_config_history_g10d3 import ALARM, ASG, ASG_ARN, Groups, _p, _trail
from warden import catalog, resolver
from warden.models import ActionKind, Alert, RemediationProposal, Severity
from warden.platforms.aws import _ASG_PROCESSES, AwsPlatformRefused

G = "warden-dev-web"
THREE = ["Launch", "ReplaceUnhealthy", "Terminate"]
PLAN = {**ASG, "event": "p-1"}


def _suspend(processes=THREE, eid="p-1", **kw):
    request = {"autoScalingGroupName": G, **({"scalingProcesses": processes} if processes is not None else {})}
    return _trail("SuspendProcesses", request, eid=eid, source="autoscaling.amazonaws.com", **kw)


class Suspended(Groups):
    """A group of 3 on which one person suspended Launch, Terminate and ReplaceUnhealthy; one instance serves."""

    def __init__(self, processes=THREE):
        super().__init__()
        self.capacity, self.serving = 3, 1
        self.suspended = list(THREE if processes is None else processes)
        self.events = [_suspend(processes)]

    def describe_auto_scaling_groups(self, AutoScalingGroupNames):
        out = super().describe_auto_scaling_groups(AutoScalingGroupNames)
        out["AutoScalingGroups"][0]["SuspendedProcesses"] = [{"ProcessName": p, "SuspensionReason": "User suspended"}
                                                             for p in self.suspended]
        return out


def test_the_suspended_processes_are_resumed_judged_by_the_group_and_its_alarm_and_suspended_again_on_rollback():
    f = Suspended()
    p = _p(f)
    live = p.live("asg_resume_processes", ASG)
    assert live["event"] == {"p-1"}, live
    assert live["environment"] == "dev", live
    assert live["state"]["processes"] == THREE, live
    assert catalog.validate("asg_resume_processes", PLAN, live) == []
    shown = catalog.change_of("asg_resume_processes", PLAN, live["state"])[0]
    assert "resume Launch, ReplaceUnhealthy, Terminate" in shown
    assert "not brought back" in shown
    p.apply("asg_resume_processes", PLAN, snapshot=live["state"], who=WHO)
    assert f.sessions == [{"actions": ["autoscaling:ResumeProcesses"], "resources": [ASG_ARN]}]
    assert f.writes == [("resume_processes", {"AutoScalingGroupName": G, "ScalingProcesses": THREE})]
    f.suspended, f.alarm_state = [], "OK"
    assert not p.healthy(G, entry="asg_resume_processes", params=PLAN)  # 1 of 3 instances serving
    f.serving = 3
    assert p.healthy(G, entry="asg_resume_processes", params=PLAN)
    f.alarm_state = "ALARM"
    assert not p.healthy(G, entry="asg_resume_processes", params=PLAN)
    f.alarm_state, f.suspended = "OK", ["Terminate"]
    assert not p.healthy(G, entry="asg_resume_processes", params=PLAN)  # one of them is suspended again
    f.suspended = []
    assert "suspended again" in p.rollback("asg_resume_processes", PLAN, live["state"], who=WHO)
    assert f.sessions[-1] == {"actions": ["autoscaling:SuspendProcesses"], "resources": [ASG_ARN]}
    assert f.writes[-1] == ("suspend_processes", {"AutoScalingGroupName": G, "ScalingProcesses": THREE})


def test_a_suspend_that_names_no_process_suspended_them_all():
    f = Suspended(processes=None)
    f.suspended = sorted(_ASG_PROCESSES)
    live = _p(f).live("asg_resume_processes", ASG)
    assert live["event"] == {"p-1"}
    assert live["state"]["processes"] == sorted(_ASG_PROCESSES)
    f.suspended = THREE  # six of the nine run again
    assert "runs again already" in _p(f).live("asg_resume_processes", ASG)["refused"]


@pytest.mark.parametrize("change, why", [
    (lambda f: setattr(f, "suspended", ["Launch", "Terminate"]), "runs again already"),
    (lambda f: setattr(f, "alarm_state", "OK"), "not in ALARM"),
    (lambda f: f.events.append(_suspend(["HealthCheck"], eid="p-2")), "2 SuspendProcesses"),
    (lambda f: f.events.__setitem__(0, _suspend(minutes_before_alarm=-5)), "after the alarm"),
    (lambda f: f.events.__setitem__(0, _trail("SuspendProcesses", {"autoScalingGroupName": "warden-dev-other",
                                                                   "scalingProcesses": THREE}, eid="p-1")),
     "no recorded"),
    (lambda f: f.events.__setitem__(0, _suspend(who={"type": "AssumedRole", "invokedBy": "codedeploy.amazonaws.com"})),
     "AWS service"),
    (lambda f: f.events.__setitem__(0, _suspend(who={"type": "Root"})), "root user"),
    (lambda f: (setattr(f, "suspended", ["Launch", "Shell"]),
                f.events.__setitem__(0, _suspend(["Launch", "Shell"]))), "does not know"),
])
def test_a_suspension_wardens_resume_may_not_undo_is_refused(change, why):
    f = Suspended()
    change(f)
    live = _p(f).live("asg_resume_processes", ASG)
    assert live["event"] == set(), live.get("refused")
    assert why in live["refused"], live.get("refused")


def test_a_process_that_runs_again_after_the_plan_is_not_resumed_and_the_plan_is_found_again_for_its_rollback():
    f = Suspended()
    p = _p(f)
    snap = p.live("asg_resume_processes", ASG)["state"]
    f.suspended = ["Launch"]
    with pytest.raises(AwsPlatformRefused):
        p.apply("asg_resume_processes", PLAN, snapshot=snap, who=WHO)
    assert f.writes == []
    # After WARDEN's own resume and with the alarm OK, the plan's event is still found: the rollback can run.
    g = Suspended()
    q = _p(g)
    snap = q.live("asg_resume_processes", ASG)["state"]
    q.apply("asg_resume_processes", PLAN, snapshot=snap, who=WHO)
    g.suspended, g.alarm_state = [], "OK"
    g.events.append(_suspend(["HealthCheck"], eid="other", minutes_before_alarm=-9))
    q.rollback("asg_resume_processes", PLAN, snap, who=WHO)
    assert g.writes[-1] == ("suspend_processes", {"AutoScalingGroupName": G, "ScalingProcesses": THREE})


def _alert():
    return Alert(alert_id="a1", name="n", service=G, environment="dev", severity=Severity.high, summary="",
                 started_at="2026-10-10T00:00:00+00:00", labels={"alarm": ALARM, "asg": G})


def _proposal():
    return RemediationProposal(action=ActionKind.revert_change, target=G, reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)


def test_the_resolver_plans_the_one_kind_of_change_recorded_and_never_chooses_between_two():
    f = Suspended()
    request, why = resolver.request_for(_alert(), _proposal(), lambda e, params: _p(f).live(e, params))
    assert why == "", why
    assert request["entry"] == "asg_resume_processes", why
    assert request["params"] == PLAN, why
    g = Groups()  # a desired-capacity change, no suspension
    request, why = resolver.request_for(_alert(), _proposal(), lambda e, params: _p(g).live(e, params))
    assert why == "", why
    assert request["entry"] == "asg_restore_capacity", why
    both = Suspended()
    both.capacity = 2
    both.events = [*Groups().events, _suspend()]
    request, why = resolver.request_for(_alert(), _proposal(), lambda e, params: _p(both).live(e, params))
    assert request is None
    assert "more than one kind of recorded change" in why
