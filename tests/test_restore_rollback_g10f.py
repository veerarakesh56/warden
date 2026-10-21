"""A restore from AWS Config's record can still be rolled back once Config has recorded the restore itself
(2026-10-11, found reading the platform; not yet seen live). The live read took any later Config record with another
value for "the value changed again" and dropped the before and after values from its snapshot - and WARDEN's own
restore IS such a record, a few minutes after it is applied. The rollback then found a snapshot unlike the one
approved, refused, and a refused rollback ends the run as rollback_failed with the kill switch tripped."""

from __future__ import annotations

import pytest

from test_aws_platform_g6 import WHO
from test_revert_config_history_g10d3 import ASG, ECS, Fake, Groups, _ci, _p, _trail
from warden.platforms.aws import AwsPlatformRefused

PLAN = {**ECS, "event": "e-1", "desired": "2"}


def _restored():
    """An ECS service whose desired count WARDEN set back to 2, as CloudTrail and Config record it afterwards."""
    f = Fake()
    p = _p(f)
    snap = p.live("ecs_restore_desired", ECS)["state"]
    p.apply("ecs_restore_desired", PLAN, snapshot=snap, who=WHO)
    f.desired = 2
    f.events.append(_trail("UpdateService", {"cluster": "c1", "service": "warden-dev-orders", "desiredCount": 2},
                           eid="warden-1", minutes_before_alarm=-3))
    f.history["AWS::ECS::Service"].append(_ci(-3, {"DesiredCount": 2}, related=["warden-1"]))
    return f, p, snap


def test_the_snapshot_keeps_its_values_when_config_has_recorded_a_later_one():
    _, p, snap = _restored()
    live = p.live("ecs_restore_desired", PLAN)
    assert live["event"] == set()
    assert "changed again" in live["refused"]  # no new plan is made from it
    assert (live["state"]["before"], live["state"]["after"]) == (snap["before"], snap["after"]) == (2, 0)


def test_a_restore_config_has_recorded_is_still_rolled_back():
    f, p, snap = _restored()
    assert "from 2 to 0" in p.rollback("ecs_restore_desired", PLAN, snap, who=WHO)
    assert f.writes[-1] == ("update_service", {"cluster": "c1", "service": "warden-dev-orders", "desiredCount": 0})


def test_a_value_someone_else_changed_since_is_still_never_written_over():
    f, p, snap = _restored()
    f.desired = 5  # a person set another count after WARDEN's restore
    f.history["AWS::ECS::Service"].append(_ci(-5, {"DesiredCount": 5}))
    with pytest.raises(AwsPlatformRefused, match="nothing was changed"):  # else a count WARDEN did not set was written over
        p.rollback("ecs_restore_desired", PLAN, snap, who=WHO)
    assert [w for w in f.writes if w[0] == "update_service"] == [
        ("update_service", {"cluster": "c1", "service": "warden-dev-orders", "desiredCount": 2})]


def test_the_same_holds_for_a_group_whose_restore_config_recorded():
    f = Groups()
    p = _p(f)
    plan = {**ASG, "event": "a-1", "desired": "6"}
    snap = p.live("asg_restore_capacity", ASG)["state"]
    p.apply("asg_restore_capacity", plan, snapshot=snap, who=WHO)
    f.capacity = 6
    f.history["AWS::AutoScaling::AutoScalingGroup"].append(_ci(-3, {"desiredCapacity": 6}))
    p.rollback("asg_restore_capacity", plan, snap, who=WHO)
    assert f.writes[-1][0] == "set_desired_capacity"
    assert f.writes[-1][1]["DesiredCapacity"] == 2
