"""Register C18a, false recovery: one good reading is not recovery, and a fix that fails within the hour is not one."""

from __future__ import annotations

import asyncio

from test_remediation_workflow import (  # noqa: F401 - fixtures
    FakePlatform,
    _approve_with,
    _run,
    owner,
    world,
)
from warden import bounds
from warden.workflows import CONSECUTIVE_HEALTHY, RemediationWorkflow


class _Sequence(FakePlatform):
    """Health as a sequence of readings; the last one repeats."""

    def __init__(self, readings):
        super().__init__()
        self.readings = list(readings)

    def healthy(self, service):
        self.checks += 1
        return self.readings[min(self.checks, len(self.readings)) - 1]


def test_flapping_health_never_adds_up_to_recovery(world, owner):  # noqa: F811
    world["platform"] = _Sequence([True, False, True, True, False] * 20)  # never three in a row
    out = _run(world, _approve_with(owner))
    assert out.status == "rolled_back" and world["platform"].rolled_back


def test_recovery_needs_consecutive_healthy_checks_then_holds_through_both_re_checks(world, owner):  # noqa: F811
    world["platform"] = _Sequence([False, True, True, True])
    out = _run(world, _approve_with(owner))
    assert out.status == "recovered"
    assert world["platform"].checks == 1 + CONSECUTIVE_HEALTHY + 2  # the failed one, the streak, T+15 and T+60
    assert [e["body"]["ok"] for e in world["log"].entries(kinds=(bounds.RESULT,))] == [True]


def test_a_relapse_is_a_failed_result_left_for_a_person(world, owner):  # noqa: F811
    world["platform"] = _Sequence([True, True, True, False])  # fails at the T+15 re-check
    out = _run(world, _approve_with(owner))
    assert out.status == "relapsed" and "15-minute re-check" in out.reasons[0]
    assert [e["body"]["ok"] for e in world["log"].entries(kinds=(bounds.RESULT,))] == [True, False]
    assert world["platform"].rolled_back == []  # WARDEN never reverses its own fix on its own (register C8)


def test_an_alarm_while_watching_is_a_relapse(world, owner):  # noqa: F811
    world["platform"] = _Sequence([True])

    async def drive(handle):
        await _approve_with(owner)(handle)
        # Three 30 s checks pass in real time here: the test server skips time only while a result is awaited.
        for _ in range(1800):
            if await handle.query(RemediationWorkflow.stage) == "watching":
                await handle.signal(RemediationWorkflow.alarm, "2026-10-03T02:00:00+00:00")
                return
            await asyncio.sleep(0.1)
        raise AssertionError("never reached watching")

    out = _run(world, drive)
    assert out.status == "relapsed" and "alarm fired again" in out.reasons[0]


def test_the_recorded_verdict_needs_the_last_k_checks_healthy_too():
    """Defence in depth: whatever the workflow claims, record_result reads this run's own check rows."""
    from test_apply_reverifies import REQ, _acts, _approve
    from warden.activities import FixRequest

    acts, _, owner_key = _acts()
    acts.platform = _Sequence([True, False, True])
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert _approve(acts, owner_key, plan, "rem-1").enough and acts.precheck(plan) == []
    acts.apply(plan, REQ["service"])
    for _ in range(3):
        acts.check_success(plan, REQ["service"])
    assert acts.record_result(plan, REQ["service"], True, CONSECUTIVE_HEALTHY).ok is False
    assert acts.record_result(plan, REQ["service"], True, 1).ok is True


def test_an_unhealthy_reading_restarts_the_count(world, owner):  # noqa: F811
    """T F T F T T T: the third healthy reading is not the third in a row - recovery waits for the seventh."""
    world["platform"] = _Sequence([True, False, True, False, True, True, True])
    out = _run(world, _approve_with(owner))
    assert out.status == "recovered" and world["platform"].checks == 7 + 2, world["platform"].checks
