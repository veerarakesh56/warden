"""Owner, 2026-10-15: "in real time the fixes might break things or cause even bigger other problems ... so everything
should be tracked and verified and double checked", and "we don't know if it is because of that issue or not, so we
can't say directly, but can investigate and compare and link them".

- Another alarm in the environment that starts while one of WARDEN's fixes is verified or watched starts its own
  incident as any alarm does (connected or not is for its diagnosis to say, with the fix beside its evidence) - and the
  fix is told: it is not called fixed and held, and it is not undone on its own.
- A fix that fails a re-check with no alarm to start an incident is diagnosed again by WARDEN itself - the cause, the
  fix, the plan - from what it reads now."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from test_false_recovery_c18a import _Sequence
from test_intake import _Client, _ev, _log
from test_relapse_now_g10l import _schedule_alarm
from test_remediation_workflow import (  # noqa: F401 - fixtures
    CONVERTER,
    QUEUE,
    REQ,
    FakePlatform,
    _approve_with,
    _run,
    owner,
    world,
)
from warden import approvals, bounds, intake
from warden.activities import FixRequest, RemediationActivities
from warden.cli import DEMO_ALERTS
from warden.models import Alert
from warden.workflows import RECHECK_AFTER, RemediationWorkflow


def test_another_alarm_in_the_environment_starts_its_incident_and_tells_the_watched_fix():
    log, now = _log(), datetime.now(UTC)
    log.append("inc-x", "remediation.plan", {"workflow_id": "rem-dev-9", "environment": "dev",
                                             "service": "warden-dev-order-processor"})
    log.append("inc-y", "remediation.plan", {"workflow_id": "rem-prod-1", "environment": "prod",
                                             "service": "warden-prod-order-processor"})
    ev = _schedule_alarm().model_copy(update={"transitioned_at": now})
    d = asyncio.run(intake.submit(client := _Client(stages={"rem-dev-9": "watching", "rem-prod-1": "verifying"}), ev,
                                  log))
    assert d.action == "start" and d.after_fix == ["rem-dev-9"]  # not another environment's fix
    told = [c for c in client.calls if c[:3] == ("signal", "rem-dev-9", "side_effect")]
    assert len(told) == 1 and f"`{ev.rule}` started at" in told[0][3]
    assert f"diagnosed as incident `{d.workflow_id.removeprefix('inc-')}`" in told[0][3]
    assert [c[0] for c in client.calls] == ["start", "signal"]  # the incident first: a fix that ended holds nothing back
    assert [e["body"]["incident"] for e in log.entries(kinds=("intake.side_effect",))] == [d.workflow_id]


def test_the_fixs_own_alarm_is_a_relapse_not_a_side_effect():
    log, now = _log(), datetime.now(UTC)
    log.append("inc-x", "remediation.plan", {"workflow_id": "rem-dev-9", "environment": "dev",
                                             "service": "warden-dev-lab-tick"})
    d = asyncio.run(intake.submit(client := _Client(stages={"rem-dev-9": "watching"}),
                                  _schedule_alarm().model_copy(update={"transitioned_at": now}), log))
    assert d.after_fix == [] and not any(c[2] == "side_effect" for c in client.calls if c[0] == "signal")


def test_an_expected_down_alarm_tells_no_fix():
    log = _log()
    log.append("inc-x", "remediation.plan", {"workflow_id": "rem-9", "environment": "prod", "service": "payments"})
    d = intake.decide(_ev(), recent=[], open_incidents={}, verifying={}, open_count=0,
                      expected=("maintenance", None))
    assert d.action == "expected" and d.after_fix == []


def _watched_then(signal, signal_with_log=False):
    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=pem, tiers=["T1", "T2"])})
    log = _log()

    async def main():
        env = await WorkflowEnvironment.start_time_skipping(data_converter=CONVERTER)
        acts = RemediationActivities(audit=log, policy=policy, platform=FakePlatform(healthy_after=1))
        methods = [acts.resolve_plan, acts.gate, acts.announce, acts.check_approval, acts.check_passkey, acts.precheck,
                   acts.apply, acts.check_success, acts.record_result, acts.rollback, acts.finish, acts.side_effects]
        async with env, Worker(env.client, task_queue=QUEUE, workflows=[RemediationWorkflow], activities=methods,
                               activity_executor=ThreadPoolExecutor(4)):
            handle = await env.client.start_workflow(RemediationWorkflow.run, FixRequest(**REQ),
                                                     id="rem-dev-6a3fb36ac419b7e0", task_queue=QUEUE)
            await _approve_with(key)(handle)
            for _ in range(60):
                if await handle.query(RemediationWorkflow.stage) == "watching":
                    break
                await env.sleep(20)
            else:
                raise AssertionError("never reached watching")
            await (_intake_saw(log) if signal_with_log else signal)(handle)
            out = await handle.result()
            events = (await handle.fetch_history()).events
            return out, events[-1].event_time.ToDatetime() - events[0].event_time.ToDatetime(), log

    return asyncio.run(main())


def _intake_saw(log, wid="rem-dev-6a3fb36ac419b7e0"):
    async def signal(handle):
        log.append(wid, "intake.side_effect", {"workflow_id": wid, "incident": "inc-abc",
                                               "rule": "warden-dev-db-connections", "at": "2026-10-15T17:30:00+00:00"})
        await handle.signal(RemediationWorkflow.side_effect, "what the signal says is not what is said")
    return signal


def test_a_watched_fix_with_another_alarm_after_it_is_not_called_fixed_nor_undone():
    said = "`warden-dev-db-connections` started at 2026-10-15T17:30:00+00:00, diagnosed as incident `abc`"
    out, took, log = _watched_then(lambda h: None, signal_with_log=True)
    assert out.status == "side_effects", out
    assert out.reasons == [f"orders passed its own checks, but after the fix: {said}"]  # from the record
    assert took < RECHECK_AFTER[0]  # said at once, not at the next re-check
    assert [e["body"]["ok"] for e in log.entries(kinds=(bounds.RESULT,))] == [True, False]  # the breaker counts it
    assert not log.entries(kinds=("remediation.rollback",))  # never undone on its own


def test_a_side_effect_signal_the_record_does_not_bear_out_changes_nothing():
    async def forged(handle):
        await handle.signal(RemediationWorkflow.side_effect, "`x` started at t, diagnosed as incident `y`")
    out, took, log = _watched_then(forged)
    assert out.status == "recovered" and took >= RECHECK_AFTER[-1], out
    assert [e["body"]["ok"] for e in log.entries(kinds=(bounds.RESULT,))] == [True]


def test_a_relapse_no_alarm_reported_is_diagnosed_again_by_warden(world, owner):  # noqa: F811
    world["platform"] = _Sequence([True, True, True, False])  # fails at the T+15 re-check, no alarm fires
    world["log"].append("inc-42", "incident.alert", {"alert": Alert(**DEMO_ALERTS["inc-002"]).model_dump(mode="json")})
    out = _run(world, _approve_with(owner))
    assert out.status == "relapsed" and "15-minute re-check" in out.reasons[0]
    again = world["log"].entries("inc-42", kinds=("remediation.rediagnose",))
    assert len(again) == 1 and "15-minute re-check" in again[0]["body"]["why"]
    assert out.reasons[1].startswith(f"WARDEN diagnoses the incident again from what it reads now, as "
                                     f"`{again[0]['body']['new']}`")
    assert world["platform"].rolled_back == []
