"""A fix that was verified and whose alarm fires again hears it at once (register G10-28).

The lab's schedule was fixed and verified, then switched off again. Its alarm fired - and reached nothing: intake
matched an alarm to an open fix by the alert's `service` (the ALARM's name here) against the plan's (the RULE's), and
told only a fix still in its verify window. The watch slept on to its 15-minute re-check, the new incident's plan was
silently not opened, and nobody was told of the relapse until then."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from test_intake import T0, _Client, _decide, _ev, _log
from test_remediation_workflow import CONVERTER, QUEUE, REQ, FakePlatform, _approve_with
from warden import approvals, bounds, intake
from warden.activities import FixRequest, RemediationActivities
from warden.workflows import RECHECK_AFTER, RemediationWorkflow


def _schedule_alarm(**labels):
    """An alarm as the lab's schedule alarm arrives: the service is the ALARM's name, the rule is in the labels."""
    ev = _ev(service="warden-dev-lab-tick-silent")
    alert = ev.alert.model_copy(update={"environment": "dev", "labels": {
        "alarm": "warden-dev-lab-tick-silent", "eventbridge_rule": "warden-dev-lab-tick", **labels}})
    return ev.model_copy(update={"alert": alert})


def test_an_alarm_reaches_the_open_fix_of_a_resource_its_labels_name():
    ev = _schedule_alarm()
    d = _decide(ev, verifying={("dev", "warden-dev-lab-tick"): "rem-dev-1"})
    assert (d.action, d.workflow_id) == ("signal_remediation", "rem-dev-1")
    assert _decide(ev, verifying={("prod", "warden-dev-lab-tick"): "rem-prod-1"}).action == "start"  # another environment's
    assert _decide(ev, verifying={("dev", "warden-dev-lab-orders"): "rem-dev-2"}).action == "start"  # another resource's
    # A label that only qualifies a resource names none: a fix filed under "shop" is not this alarm's namespace.
    assert _decide(_schedule_alarm(namespace="shop"), verifying={("dev", "shop"): "rem-dev-3"}).action == "start"
    assert _decide(_schedule_alarm(sqs="jobs, orders"), verifying={("dev", "orders"): "rem-dev-4"}).workflow_id == "rem-dev-4"


def test_a_watched_fix_is_told_its_alarm_fired_again_and_the_alarm_still_starts_its_incident():
    log, now = _log(), datetime.now(UTC)
    log.append("inc-x", "remediation.plan", {"workflow_id": "rem-dev-9", "environment": "dev",
                                             "service": "warden-dev-lab-tick"})
    ev = _schedule_alarm().model_copy(update={"transitioned_at": now})
    d = asyncio.run(intake.submit(client := _Client(stages={"rem-dev-9": "watching"}), ev, log))
    assert d.action == "start"
    assert ("signal", "rem-dev-9", "alarm", now.isoformat()) in client.calls
    assert [c[0] for c in client.calls] == ["signal", "start"]
    assert [e["body"]["workflow_id"] for e in log.entries(kinds=("intake.relapse",))] == ["rem-dev-9"]
    quiet = asyncio.run(intake.submit(client := _Client(stages={"rem-dev-9": "awaiting_approval"}),
                                      ev.model_copy(update={"transitioned_at": now + timedelta(hours=1)}), log))
    assert quiet.action == "start"
    assert [c[0] for c in client.calls] == ["start"]  # a plan nobody approved yet: not told


def _watched(alarm_at):
    """Approve a fix, let it verify, then - once it is being watched - signal its alarm (or not)."""
    owner = Ed25519PrivateKey.generate()
    pem = owner.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=pem, tiers=["T1", "T2"])})
    log = _log()

    async def main():
        env = await WorkflowEnvironment.start_time_skipping(data_converter=CONVERTER)
        acts = RemediationActivities(audit=log, policy=policy, platform=FakePlatform(healthy_after=1),
                                     limits=bounds.DEFAULT_LIMITS)
        methods = [acts.resolve_plan, acts.gate, acts.announce, acts.check_approval, acts.check_passkey, acts.precheck,
                   acts.apply, acts.check_success, acts.record_result, acts.rollback, acts.finish]
        async with env, Worker(env.client, task_queue=QUEUE, workflows=[RemediationWorkflow], activities=methods,
                               activity_executor=ThreadPoolExecutor(4)):
            handle = await env.client.start_workflow(RemediationWorkflow.run, FixRequest(**REQ),
                                                     id="rem-dev-6a3fb36ac419b7e0", task_queue=QUEUE)
            await _approve_with(owner)(handle)
            for _ in range(60):
                if await handle.query(RemediationWorkflow.stage) == "watching":
                    break
                await env.sleep(20)
            else:
                raise AssertionError("never reached watching")
            if alarm_at:
                await handle.signal(RemediationWorkflow.alarm, alarm_at)
            out = await handle.result()
            events = (await handle.fetch_history()).events  # how long the run itself lasted, on the server's clock
            return out, events[-1].event_time.ToDatetime() - events[0].event_time.ToDatetime()

    return asyncio.run(main())


def test_the_watch_ends_when_the_alarm_fires_again_not_at_its_next_recheck():
    at = T0.isoformat()
    out, took = _watched(at)
    assert out.status == "relapsed", out
    assert out.reasons == [f"orders recovered, then its alarm fired again at {at}"], out
    assert took < RECHECK_AFTER[0], took  # told at once: the first re-check is a quarter of an hour away


def test_a_watch_nothing_disturbs_still_runs_its_rechecks_to_the_end():
    out, took = _watched("")
    assert out.status == "recovered", (out, took)
    assert took >= RECHECK_AFTER[-1], (out, took)
