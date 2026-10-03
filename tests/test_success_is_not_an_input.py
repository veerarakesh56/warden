"""A fix is verified only by WARDEN's own health checks of the same run (fourth review, 2026-09-30, B-N2).

`rem-<service>` is reused, and the payload codec binds a result to the workflow id, not the run. Run 1's
"healthy" result, completed into run 2's check_success by anyone who can complete activity tasks, marked run 2
recovered with no health check made: no rollback, and a signed audit row saying ok. The verdict now comes from
the audit rows of the run's own checks, returned with that run's id."""

from __future__ import annotations

import asyncio
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio import activity
from temporalio.api.workflowservice.v1 import RespondActivityTaskCompletedRequest
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from test_remediation_workflow import REQ, FakePlatform, _until_awaiting_approval
from warden import approvals, audit, bounds, codec
from warden.activities import FixRequest, Plan, RemediationActivities
from warden.workflows import RemediationWorkflow

WID = "rem-orders"


def test_a_replayed_healthy_result_does_not_verify_a_fix():
    async def main():
        owner = Ed25519PrivateKey.generate()
        pem = owner.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=pem, tiers=["T1", "T2"])})
        log = audit.AuditLog(Path(tempfile.mkdtemp()) / "audit.db", key=Ed25519PrivateKey.generate())
        platform = FakePlatform(healthy_after=1)
        # Two runs on one target, back to back: about a replayed result, not the cool-down (register C8).
        acts = RemediationActivities(audit=log, policy=policy, platform=platform,
                                     limits=bounds.Limits(cooldown=timedelta(0)))
        every = [acts.resolve_plan, acts.gate, acts.check_approval, acts.precheck, acts.apply, acts.check_success,
                 acts.record_result, acts.rollback, acts.finish]
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env:
            ns, svc = env.client.namespace, env.client.workflow_service
            # Run 1: approved, applied, recovers. Its check_success result is "healthy".
            async with Worker(env.client, task_queue="q1", workflows=[RemediationWorkflow], activities=every,
                              activity_executor=ThreadPoolExecutor(4)):
                h = await env.client.start_workflow(RemediationWorkflow.run, FixRequest(**REQ), id=WID, task_queue="q1")
                plan = await _until_awaiting_approval(h)
                await h.signal(RemediationWorkflow.approve, approvals.sign(
                    owner, approver="owner", now=datetime.now(UTC), workflow_id=WID, plan_hash=plan.plan_hash,
                    tier=plan.tier))
                assert (await h.result()).status == "recovered"
            events = (await h.fetch_history()).events
            scheduled = {e.event_id: e.activity_task_scheduled_event_attributes.activity_type.name for e in events
                         if e.HasField("activity_task_scheduled_event_attributes")}
            healthy = next(e.activity_task_completed_event_attributes.result for e in events
                           if e.HasField("activity_task_completed_event_attributes")
                           and scheduled[e.activity_task_completed_event_attributes.scheduled_event_id] == "check_success")
            # Run 2: a new plan that never recovers. Its check_success is completed with run 1's result.
            platform.healthy_after, platform.checks = None, 0
            platform.state = {"revision": "9", "image": "orders:worse"}
            no_check = [m for m in every if m.__name__ != "check_success"]

            # The forger: run 2's check_success task is completed - through the server, with its task token - with
            # run 1's recorded "healthy" bytes, and no health check is made. Done from inside the task so it is the
            # only completion, whatever the timing: an outside poller raced the worker's own NotFound failures, and
            # with retries now bounded (audit A-B-L10) those ran out first in CI (2026-10-02).
            @activity.defn(name="check_success")
            async def forged(plan: Plan, service: str) -> bool:
                await svc.respond_activity_task_completed(RespondActivityTaskCompletedRequest(
                    namespace=ns, task_token=activity.info().task_token, result=healthy, identity="forger"))
                activity.raise_complete_async()

            async with Worker(env.client, task_queue="q2", workflows=[RemediationWorkflow],
                              activities=[*no_check, forged], activity_executor=ThreadPoolExecutor(4)):
                h2 = await env.client.start_workflow(RemediationWorkflow.run, FixRequest(**REQ), id=WID, task_queue="q2")
                plan2 = await _until_awaiting_approval(h2)
                await h2.signal(RemediationWorkflow.approve, approvals.sign(
                    owner, approver="owner", now=datetime.now(UTC), workflow_id=WID, plan_hash=plan2.plan_hash,
                    tier=plan2.tier))
                return await asyncio.wait_for(h2.result(), 120), platform, log

    out, platform, log = asyncio.run(main())
    assert out.status == "rolled_back" and not out.checklist.get("verified"), (out.status, out.checklist)
    assert platform.rolled_back, "the unverified change was not rolled back"
    results = [e["body"] for e in log.entries(kinds=("remediation.result",))]
    assert results[-1].get("ok") is False, results
    assert log.entries(kinds=("remediation.result_mismatch",)), "the forged claim left no trace"
