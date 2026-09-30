"""A plain (unencrypted) Temporal message must neither reach the workflow as data nor stall it.

Independent review, 2026-09-28: when the codec RAISED on a plain payload, one plain signal - any
name, sent by anyone with signal permission on the namespace, e.g. the web UI's "Send signal" - failed
every workflow task of a RemediationWorkflow that had already applied a change. The success check,
the rollback and the final audit row never ran.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.client import Client
from temporalio.converter import DataConverter
from temporalio.service import RPCError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from test_remediation_workflow import REQ, FakePlatform, _until_awaiting_approval
from warden import approvals, audit, codec
from warden.activities import FixRequest, RemediationActivities
from warden.workflows import RemediationWorkflow


def test_a_plain_signal_after_apply_does_not_stop_the_rollback():
    async def main():
        owner = Ed25519PrivateKey.generate()
        pem = owner.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=pem, tiers=["T1", "T2"])})
        log = audit.AuditLog(Path(tempfile.mkdtemp()) / "audit.db", key=Ed25519PrivateKey.generate())
        platform = FakePlatform(healthy_after=None)  # never recovers: the workflow must roll back
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        acts = RemediationActivities(audit=log, policy=policy, platform=platform)
        methods = [acts.resolve_plan, acts.gate, acts.check_approval, acts.precheck, acts.apply,
                   acts.check_success, acts.record_result, acts.rollback, acts.finish]
        async with env, Worker(env.client, task_queue="plain", workflows=[RemediationWorkflow],
                               activities=methods, activity_executor=ThreadPoolExecutor(4)):
            h = await env.client.start_workflow(RemediationWorkflow.run, FixRequest(**REQ),
                                                id=f"rem-{uuid.uuid4()}", task_queue="plain")
            plan = await _until_awaiting_approval(h)
            await h.signal(RemediationWorkflow.approve, approvals.sign(
                owner, approver="owner", now=datetime.now(UTC), workflow_id=h.id,
                plan_hash=plan.plan_hash, tier=plan.tier))
            for _ in range(200):
                if platform.applied:
                    break
                await asyncio.sleep(0.05)
            assert platform.applied
            keyless = Client(env.client.service_client, namespace=env.client.namespace,
                             data_converter=DataConverter.default)
            await keyless.get_workflow_handle(h.id).signal("anything", {"hello": 1})
            await keyless.get_workflow_handle(h.id).signal(RemediationWorkflow.approve, {"forged": True})
            out = await asyncio.wait_for(h.result(), 60)
            return out, platform

    out, platform = asyncio.run(main())
    assert out.status == "rolled_back" and platform.rolled_back



def _policy_and_owner():
    owner = Ed25519PrivateKey.generate()
    pem = owner.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=pem, tiers=["T1", "T2"])}), owner


def _world(policy, healthy_after=1):
    log = audit.AuditLog(Path(tempfile.mkdtemp()) / "audit.db", key=Ed25519PrivateKey.generate())
    platform = FakePlatform(healthy_after=healthy_after)
    a = RemediationActivities(audit=log, policy=policy, platform=platform)
    return platform, [a.resolve_plan, a.gate, a.check_approval, a.precheck, a.apply, a.check_success,
                      a.record_result, a.rollback, a.finish]


def test_a_forged_ciphertext_signal_after_apply_does_not_stop_the_rollback():
    """Second review (2026-09-30): the key id is plain metadata, so a keyless sender could mark
    random bytes "encrypted"; the codec raised, and the workflow stalled after it had applied."""
    from temporalio.api.common.v1 import Payload, Payloads, WorkflowExecution
    from temporalio.api.workflowservice.v1 import SignalWorkflowExecutionRequest

    async def main():
        policy, owner = _policy_and_owner()
        platform, methods = _world(policy, healthy_after=None)
        conv = codec.data_converter(os.urandom(32))
        env = await WorkflowEnvironment.start_time_skipping(data_converter=conv)
        async with env, Worker(env.client, task_queue="forge", workflows=[RemediationWorkflow],
                               activities=methods, activity_executor=ThreadPoolExecutor(4)):
            h = await env.client.start_workflow(RemediationWorkflow.run, FixRequest(**REQ),
                                                id=f"rem-{uuid.uuid4()}", task_queue="forge")
            plan = await _until_awaiting_approval(h)
            await h.signal(RemediationWorkflow.approve, approvals.sign(
                owner, approver="owner", now=datetime.now(UTC), workflow_id=h.id,
                plan_hash=plan.plan_hash, tier=plan.tier))
            for _ in range(200):
                if platform.applied:
                    break
                await asyncio.sleep(0.05)
            assert platform.applied
            forged = Payload(metadata={"encoding": codec.ENCODING,
                                       "encryption-key-id": conv.payload_codec.key_id}, data=os.urandom(64))
            await env.client.workflow_service.signal_workflow_execution(SignalWorkflowExecutionRequest(
                namespace=env.client.namespace, workflow_execution=WorkflowExecution(workflow_id=h.id),
                signal_name="approve", input=Payloads(payloads=[forged]), identity="forger"))
            return await asyncio.wait_for(h.result(), 60), platform

    out, platform = asyncio.run(main())
    assert out.status == "rolled_back" and platform.rolled_back


def test_a_replayed_approval_does_not_apply_another_workflow():
    """Second review (2026-09-30), the reviewer's attack: A is approved properly; A's encrypted
    approve signal is replayed into B, and B's check_approval task is completed with A's recorded
    encrypted result. Nobody signed anything for B, and B must not apply."""
    from temporalio.api.common.v1 import WorkflowExecution
    from temporalio.api.taskqueue.v1 import TaskQueue
    from temporalio.api.workflowservice.v1 import (
        PollActivityTaskQueueRequest,
        RespondActivityTaskCompletedRequest,
        SignalWorkflowExecutionRequest,
    )

    async def main():
        policy, owner = _policy_and_owner()
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env:
            ns, svc = env.client.namespace, env.client.workflow_service
            _, methods_a = _world(policy)
            async with Worker(env.client, task_queue="qa", workflows=[RemediationWorkflow], activities=methods_a,
                              activity_executor=ThreadPoolExecutor(4)):
                ha = await env.client.start_workflow(RemediationWorkflow.run, FixRequest(**REQ),
                                                     id=f"rem-A-{uuid.uuid4()}", task_queue="qa")
                plan = await _until_awaiting_approval(ha)
                await ha.signal(RemediationWorkflow.approve, approvals.sign(
                    owner, approver="owner", now=datetime.now(UTC), workflow_id=ha.id,
                    plan_hash=plan.plan_hash, tier=plan.tier))
                await ha.result()
            events = (await ha.fetch_history()).events
            signal = next(e.workflow_execution_signaled_event_attributes.input for e in events
                          if e.HasField("workflow_execution_signaled_event_attributes"))
            kinds = {e.event_id: e.activity_task_scheduled_event_attributes.activity_type.name for e in events
                     if e.HasField("activity_task_scheduled_event_attributes")}
            result = next(e.activity_task_completed_event_attributes.result for e in events
                          if e.HasField("activity_task_completed_event_attributes")
                          and kinds[e.activity_task_completed_event_attributes.scheduled_event_id] == "check_approval")
            platform_b, methods_b = _world(policy)
            without_check = [m for m in methods_b if m.__name__ != "check_approval"]
            async with Worker(env.client, task_queue="qb", workflows=[RemediationWorkflow], activities=without_check,
                              activity_executor=ThreadPoolExecutor(4)):
                hb = await env.client.start_workflow(RemediationWorkflow.run, FixRequest(**REQ),
                                                     id=f"rem-B-{uuid.uuid4()}", task_queue="qb")
                await _until_awaiting_approval(hb)
                await svc.signal_workflow_execution(SignalWorkflowExecutionRequest(
                    namespace=ns, workflow_execution=WorkflowExecution(workflow_id=hb.id), signal_name="approve",
                    input=signal, identity="replayer"))
                for _ in range(5):
                    try:  # the replayed signal is refused, so there may be no check_approval task at all
                        task = await svc.poll_activity_task_queue(PollActivityTaskQueueRequest(
                            namespace=ns, task_queue=TaskQueue(name="qb"), identity="replayer"),
                            timeout=timedelta(seconds=2))
                    except RPCError:
                        continue
                    if task.task_token and task.activity_type.name == "check_approval":
                        await svc.respond_activity_task_completed(RespondActivityTaskCompletedRequest(
                            namespace=ns, task_token=task.task_token, result=result, identity="replayer"))
                        break
                await asyncio.sleep(3)
                applied = list(platform_b.applied)
                await hb.terminate("test over")
            return applied

    assert asyncio.run(main()) == []
