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
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.client import Client
from temporalio.converter import DataConverter
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
