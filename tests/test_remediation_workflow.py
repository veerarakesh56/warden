"""RemediationWorkflow on Temporal's time-skipping test server, with a fake platform.

Every path is checked end to end: through the real workflow, the real activities, the real audit log
and real signatures. Only the platform being changed is fake.
"""

from __future__ import annotations

import asyncio
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Replayer, Worker

from warden import approvals, audit, bounds
from warden.activities import FixRequest, RemediationActivities
from warden.workflows import STEPS, RemediationWorkflow

QUEUE = "remediation-test"


class FakePlatform:
    def __init__(self, healthy_after=1):
        self.state = {"revision": "7", "image": "orders:bad"}
        self.applied, self.rolled_back = [], []
        self.checks = 0
        self.healthy_after = healthy_after  # None: never recovers
        self.drift_on_second_read = False
        self.reads = 0
        self.apply_error = None

    def live(self, entry, params):
        self.reads += 1
        if self.drift_on_second_read and self.reads == 2:
            self.state = {**self.state, "revision": "8"}
        return {"namespace": {"shop"}, "deployment": {"orders"}, "to_revision": {"6"}, "state": dict(self.state)}

    def apply(self, entry, params):
        if self.apply_error:
            raise RuntimeError(self.apply_error)
        self.applied.append((entry, params))
        return "rolled back to revision 6"

    def healthy(self, service):
        self.checks += 1
        return self.healthy_after is not None and self.checks >= self.healthy_after

    def rollback(self, entry, params, snapshot):
        self.rolled_back.append(snapshot)
        return f"restored revision {snapshot['revision']}"


@pytest.fixture
def owner():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def world(tmp_path, owner):
    pem = owner.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=pem, tiers=["T1", "T2"])})
    log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
    return {"log": log, "policy": policy, "platform": FakePlatform(), "db": tmp_path / "audit.db"}


REQ = {"incident_id": "inc-42", "entry": "k8s_rollout_undo", "service": "orders",
       "params": {"namespace": "shop", "deployment": "orders", "to_revision": "6"}}


def _run(world, drive, **req):
    """Start the workflow, let `drive(handle, sign)` interact with it, return the outcome."""
    async def main():
        env = await WorkflowEnvironment.start_time_skipping(data_converter=pydantic_data_converter)
        acts = RemediationActivities(audit=world["log"], policy=world["policy"], platform=world["platform"])
        methods = [acts.resolve_plan, acts.gate, acts.check_approval, acts.precheck, acts.apply,
                   acts.check_success, acts.record_result, acts.rollback, acts.finish]
        async with env, Worker(env.client, task_queue=QUEUE, workflows=[RemediationWorkflow], activities=methods,
                               activity_executor=ThreadPoolExecutor(4)):
            handle = await env.client.start_workflow(RemediationWorkflow.run, FixRequest(**{**REQ, **req}),
                                                     id=f"rem-{uuid.uuid4()}", task_queue=QUEUE)
            await drive(handle)
            outcome = await handle.result()
            world["history"] = await handle.fetch_history()
            return outcome
    return asyncio.run(main())


async def _until_awaiting_approval(handle):
    for _ in range(200):
        if await handle.query(RemediationWorkflow.stage) == "awaiting_approval":
            return await handle.query(RemediationWorkflow.plan)
        await asyncio.sleep(0.05)
    raise AssertionError("never reached awaiting_approval")


def _approve_with(key, approver="owner", tweak=None):
    async def drive(handle):
        plan = await _until_awaiting_approval(handle)
        fields = {"workflow_id": handle.id, "plan_hash": plan.plan_hash, "tier": plan.tier, **(tweak or {})}
        await handle.signal(RemediationWorkflow.approve,
                            approvals.sign(key, approver=approver, now=datetime.now(UTC), **fields))
    return drive


async def _no_approval(handle):
    pass


def test_an_approved_fix_is_applied_once_verified_and_fully_audited(world, owner):
    out = _run(world, _approve_with(owner))
    assert out.status == "recovered" and out.checklist == dict.fromkeys(STEPS, True)
    assert world["platform"].applied == [("k8s_rollout_undo", REQ["params"])]
    kinds = [e["kind"] for e in world["log"].entries("inc-42")]
    assert kinds == ["remediation.plan", "remediation.gate", "approval.accepted", "remediation.precheck",
                     "remediation.intent", bounds.APPLIED, bounds.RESULT, "workflow.end"]
    assert audit.verify(world["db"], world["log"].key.public_key()).unsigned_tail == 0


def test_without_an_approval_nothing_happens_and_it_expires(world):
    out = _run(world, _no_approval)
    assert out.status == "expired" and not out.checklist["approved"]
    assert world["platform"].applied == []


def test_a_forged_approval_is_refused_and_a_real_one_still_works(world, owner):
    async def drive(handle):
        await _approve_with(Ed25519PrivateKey.generate())(handle)  # someone else's key
        await _approve_with(owner)(handle)
    out = _run(world, drive)
    assert out.status == "recovered"
    refused = world["log"].entries("inc-42", kinds=("approval.refused",))
    assert refused[0]["body"]["problems"] == ["the signature is not owner's"]


def test_an_approval_of_a_different_plan_does_not_count(world, owner):
    out = _run(world, _approve_with(owner, tweak={"plan_hash": "0" * 64}))
    assert out.status == "expired"
    assert "approval is for a different plan (the plan changed after it was approved)" in out.reasons
    assert world["platform"].applied == []


def test_a_target_warden_did_not_read_is_refused_before_anything_else(world, owner):
    out = _run(world, _no_approval, params={**REQ["params"], "deployment": "payments; rm -rf /"})
    assert out.status == "refused" and not out.checklist["planned"]
    assert world["platform"].applied == []


def test_the_kill_switch_blocks_it(world, owner):
    bounds.trip(world["log"], "inc-0", "manual stop")
    out = _run(world, _no_approval)
    assert out.status == "blocked" and out.reasons == ["the kill switch is on: manual stop"]


def test_a_target_that_changed_after_approval_is_not_touched(world, owner):
    world["platform"].drift_on_second_read = True
    out = _run(world, _approve_with(owner))
    assert out.status == "drifted" and world["platform"].applied == []
    assert out.reasons == ["the target changed after the plan was made; it needs a new plan"]


def test_a_fix_that_does_not_recover_is_rolled_back(world, owner):
    world["platform"].healthy_after = None
    out = _run(world, _approve_with(owner))
    assert out.status == "rolled_back" and out.checklist["applied"] and not out.checklist["verified"]
    assert world["platform"].rolled_back == [{"revision": "7", "image": "orders:bad"}]
    assert world["log"].entries("inc-42", kinds=(bounds.RESULT,))[0]["body"]["ok"] is False


def test_a_failed_apply_is_not_retried_or_rolled_back_blindly(world, owner):
    world["platform"].apply_error = "API timeout"
    out = _run(world, _approve_with(owner))
    assert out.status == "apply_failed" and not out.checklist["applied"]
    assert world["platform"].rolled_back == []
    intents = world["log"].entries("inc-42", kinds=("remediation.intent",))
    assert len(intents) == 1  # maximum_attempts=1: tried once


def test_an_approver_limited_to_t1_cannot_approve_a_t2_fix(world, owner):
    world["policy"].approvers["owner"].tiers = ["T1"]
    out = _run(world, _approve_with(owner))
    assert out.status == "expired" and "owner may not approve T2" in out.reasons


def test_the_checklist_cannot_be_given_as_input():
    assert set(FixRequest.model_fields) == {"incident_id", "entry", "params", "service",
                                            "approval_ttl_minutes", "recover_within_minutes"}


def test_the_ttl_is_honoured(world, owner):
    async def late(handle):
        await _until_awaiting_approval(handle)
    out = _run(world, late, approval_ttl_minutes=1)
    assert out.status == "expired"
    assert (world["log"].entries("inc-42", kinds=("workflow.end",))[0]["at"]
            - world["log"].entries("inc-42", kinds=("remediation.plan",))[0]["at"]) < timedelta(minutes=5)


def test_a_recorded_history_replays_deterministically(world, owner):
    """The workflow code must make the same decisions when Temporal replays it after a worker restart."""
    _run(world, _approve_with(owner))
    asyncio.run(Replayer(workflows=[RemediationWorkflow], data_converter=pydantic_data_converter)
                .replay_workflow(world["history"]))
