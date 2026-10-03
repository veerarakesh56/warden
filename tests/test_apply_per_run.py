"""Apply bookkeeping is per run, and the signed end row states what the audit shows (fourth review,
2026-09-30, B-N6 and B-N9)."""

from __future__ import annotations

import asyncio
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from test_remediation_workflow import REQ, FakePlatform, _until_awaiting_approval
from warden import approvals, audit, bounds, codec
from warden.activities import FixOutcome, FixRequest, RemediationActivities
from warden.workflows import RemediationWorkflow

WID = "rem-orders"


def _world(platform):
    owner = Ed25519PrivateKey.generate()
    pem = owner.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=pem, tiers=["T1", "T2"])})
    log = audit.AuditLog(Path(tempfile.mkdtemp()) / "audit.db", key=Ed25519PrivateKey.generate())
    # About scoping a plan to its run, not the cool-down (register C8, which would hold the second run for 30 min).
    return owner, log, RemediationActivities(audit=log, policy=policy, platform=platform,
                                             limits=bounds.Limits(cooldown=timedelta(0)))


def _every(a):
    return [a.resolve_plan, a.gate, a.check_approval, a.precheck, a.apply, a.check_success, a.record_result,
            a.rollback, a.finish]


async def _run_once(env, owner, acts):
    async with Worker(env.client, task_queue="q", workflows=[RemediationWorkflow], activities=_every(acts),
                      activity_executor=ThreadPoolExecutor(4)):
        h = await env.client.start_workflow(RemediationWorkflow.run, FixRequest(**REQ), id=WID, task_queue="q")
        plan = await _until_awaiting_approval(h)
        await h.signal(RemediationWorkflow.approve, approvals.sign(
            owner, approver="owner", now=datetime.now(UTC), workflow_id=WID, plan_hash=plan.plan_hash, tier=plan.tier))
        return await h.result()


def test_a_second_approved_run_of_the_same_plan_really_applies():
    """Run 1 applies, does not recover and rolls back to the same state, so run 2 plans the same hash.
    'Already applied' was checked across runs: run 2 applied nothing, then rolled back a change it never
    made, and the two 'failures' tripped the kill switch."""
    platform = FakePlatform(healthy_after=None)
    owner, _log, acts = _world(platform)

    async def main():
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env:
            return [await _run_once(env, owner, acts) for _ in range(2)]

    outs = asyncio.run(main())
    assert [o.status for o in outs] == ["rolled_back", "rolled_back"], [o.status for o in outs]
    assert len(platform.applied) == 2 and len(platform.rolled_back) == 2, (platform.applied, platform.rolled_back)


def test_a_refused_apply_says_nothing_was_changed(monkeypatch):
    """A refused apply was reported as 'apply_failed ... may be half-made' with approved and prechecked True.
    It is its own outcome now: nothing was applied or rolled back."""
    platform = FakePlatform(healthy_after=1)
    owner, _log, acts = _world(platform)
    monkeypatch.setattr(RemediationActivities, "_not_approved", lambda self, plan, service: ["refused for the test"])

    async def main():
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env:
            return await _run_once(env, owner, acts)

    out = asyncio.run(main())
    assert out.status == "refused_at_apply", out.status
    assert platform.applied == [] and platform.rolled_back == []


def test_the_signed_end_row_states_what_the_audit_shows():
    """The end row's checklist is taken from the run's audit rows; a claim the audit does not back is kept
    only as `claimed_checklist`."""
    platform = FakePlatform(healthy_after=1)
    _, log, acts = _world(platform)
    claimed = FixOutcome(status="recovered", checklist={"planned": True, "policy": True, "approved": True,
                                                        "prechecked": True, "applied": True, "verified": True},
                         plan_hash="h")
    acts.finish("inc-42", WID, claimed)
    row = log.entries("inc-42", kinds=("workflow.end",))[-1]["body"]
    assert row["checklist"]["approved"] is False and row["checklist"]["applied"] is False
    assert row["checklist"]["verified"] is False and row["claimed_checklist"]["approved"] is True


def test_one_signature_of_a_two_person_tier_is_not_recorded_as_approved():
    """Fifth review (2026-10-01): the signed end row said `approved: True` when one of two required approvers
    had signed and the run expired."""
    platform = FakePlatform(healthy_after=1)
    owner, log, acts = _world(platform)
    acts.policy.required["T2"] = 2

    async def main():
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env:
            return await _run_once(env, owner, acts)

    out = asyncio.run(main())
    assert out.status != "recovered" and platform.applied == [], out.status
    row = log.entries("inc-42", kinds=("workflow.end",))[-1]["body"]
    assert row["checklist"]["approved"] is False, row["checklist"]


def test_a_success_needs_this_runs_apply():
    """Fifth review (2026-10-01): a replayed apply result let a run with nothing applied record a healthy check
    as a success. With no APPLIED row of this run, the result is not ok."""
    platform = FakePlatform(healthy_after=1)
    _, log, acts = _world(platform)
    plan = acts.resolve_plan(FixRequest(**REQ), WID)
    assert acts.check_success(plan, "orders") is True   # the service IS healthy...
    recorded = acts.record_result(plan, "orders", True)
    assert recorded.ok is False                         # ...but this run applied nothing
    assert log.entries("inc-42", kinds=("remediation.result_mismatch",))
