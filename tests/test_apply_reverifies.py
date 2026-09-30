"""`apply` trusts nothing the workflow hands it: the plan must be one WARDEN made, and the approvals
must be in WARDEN's own audit log (second review, 2026-09-30: a forged or replayed activity result
could otherwise carry a workflow past the approval wait)."""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.exceptions import ApplicationError

from test_remediation_workflow import REQ, FakePlatform
from warden import approvals, audit
from warden.activities import FixRequest, RemediationActivities


def _acts():
    owner = Ed25519PrivateKey.generate()
    pem = owner.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=pem, tiers=["T1", "T2"])})
    log = audit.AuditLog(Path(tempfile.mkdtemp()) / "audit.db", key=Ed25519PrivateKey.generate())
    platform = FakePlatform(healthy_after=1)
    return RemediationActivities(audit=log, policy=policy, platform=platform), platform, owner


def _approve(acts, owner, plan, workflow_id):
    signed = approvals.sign(owner, approver="owner", now=datetime.now(UTC), workflow_id=workflow_id,
                            plan_hash=plan.plan_hash, tier=plan.tier)
    return acts.check_approval(plan, signed, [])


def test_apply_refuses_a_plan_nobody_approved():
    acts, platform, _ = _acts()
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    with pytest.raises(ApplicationError, match="approval"):
        acts.apply(plan, REQ["service"])
    assert platform.applied == []


def test_apply_refuses_a_plan_warden_never_made():
    acts, platform, owner = _acts()
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert _approve(acts, owner, plan, "rem-1").enough
    forged = plan.model_copy(update={"params": {**plan.params, "replicas": 99}, "plan_hash": "f" * 64})
    with pytest.raises(ApplicationError, match="plan"):
        acts.apply(forged, REQ["service"])
    other = plan.model_copy(update={"workflow_id": "rem-2"})
    with pytest.raises(ApplicationError):
        acts.apply(other, REQ["service"])
    assert platform.applied == []


def test_apply_proceeds_with_a_recorded_approval():
    acts, platform, owner = _acts()
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert _approve(acts, owner, plan, "rem-1").enough
    acts.apply(plan, REQ["service"])
    assert platform.applied


@pytest.mark.parametrize("change", [{"entry": "aurora_failover"}, {"params": {**REQ["params"], "to_revision": "1"}}],
                         ids=["entry", "params"])
def test_apply_refuses_a_plan_changed_under_its_approved_hash(change):
    """A forged Plan can keep the real, approved hash and change what would actually be done."""
    acts, platform, owner = _acts()
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert _approve(acts, owner, plan, "rem-1").enough
    with pytest.raises(ApplicationError, match="plan"):
        acts.apply(plan.model_copy(update=change), REQ["service"])
    assert platform.applied == []


def test_apply_refuses_a_plan_that_had_problems_even_if_approved():
    acts, platform, owner = _acts()
    plan = acts.resolve_plan(FixRequest(**{**REQ, "params": {"namespace": "shop", "deployment": "orders"}}), "rem-1")
    assert plan.problems
    _approve(acts, owner, plan, "rem-1")
    with pytest.raises(ApplicationError, match="plan"):
        acts.apply(plan, REQ["service"])
    assert platform.applied == []
