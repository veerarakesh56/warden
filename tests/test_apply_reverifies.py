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
    assert acts.precheck(plan) == []
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



def _ready(acts, owner):
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert _approve(acts, owner, plan, "rem-1").enough
    return plan


def test_apply_needs_a_clean_precheck_of_this_plan_after_the_approval():
    """Third review (2026-09-30): a precheck result replayed from another slot skipped the drift check;
    apply never looked. Now it needs WARDEN's own clean precheck row, after the approvals."""
    acts, platform, owner = _acts()
    plan = _ready(acts, owner)
    with pytest.raises(ApplicationError, match="precheck"):
        acts.apply(plan, REQ["service"])
    platform.state["revision"] = "99"  # the target drifted: the precheck row records problems
    assert acts.precheck(plan)
    with pytest.raises(ApplicationError, match="precheck"):
        acts.apply(plan, REQ["service"])
    assert platform.applied == []


def test_a_kill_switch_tripped_while_waiting_for_approval_stops_the_apply():
    """Third review: the gate ran once, before the approval wait (up to its TTL); a kill switch tripped
    during the wait did not stop the apply. No attacker needed."""
    from warden import bounds

    acts, platform, owner = _acts()
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert acts.gate(plan, REQ["service"]) == []
    bounds.trip(acts.audit, "owner", "owner: stop everything")
    assert _approve(acts, owner, plan, "rem-1").enough
    assert acts.precheck(plan) == []
    with pytest.raises(ApplicationError, match="kill switch"):
        acts.apply(plan, REQ["service"])
    assert platform.applied == []


def test_rows_of_another_run_of_the_same_workflow_do_not_count(monkeypatch):
    """Third review: `rem-<service>` is reused, and a replay of run 1's approval and results into run 2
    applied with nobody approving run 2. Every row now carries the Temporal run id."""
    from warden import activities

    acts, platform, owner = _acts()
    monkeypatch.setattr(activities, "_run_id", lambda: "run-1")
    plan = _ready(acts, owner)
    assert acts.precheck(plan) == []
    monkeypatch.setattr(activities, "_run_id", lambda: "run-2")
    with pytest.raises(ApplicationError):
        acts.apply(plan, REQ["service"])
    assert platform.applied == []
