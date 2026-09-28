"""Signed approvals: exactly one plan of exactly one workflow, by an allowed approver, in time, once."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import approvals

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
PLAN_AT = NOW - timedelta(minutes=30)


def _pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


@pytest.fixture
def owner():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def policy(owner):
    return approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=_pem(owner),
                                                                           tiers=["T1", "T2", "T3"])})


def _sign(key, approver="owner", tier="T2", now=NOW, **kw):
    fields = {"workflow_id": "rem-fn-a", "plan_hash": "p" * 64, **kw}
    return approvals.sign(key, approver=approver, tier=tier, now=now, **fields)


def _check(approval, policy, tier="T2", used=None, now=NOW, plan_at=PLAN_AT):
    return approvals.check(approval, policy=policy, workflow_id="rem-fn-a", plan_hash="p" * 64, tier=tier,
                           plan_created_at=plan_at, used_nonces=used or set(), now=now)


def test_a_correct_approval_passes(owner, policy):
    assert _check(_sign(owner), policy) == []


@pytest.mark.parametrize("change,expected", [
    ({"workflow_id": "rem-other"}, "approval is for a different workflow"),
    ({"plan_hash": "q" * 64}, "approval is for a different plan (the plan changed after it was approved)"),
])
def test_an_approval_for_something_else_is_refused(owner, policy, change, expected):
    assert expected in _check(_sign(owner, **change), policy)


def test_a_forged_signature_is_refused(owner, policy):
    approval = _sign(Ed25519PrivateKey.generate())  # signed with a key that is not the owner's
    assert _check(approval, policy) == ["the signature is not owner's"]


def test_editing_a_signed_approval_breaks_the_signature(owner, policy):
    approval = _sign(owner)
    approval.plan_hash = "q" * 64
    assert _check(approval, policy) == ["the signature is not owner's"]


def test_someone_not_on_the_allowlist_cannot_approve(policy):
    stranger = Ed25519PrivateKey.generate()
    assert _check(_sign(stranger, approver="mallory"), policy) == ["'mallory' is not an approver"]


def test_an_approver_can_only_approve_their_tiers(owner):
    limited = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=_pem(owner), tiers=["T1"])})
    assert "owner may not approve T2" in _check(_sign(owner), limited)


def test_a_t2_approval_does_not_approve_a_t3_plan(owner, policy):
    problems = _check(_sign(owner, tier="T2"), policy, tier="T3")
    assert "approval is for T2, the plan is T3" in problems


def test_an_expired_or_future_approval_is_refused(owner, policy):
    assert "approval has expired" in _check(_sign(owner), policy, now=NOW + timedelta(hours=1))
    assert "approval is issued in the future" in _check(_sign(owner, now=NOW + timedelta(minutes=5)), policy)


def test_the_validity_is_capped(owner, policy):
    approval = approvals.sign(owner, approver="owner", workflow_id="rem-fn-a", plan_hash="p" * 64, tier="T2",
                              ttl=timedelta(days=30), now=NOW)
    assert approval.expires_at - approval.issued_at == approvals.MAX_TTL
    forged_long = _sign(owner)
    forged_long.expires_at = NOW + timedelta(days=30)
    forged_long.signature = owner.sign(forged_long.message()).hex()  # even the owner's own key
    assert "approval is valid for longer than allowed" in _check(forged_long, policy)


def test_an_approval_works_once(owner, policy):
    approval = _sign(owner)
    assert "approval was already used" in _check(approval, policy, used={approval.nonce})


def test_t3_needs_the_plan_to_have_existed_for_the_cooling_off_time(owner, policy):
    rushed = _check(_sign(owner, tier="T3"), policy, tier="T3", plan_at=NOW - timedelta(minutes=2))
    assert "T3 needs the plan to exist for 0:10:00 before it is approved" in rushed
    assert _check(_sign(owner, tier="T3"), policy, tier="T3", plan_at=NOW - timedelta(minutes=11)) == []


def test_two_person_rule_counts_different_approvers_only(owner, policy):
    second = Ed25519PrivateKey.generate()
    policy.approvers["sre"] = approvals.Approver(public_key=_pem(second), tiers=["T3"])
    policy.required["T3"] = 2
    a, b = _sign(owner, tier="T3"), _sign(second, approver="sre", tier="T3")
    assert not approvals.enough([a, _sign(owner, tier="T3")], "T3", policy)  # the same person twice
    assert approvals.enough([a, b], "T3", policy)


def test_an_unknown_tier_cannot_be_signed(owner):
    with pytest.raises(ValueError):
        _sign(owner, tier="T9")


def test_the_policy_loads_from_yaml(owner, tmp_path):
    path = tmp_path / "approvers.yaml"
    path.write_text("approvers:\n  owner:\n    tiers: [T1, T2]\n    public_key: |\n"
                    + "".join(f"      {line}\n" for line in _pem(owner).splitlines()), encoding="utf-8")
    policy = approvals.ApproverPolicy.load(path)
    assert policy.required == {"T1": 1, "T2": 1, "T3": 1} and policy.cooling_off_minutes == {"T3": 10}
    assert _check(_sign(owner), policy) == []
