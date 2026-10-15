"""An approver may be limited to some environments (owner, 2026-10-15: the bench approver is dev only, T1/T2): a
signed approval for a plan anywhere else is refused, whatever its signature; an approver with no list keeps every one."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import approvals


def _policy(key, environments):
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return approvals.ApproverPolicy(approvers={"bench": approvals.Approver(
        public_key=pem, tiers=["T1", "T2"], environments=environments)})


def _problems(policy, key, environment, tier="T1"):
    now = datetime.now(UTC)
    a = approvals.sign(key, approver="bench", workflow_id="rem-x", plan_hash="h", tier=tier, now=now)
    return approvals.check(a, policy=policy, workflow_id="rem-x", plan_hash="h", tier=tier,
                           plan_created_at=now - timedelta(hours=1), used_nonces=set(), now=now, environment=environment)


def test_a_dev_only_approver_approves_in_dev_and_nowhere_else():
    key = Ed25519PrivateKey.generate()
    policy = _policy(key, ["dev"])
    assert _problems(policy, key, "dev") == []
    for env in ("prod", "staging", ""):
        assert any("may not approve in" in p for p in _problems(policy, key, env)), env
    assert any("may not approve T3" in p for p in _problems(policy, key, "dev", tier="T3"))


def test_an_approver_with_no_list_keeps_every_environment():
    key = Ed25519PrivateKey.generate()
    assert _problems(_policy(key, []), key, "prod") == []
