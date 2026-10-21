"""An approver may be limited to some environments (owner, 2026-10-15: the bench approver is dev only, T1/T2): a
signed approval for a plan anywhere else is refused, whatever its signature; an approver with no list keeps every one.
The bench approver - a test identity Claude holds - approves only in a nonprod-tier environment whatever its entry in
the approver list names, and its key is made only for one."""

from __future__ import annotations

import importlib.util
import pathlib
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import approvals
from warden.environments import default_environment_policies

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _policy(key, environments, name="bench", label=""):
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return approvals.ApproverPolicy(approvers={name: approvals.Approver(
        name=label, public_key=pem, tiers=["T1", "T2"], environments=environments)})


def _problems(policy, key, environment, tier="T1", name="bench"):
    now = datetime.now(UTC)
    a = approvals.sign(key, approver=name, workflow_id="rem-x", plan_hash="h", tier=tier, now=now)
    return approvals.check(a, policy=policy, workflow_id="rem-x", plan_hash="h", tier=tier,
                           plan_created_at=now - timedelta(hours=1), used_nonces=set(), now=now, environment=environment)


def _tiers():
    policies = default_environment_policies()
    by = {e: policies.for_env(e).tier for e in policies.known_environments}
    return [e for e, t in by.items() if t == "nonprod"], [e for e, t in by.items() if t == "prod"]


def test_a_dev_only_approver_approves_in_dev_and_nowhere_else():
    key = Ed25519PrivateKey.generate()
    policy = _policy(key, ["dev"])
    assert _problems(policy, key, "dev") == []
    for env in ("prod", "staging", ""):
        assert any("may not approve in" in p for p in _problems(policy, key, env)), env
    assert any("may not approve T3" in p for p in _problems(policy, key, "dev", tier="T3"))


def test_an_approver_with_no_list_keeps_every_environment():
    key = Ed25519PrivateKey.generate()
    assert _problems(_policy(key, [], name="alice"), key, "prod", name="alice") == []


def test_the_bench_approver_never_approves_outside_a_nonprod_environment_whatever_its_entry_says():
    nonprod, prod = _tiers()
    assert nonprod
    assert prod
    key = Ed25519PrivateKey.generate()
    # By its id, and by its label under another id: an entry naming production, or naming nothing, does not let it in.
    for name, label in (("bench", ""), ("claude-test", "bench approver (Claude), test")):
        for entry in ([*nonprod, *prod], []):
            policy = _policy(key, entry, name=name, label=label)
            for env in prod:
                assert any("bench approver" in p for p in _problems(policy, key, env, name=name)), (name, entry, env)
            assert _problems(policy, key, "", name=name), (name, entry)  # no environment named: never approved
            for env in nonprod:
                assert _problems(policy, key, env, name=name) == [], (name, entry, env)
    # The same rule on the passkey path and the signed deny path: one function decides for all three.
    bench = _policy(key, prod, name="bench").approvers["bench"]
    assert approvals.environment_refusal("bench", bench, prod[0])
    for src in ("activities.py", "approval_page.py"):
        assert "approvals.environment_refusal(" in (ROOT / "warden" / "src" / "warden" / src).read_text(encoding="utf-8"), src


def test_the_bench_key_is_made_only_for_a_nonprod_environment(tmp_path, monkeypatch):
    nonprod, prod = _tiers()
    spec = importlib.util.spec_from_file_location("bench_approve", ROOT / "fault-lab" / "scripts" / "bench_approve.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    folder = tmp_path / "k"
    monkeypatch.setenv("WARDEN_BENCH_KEY_DIR", str(folder))
    monkeypatch.setenv("WARDEN_BENCH_KEY_PASSPHRASE", "bench pass")
    for env in [*prod, "", "no-such-env"]:
        with pytest.raises(SystemExit, match="nonprod environment only"):
            mod.new_key(env)
        assert not (folder / mod.KEY_NAME).exists(), env
    assert "bench" in mod.new_key(nonprod[0])
