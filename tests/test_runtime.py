"""runtime.approve: signs only the plan the approver reviewed, and only while one is awaited."""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.testing import WorkflowEnvironment

from test_remediation_workflow import REQ, FakePlatform
from warden import approvals, audit, codec, runtime
from warden.activities import FixRequest
from warden.workflows import RemediationWorkflow

KEY = os.urandom(32)


@pytest.fixture
def setup(tmp_path):
    owner = Ed25519PrivateKey.generate()
    pem = owner.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=pem, tiers=["T2"])})
    log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
    return owner, policy, log


def _session(setup, platform, drive):
    owner, policy, log = setup

    async def main():
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(KEY))
        async with env, runtime.worker(env.client, log=log, policy=policy, platform=platform):
            wid = f"rem-{uuid.uuid4()}"
            handle = await env.client.start_workflow(RemediationWorkflow.run, FixRequest(**REQ), id=wid,
                                                     task_queue=runtime.TASK_QUEUE)
            for _ in range(200):
                if (await runtime.status(env.client, wid))[0] != "planning":
                    break
                await asyncio.sleep(0.05)
            await drive(env.client, wid, owner)
            return await handle.result()
    return asyncio.run(main())


def test_approving_the_reviewed_plan_completes_the_fix(setup):
    async def drive(client, wid, owner):
        stage, plan = await runtime.status(client, wid)
        assert stage == "awaiting_approval" and plan.entry == "k8s_rollout_undo"
        await runtime.approve(client, wid, plan_hash=plan.plan_hash, key=owner, approver="owner")
    assert _session(setup, FakePlatform(), drive).status == "recovered"


def test_a_hash_that_is_not_the_current_plan_sends_nothing(setup):
    async def drive(client, wid, owner):
        with pytest.raises(ValueError, match="not the one you reviewed"):
            await runtime.approve(client, wid, plan_hash="0" * 64, key=owner, approver="owner")
    platform = FakePlatform()
    out = _session(setup, platform, drive)
    assert out.status == "expired" and platform.applied == []
    assert setup[2].entries(kinds=("approval.refused", "approval.accepted")) == []  # no signal was sent


def test_without_a_platform_every_fix_is_refused_at_planning(setup):
    async def drive(client, wid, owner):
        stage, plan = await runtime.status(client, wid)
        assert stage == "refused"
        with pytest.raises(ValueError, match="not waiting for an approval"):
            await runtime.approve(client, wid, plan_hash=plan.plan_hash, key=owner, approver="owner")
    assert _session(setup, None, drive).status == "refused"


def test_killswitch_cli_on_status_and_a_signed_reset(tmp_path, monkeypatch, capsys):
    from warden import cli

    owner = Ed25519PrivateKey.generate()
    (tmp_path / "owner.pem").write_bytes(owner.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pub = owner.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    approvers = tmp_path / "approvers.yaml"

    def policy(cooling):
        approvers.write_text("approvers:\n  owner:\n    tiers: [T3]\n    public_key: |\n"
                             + "".join(f"      {line}\n" for line in pub.splitlines())
                             + f"cooling_off_minutes:\n  T3: {cooling}\n", encoding="utf-8")
    audit.generate_key(tmp_path / "audit.pem", tmp_path / "audit.pub")
    monkeypatch.setenv("WARDEN_AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("WARDEN_AUDIT_KEY", str(tmp_path / "audit.pem"))
    monkeypatch.setenv("WARDEN_APPROVERS", str(approvers))
    monkeypatch.delenv("WARDEN_AUDIT_KEY_PASSPHRASE", raising=False)
    monkeypatch.delenv("WARDEN_APPROVER_KEY_PASSPHRASE", raising=False)
    reset = ["killswitch", "reset", "--approver", "owner", "--key", str(tmp_path / "owner.pem")]

    assert cli.main(["killswitch", "on", "--reason", "drill"]) == 0
    out = capsys.readouterr().out
    assert "kill switch: ON (1 trip since the last reset)" in out and "  - drill" in out
    policy(10)
    assert cli.main(reset) == 1  # the cooling-off applies to a reset too
    assert "T3 needs the plan to exist for 0:10:00" in capsys.readouterr().out
    policy(0)
    assert cli.main(reset) == 0 and "kill switch: off" in capsys.readouterr().out
    assert audit.verify(tmp_path / "audit.db", audit.load_public_key(tmp_path / "audit.pub")).ok
