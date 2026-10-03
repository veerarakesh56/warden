"""Audit A-P-2: approver decisions fed back as labels. A label is an approver's signed verdict on a diagnosis and its
action, recorded only when their signature verifies - calibration (G7) must not learn from a planted one."""

from __future__ import annotations

import pathlib
from datetime import UTC, datetime

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import approvals, audit, labels
from warden.cli import main


def _pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


@pytest.fixture
def setup(tmp_path):
    owner = Ed25519PrivateKey.generate()
    policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=_pem(owner), tiers=["T1"])})
    return owner, policy, audit.AuditLog(tmp_path / "a.db")


def test_a_signed_label_is_recorded_and_exported_for_calibration(setup):
    owner, policy, log = setup
    label = labels.sign(owner, incident_id="inc-7", approver="owner", diagnosis="right", action="wrong",
                        note="the rollback target was the wrong revision")
    assert labels.record(log, label, policy) == []
    [row] = labels.export(log)
    assert (row["incident_id"], row["diagnosis"], row["action"]) == ("inc-7", "right", "wrong")


def test_a_planted_or_altered_label_is_refused(setup):
    owner, policy, log = setup
    stranger = labels.sign(Ed25519PrivateKey.generate(), incident_id="inc-7", approver="owner", diagnosis="right",
                           action="right")
    assert labels.record(log, stranger, policy) == ["the signature is not owner's"]
    real = labels.sign(owner, incident_id="inc-7", approver="owner", diagnosis="wrong", action="wrong")
    altered = real.model_copy(update={"action": "right"})  # "teach" it the action was right
    assert labels.record(log, altered, policy) == ["the signature is not owner's"]
    nobody = labels.sign(owner, incident_id="inc-7", approver="mallory", diagnosis="right", action="right")
    assert labels.record(log, nobody, policy) == ["'mallory' is not an approver"]
    assert labels.export(log) == []


def test_a_label_signature_never_passes_as_an_approval(setup):
    owner, policy, _ = setup
    label = labels.sign(owner, incident_id="inc-7", approver="owner", diagnosis="right", action="right")
    now = datetime.now(UTC)
    forged = approvals.SignedApproval(approver="owner", workflow_id="inc-7", plan_hash="h", tier="T1",
                                      issued_at=now, expires_at=now, nonce="n", signature=label.signature)
    problems = approvals.check(forged, policy=policy, workflow_id="inc-7", plan_hash="h", tier="T1",
                               plan_created_at=now, used_nonces=set(), now=now)
    assert problems == ["the signature is not owner's"]


def test_the_command_records_a_label_and_refuses_a_wrong_key(tmp_path, monkeypatch, capsys):
    owner = Ed25519PrivateKey.generate()
    key_file = tmp_path / "owner.pem"
    key_file.write_bytes(owner.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
    other_file = tmp_path / "other.pem"
    other_file.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    audit.generate_key(tmp_path / "audit.pem", tmp_path / "audit.pub")
    (tmp_path / "approvers.yaml").write_text(yaml.safe_dump(
        {"approvers": {"owner": {"public_key": _pem(owner), "tiers": ["T1"]}}}), encoding="utf-8")
    for name, value in {"WARDEN_APPROVERS": "approvers.yaml", "WARDEN_AUDIT_DB": "audit.db",
                        "WARDEN_AUDIT_KEY": "audit.pem"}.items():
        monkeypatch.setenv(name, str(tmp_path / value))
    monkeypatch.delenv("WARDEN_ENV", raising=False)
    args = ["label", "inc-7", "--diagnosis", "right", "--action", "unsure", "--approver", "owner"]
    assert main([*args, "--key", str(key_file)]) == 0
    assert main([*args, "--key", str(other_file)]) == 1
    rows = labels.export(audit.AuditLog(pathlib.Path(tmp_path / "audit.db")))
    assert len(rows) == 1 and rows[0]["action"] == "unsure"
    assert "label not recorded" in capsys.readouterr().err
