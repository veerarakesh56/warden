"""Register S12: whoever holds the audit key and the database can rewrite and re-sign the history - but not the KMS
key, and not the anchors written out of reach. Both are proven here against that exact attack."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import audit


class _FakeKms:
    """KMS Sign / GetPublicKey for one ECC_NIST_EDWARDS25519 key that never leaves it."""

    def __init__(self):
        self._key, self.calls = Ed25519PrivateKey.generate(), []

    def sign(self, *, KeyId, Message, MessageType, SigningAlgorithm):
        self.calls.append((KeyId, MessageType, SigningAlgorithm))
        return {"Signature": self._key.sign(Message)}

    def get_public_key(self, *, KeyId):
        return {"PublicKey": self._key.public_key().public_bytes(serialization.Encoding.DER,
                                                                 serialization.PublicFormat.SubjectPublicKeyInfo)}


class _FakeAnchors:
    """An Object Lock bucket in compliance mode: a key once written cannot be overwritten."""

    def __init__(self):
        self.objects, self.puts = {}, []

    def put_object(self, *, Bucket, Key, Body, ObjectLockMode, ObjectLockRetainUntilDate, ChecksumAlgorithm):
        assert ObjectLockMode == "COMPLIANCE" and ObjectLockRetainUntilDate > datetime.now(UTC)
        assert Key not in self.objects, "an object under Object Lock cannot be overwritten"
        self.objects[Key] = Body
        self.puts.append(Key)

    def get_paginator(self, op):
        assert op == "list_objects_v2"
        return self

    def paginate(self, *, Bucket, Prefix):
        yield {"Contents": [{"Key": k} for k in sorted(self.objects) if k.startswith(Prefix)]}

    def get_object(self, *, Bucket, Key):
        import io

        return {"Body": io.BytesIO(self.objects[Key])}


def _log(key, anchor_client=None):
    db = Path(tempfile.mkdtemp()) / "audit.db"
    anchor = audit.S3Anchor("anchors-bucket", anchor_client, retain=timedelta(days=1)) if anchor_client else None
    return db, audit.AuditLog(db, key=key, anchor=anchor)


def _rewrite_and_resign(db, key):
    """The attack: drop the append-only triggers, change row 1, re-chain every hash, re-sign every checkpoint."""
    con = sqlite3.connect(db)
    for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'").fetchall():
        con.execute(f"DROP TRIGGER {name}")
    con.execute("UPDATE entries SET body = ? WHERE seq = 1", (json.dumps({"approved_by": "attacker"}),))
    prev = audit.GENESIS
    for seq, at, cid, kind, body in con.execute("SELECT seq, at, correlation_id, kind, body FROM entries ORDER BY seq"):
        digest = audit._hash(prev, seq, at, cid, kind, body)
        con.execute("UPDATE entries SET prev = ?, hash = ? WHERE seq = ?", (prev, digest, seq))
        prev = digest
    for seq, in con.execute("SELECT seq FROM checkpoints").fetchall():
        head = con.execute("SELECT hash FROM entries WHERE seq = ?", (seq,)).fetchone()[0]
        con.execute("UPDATE checkpoints SET hash = ?, signature = ? WHERE seq = ?",
                    (head, key.sign(audit._signed_message(seq, head)).hex(), seq))
    con.commit()
    con.close()


def test_a_history_rewritten_and_re_signed_with_the_key_is_caught_by_its_anchors():
    key, bucket = Ed25519PrivateKey.generate(), _FakeAnchors()
    db, log = _log(key, bucket)
    for i in range(3):
        log.append("inc-1", "step", {"i": i})
    log.checkpoint()
    log.close()
    anchors = audit.S3Anchor("anchors-bucket", bucket).all()
    assert audit.verify(db, key.public_key(), anchors).ok
    _rewrite_and_resign(db, key)
    assert audit.verify(db, key.public_key()).ok, "with the key alone, the rewrite is invisible - why anchors exist"
    found = audit.verify(db, key.public_key(), anchors).problems
    assert any("differs from its anchor" in p for p in found), found


def test_a_checkpoint_that_was_never_anchored_or_an_anchor_with_no_checkpoint_is_reported():
    key = Ed25519PrivateKey.generate()
    db, log = _log(key)
    log.append("inc-1", "step", {})
    log.checkpoint()
    log.close()
    problems = audit.verify(db, key.public_key(), anchors={}).problems
    assert any("never anchored" in p for p in problems)
    problems = audit.verify(db, key.public_key(), anchors={1: ("x", "y"), 99: ("h", "s")}).problems
    assert any("anchor 99 has no checkpoint" in p for p in problems)


def test_checkpoints_are_signed_by_kms_and_verify_with_its_public_key():
    kms = _FakeKms()
    signer = audit.KmsSigner("alias/warden-audit", kms)
    db, log = _log(signer)
    log.append("inc-1", "step", {})
    log.checkpoint()
    log.close()
    assert kms.calls == [("alias/warden-audit", "RAW", "ED25519_SHA_512")]
    assert audit.verify(db, signer.public_key()).ok


def test_audit_verify_checks_the_anchor_bucket_when_named(monkeypatch, capsys, tmp_path):
    from warden.cli import main

    key, bucket = Ed25519PrivateKey.generate(), _FakeAnchors()
    db, log = _log(key, bucket)
    log.append("inc-1", "step", {})
    log.checkpoint()
    log.close()
    pub = tmp_path / "audit.pub"
    pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setattr(audit, "S3Anchor", lambda name: _Real(name, bucket))  # the CLI's bucket, faked
    base = ["audit", "verify", "--db", str(db), "--public-key", str(pub), "--anchor-bucket", "anchors-bucket"]
    assert main(base) == 0
    _rewrite_and_resign(db, key)
    assert main(base) == 1 and "differs from its anchor" in capsys.readouterr().out


_Real = audit.S3Anchor
