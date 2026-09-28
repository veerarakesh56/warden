"""The audit log must make every kind of tampering visible - including the careful kind that
recomputes the hash chain after editing a row."""

from __future__ import annotations

import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import audit


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


def _log(tmp_path, key, rows=5, every=100):
    path = tmp_path / "audit.db"
    log = audit.AuditLog(path, key=key, checkpoint_every=every)
    for i in range(rows):
        log.append("inc-1", "step", {"n": i, "note": "ünïcode ok"})
    log.checkpoint()
    log.close()
    return path


def _raw(path):
    """What an attacker with the file does: drop the guard rails and write SQL directly."""
    db = sqlite3.connect(path, isolation_level=None)
    for t in ("entries", "checkpoints"):
        for op in ("update", "delete"):
            db.execute(f"DROP TRIGGER {t}_no_{op}")
    return db


def test_an_untouched_log_verifies_and_is_fully_signed(tmp_path, key):
    path = _log(tmp_path, key)
    result = audit.verify(path, key.public_key())
    assert result.ok and result.rows == 5 and result.signed_through == 5 and result.unsigned_tail == 0
    assert [e["body"]["n"] for e in audit.AuditLog(path).entries("inc-1")] == [0, 1, 2, 3, 4]


def test_rows_cannot_be_updated_or_deleted_through_sql(tmp_path, key):
    db = sqlite3.connect(_log(tmp_path, key))
    for sql in ("UPDATE entries SET body = '{}' WHERE seq = 2", "DELETE FROM entries WHERE seq = 2",
                "DELETE FROM checkpoints"):
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            db.execute(sql)


def test_an_edited_row_is_found(tmp_path, key):
    path = _log(tmp_path, key)
    _raw(path).execute("""UPDATE entries SET body = '{"n":2,"note":"nothing happened"}' WHERE seq = 3""")
    assert "row 3 was changed after it was written" in audit.verify(path, key.public_key()).problems


def test_a_deleted_row_is_found(tmp_path, key):
    path = _log(tmp_path, key)
    _raw(path).execute("DELETE FROM entries WHERE seq = 2")
    problems = audit.verify(path, key.public_key()).problems
    assert "row 2 is missing (next row is 3)" in problems


def test_rewriting_a_row_and_recomputing_every_later_hash_is_caught_by_the_signature(tmp_path, key):
    """The careful attacker: the chain is internally consistent again afterwards. Only the signed
    checkpoint still remembers the real history."""
    path = _log(tmp_path, key)
    db = _raw(path)
    rows = db.execute("SELECT seq, at, correlation_id, kind, body FROM entries ORDER BY seq").fetchall()
    prev = audit.GENESIS
    for seq, at, cid, kind, body in rows:
        if seq == 2:
            body = '{"n":1,"note":"approved by someone else"}'
        digest = audit._hash(prev, seq, at, cid, kind, body)
        db.execute("UPDATE entries SET body = ?, prev = ?, hash = ? WHERE seq = ?", (body, prev, digest, seq))
        prev = digest
    result = audit.verify(path, key.public_key())
    assert result.problems == ["checkpoint 5 was signed over a different history"]


def test_a_checkpoint_signed_with_another_key_is_rejected(tmp_path, key):
    path = _log(tmp_path, key)
    forger = Ed25519PrivateKey.generate()
    db = _raw(path)
    head = db.execute("SELECT hash FROM checkpoints WHERE seq = 5").fetchone()[0]
    db.execute("UPDATE checkpoints SET signature = ? WHERE seq = 5",
               (forger.sign(audit._signed_message(5, head)).hex(),))
    assert "checkpoint 5 has an invalid signature" in audit.verify(path, key.public_key()).problems


def test_cutting_the_tail_but_keeping_its_checkpoint_is_found(tmp_path, key):
    path = _log(tmp_path, key)
    _raw(path).execute("DELETE FROM entries WHERE seq >= 4")
    assert "checkpoint 5 was signed over a different history" in audit.verify(path, key.public_key()).problems


def test_rows_after_the_last_checkpoint_are_reported_as_unsigned(tmp_path, key):
    path = _log(tmp_path, key)
    log = audit.AuditLog(path, key=key)
    log.append("inc-2", "step", {})
    log.close()
    result = audit.verify(path, key.public_key())
    assert result.ok and result.unsigned_tail == 1


def test_a_checkpoint_is_written_automatically_every_n_rows(tmp_path, key):
    path = _log(tmp_path, key, rows=7, every=3)
    db = sqlite3.connect(path)
    assert [s for (s,) in db.execute("SELECT seq FROM checkpoints ORDER BY seq")] == [3, 6, 7]


def test_a_damaged_file_is_a_finding_not_a_crash(tmp_path, key):
    path = _log(tmp_path, key)
    data = bytearray(path.read_bytes())
    data[:16] = b"X" * 16  # destroy the SQLite header
    path.write_bytes(bytes(data))
    result = audit.verify(path, key.public_key())
    assert not result.ok and "cannot be read" in result.problems[0]


def test_keys_round_trip_and_a_passphrase_is_required_when_set(tmp_path):
    priv, pub = tmp_path / "k.pem", tmp_path / "k.pub"
    audit.generate_key(priv, pub, passphrase=b"correct horse")
    key = audit.load_private_key(priv, b"correct horse")
    message = audit._signed_message(1, audit.GENESIS)
    audit.load_public_key(pub).verify(key.sign(message), message)
    with pytest.raises(TypeError):
        audit.load_private_key(priv)  # encrypted, no passphrase given


def test_the_cli_creates_a_key_refuses_to_overwrite_it_and_verifies(tmp_path, capsys, monkeypatch):
    from warden import cli

    monkeypatch.delenv("WARDEN_AUDIT_KEY_PASSPHRASE", raising=False)
    priv, pub = tmp_path / "k.pem", tmp_path / "k.pub"
    assert cli.main(["audit", "keygen", "--private", str(priv), "--public", str(pub)]) == 0
    assert cli.main(["audit", "keygen", "--private", str(priv), "--public", str(pub)]) == 1
    path = _log(tmp_path, audit.load_private_key(priv))
    assert cli.main(["audit", "verify", "--db", str(path), "--public-key", str(pub)]) == 0
    assert "5 rows, signed through row 5" in capsys.readouterr().out
    _raw(path).execute("UPDATE entries SET kind = 'nothing' WHERE seq = 1")
    assert cli.main(["audit", "verify", "--db", str(path), "--public-key", str(pub)]) == 1
    out = capsys.readouterr().out
    assert "TAMPERED: row 1 was changed after it was written" in out and "NOT intact" in out
