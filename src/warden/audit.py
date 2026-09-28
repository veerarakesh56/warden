"""Tamper-evident audit log: append-only SQLite, a hash chain, and Ed25519-signed checkpoints.

Every step of an incident (evidence gathered, plan, approval, credential session, action, result)
is one row, and one correlation id (`inc-...`) runs through all of them.

Three layers, because each one alone is beatable:
- **Append-only.** Triggers abort any UPDATE or DELETE, so a bug or a careless script cannot
  rewrite history. Anyone who can write the file can drop a trigger, so this is a guard rail, not
  proof.
- **Hash chain.** Each row's hash covers the previous row's hash and all of its own fields, so an
  edited, removed or reordered row breaks every link after it.
- **Signed checkpoints.** An attacker who edits a row AND recomputes every later hash leaves a
  consistent chain. What they cannot recompute is the Ed25519 signature over a checkpoint (the
  head's sequence number and hash). Checkpoints are written every `checkpoint_every` rows and when a
  workflow ends.

⛔ Honest limits:
- Rows after the last checkpoint are chained but not yet signed. `verify` reports that tail.
- Someone who deletes the tail back to an earlier checkpoint, together with the later checkpoint
  rows, is only caught by an outside copy of the latest checkpoint. Shipping each checkpoint
  somewhere the writer cannot delete (S3 with Object Lock, the Slack footer) is Phase 4.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

GENESIS = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    seq INTEGER PRIMARY KEY, at TEXT NOT NULL, correlation_id TEXT NOT NULL, kind TEXT NOT NULL,
    body TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS checkpoints (seq INTEGER PRIMARY KEY, hash TEXT NOT NULL, signature TEXT NOT NULL);
""" + "".join(
    f"CREATE TRIGGER IF NOT EXISTS {t}_no_{op.lower()} BEFORE {op} ON {t} "
    f"BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;\n"
    for t in ("entries", "checkpoints") for op in ("UPDATE", "DELETE")
)


def _hash(prev: str, seq: int, at: str, correlation_id: str, kind: str, body: str) -> str:
    material = json.dumps([prev, seq, at, correlation_id, kind, body], ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _signed_message(seq: int, head: str) -> bytes:
    return f"warden-audit:{seq}:{head}".encode()


class AuditLog:
    def __init__(self, path: str | pathlib.Path, *, key: Ed25519PrivateKey | None = None,
                 checkpoint_every: int = 100) -> None:
        self.key = key
        self.checkpoint_every = checkpoint_every
        self._lock = threading.Lock()
        self.db = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self.db.executescript(_SCHEMA)

    def append(self, correlation_id: str, kind: str, body: dict[str, Any]) -> str:
        """Add one row and return its hash."""
        text = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
        at = datetime.now(UTC).isoformat()
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                last = self.db.execute("SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
                seq, prev = (last[0] + 1, last[1]) if last else (1, GENESIS)
                digest = _hash(prev, seq, at, correlation_id, kind, text)
                self.db.execute("INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?, ?)",
                                (seq, at, correlation_id, kind, text, prev, digest))
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
        if self.key is not None and seq % self.checkpoint_every == 0:
            self.checkpoint()
        return digest

    def checkpoint(self) -> int | None:
        """Sign the current head. Returns its sequence number (None for an empty log or no key)."""
        if self.key is None:
            return None
        with self._lock:
            last = self.db.execute("SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
            if not last:
                return None
            signature = self.key.sign(_signed_message(*last)).hex()
            self.db.execute("INSERT OR IGNORE INTO checkpoints VALUES (?, ?, ?)", (*last, signature))
        return last[0]

    def entries(self, correlation_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT seq, at, correlation_id, kind, body FROM entries"
        rows = (self.db.execute(query + " WHERE correlation_id = ? ORDER BY seq", (correlation_id,))
                if correlation_id else self.db.execute(query + " ORDER BY seq"))
        return [{"seq": s, "at": a, "correlation_id": c, "kind": k, "body": json.loads(b)}
                for s, a, c, k, b in rows]

    def close(self) -> None:
        self.db.close()


@dataclass
class Verification:
    rows: int = 0
    signed_through: int = 0
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    @property
    def unsigned_tail(self) -> int:
        return self.rows - self.signed_through


def verify(path: str | pathlib.Path, public_key: Ed25519PublicKey) -> Verification:
    """Recompute the whole chain and check every checkpoint signature. Never raises on a damaged file:
    damage is a finding."""
    result = Verification()
    try:
        db = sqlite3.connect(f"file:{pathlib.Path(path).as_posix()}?mode=ro", uri=True)
        try:
            rows = db.execute("SELECT seq, at, correlation_id, kind, body, prev, hash FROM entries ORDER BY seq").fetchall()
            checkpoints = db.execute("SELECT seq, hash, signature FROM checkpoints ORDER BY seq").fetchall()
        finally:
            db.close()
    except sqlite3.DatabaseError as exc:
        result.problems.append(f"the audit database cannot be read: {exc}")
        return result

    result.rows = len(rows)
    hashes: dict[int, str] = {}
    prev = GENESIS
    for expected_seq, (seq, at, cid, kind, body, stored_prev, stored_hash) in enumerate(rows, start=1):
        if seq != expected_seq:
            result.problems.append(f"row {expected_seq} is missing (next row is {seq})")
        if stored_prev != prev:
            result.problems.append(f"row {seq} does not link to the row before it")
        if _hash(stored_prev, seq, at, cid, kind, body) != stored_hash:
            result.problems.append(f"row {seq} was changed after it was written")
        hashes[seq] = stored_hash
        prev = stored_hash

    for seq, head, signature in checkpoints:
        try:
            public_key.verify(bytes.fromhex(signature), _signed_message(seq, head))
        except (InvalidSignature, ValueError):
            result.problems.append(f"checkpoint {seq} has an invalid signature")
            continue
        if hashes.get(seq) != head:
            result.problems.append(f"checkpoint {seq} was signed over a different history")
            continue
        result.signed_through = max(result.signed_through, seq)
    return result


# --------------------------------------------------------------------------- keys


def generate_key(private_path: pathlib.Path, public_path: pathlib.Path, passphrase: bytes | None = None) -> None:
    key = Ed25519PrivateKey.generate()
    encryption = (serialization.BestAvailableEncryption(passphrase) if passphrase
                  else serialization.NoEncryption())
    private_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               encryption))
    private_path.chmod(0o600)
    public_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                          serialization.PublicFormat.SubjectPublicKeyInfo))


def load_private_key(path: pathlib.Path, passphrase: bytes | None = None) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=passphrase)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: pathlib.Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"{path} is not an Ed25519 public key")
    return key
