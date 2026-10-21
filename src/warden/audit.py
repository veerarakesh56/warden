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

import contextlib
import functools
import hashlib
import json
import logging
import os
import pathlib
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
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
CREATE INDEX IF NOT EXISTS entries_by_correlation ON entries (correlation_id, seq);
CREATE INDEX IF NOT EXISTS entries_by_kind ON entries (kind, seq);
""" + "".join(
    f"CREATE TRIGGER IF NOT EXISTS {t}_no_{op.lower()} BEFORE {op} ON {t} "
    f"BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;\n"
    for t in ("entries", "checkpoints") for op in ("UPDATE", "DELETE")
)


# The same tables on PostgreSQL (Aurora in the runtime: every worker and Lambda writes one chain). Created only by
# `migrate`, run under a migration role; the runtime's role holds SELECT and INSERT and nothing else, and the
# triggers refuse UPDATE, DELETE and TRUNCATE even to a role that could (register O4, G6).
_PG_SCHEMA = (
    ("CREATE TABLE IF NOT EXISTS entries (seq BIGINT PRIMARY KEY, at TEXT NOT NULL, correlation_id TEXT NOT NULL, "
     "kind TEXT NOT NULL, body TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL)"),
    "CREATE TABLE IF NOT EXISTS checkpoints (seq BIGINT PRIMARY KEY, hash TEXT NOT NULL, signature TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS entries_by_correlation ON entries (correlation_id, seq)",
    "CREATE INDEX IF NOT EXISTS entries_by_kind ON entries (kind, seq)",
    ("CREATE OR REPLACE FUNCTION warden_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS "
     "$f$ BEGIN RAISE EXCEPTION 'the audit log is append-only'; END $f$"),
    *(f"CREATE OR REPLACE TRIGGER {t}_append_only BEFORE UPDATE OR DELETE ON {t} FOR EACH ROW "
      "EXECUTE FUNCTION warden_audit_append_only()" for t in ("entries", "checkpoints")),
    *(f"CREATE OR REPLACE TRIGGER {t}_no_truncate BEFORE TRUNCATE ON {t} FOR EACH STATEMENT "
      "EXECUTE FUNCTION warden_audit_append_only()" for t in ("entries", "checkpoints")),
)
# One chain, many writers: each append holds this transaction-scoped advisory lock (a fixed key: "warden-audit").
_PG_LOCK = int.from_bytes(b"wardenau", "big") >> 1


def _is_postgres(target: str | pathlib.Path) -> bool:
    return isinstance(target, str) and target.startswith(("postgresql://", "postgres://"))


def _pg_connect(dsn: str) -> Any:
    """A connection; with WARDEN_AUDIT_IAM_AUTH=1 and no password in the DSN, signed in with a 15-minute IAM token
    for the DSN's user (the runtime: no audit password exists anywhere, and the task role's rds-db:connect decides)."""
    import psycopg

    extra: dict[str, Any] = {}
    if os.environ.get("WARDEN_AUDIT_IAM_AUTH") == "1":
        from psycopg.conninfo import conninfo_to_dict

        parts = conninfo_to_dict(dsn)
        if not parts.get("password"):
            import boto3

            from .environments import region

            extra = {"password": boto3.client("rds", region_name=region()).generate_db_auth_token(
                DBHostname=parts["host"], Port=int(parts.get("port") or 5432), DBUsername=parts["user"]),
                "sslmode": "require"}
    return psycopg.connect(dsn, autocommit=True, connect_timeout=10, **extra)


def migrate(dsn: str, writer_role: str | None = None, *, iam_login: bool = False) -> None:
    """Create the audit tables and their append-only triggers on PostgreSQL, and grant `writer_role` (the runtime's
    database user) SELECT and INSERT on them and nothing else. Run by a migration role, never by the runtime.
    `iam_login` (Aurora): the writer is also created if missing, as a login with no password that signs in only with
    an IAM token (rds_iam)."""
    import re

    with _pg_connect(dsn) as db:
        for statement in _PG_SCHEMA:
            db.execute(statement)
        if writer_role:
            if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", writer_role):
                raise ValueError(f"not a plain database role name: {writer_role!r}")
            if iam_login:
                db.execute(f"DO $r$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{writer_role}') THEN "
                           f"CREATE ROLE {writer_role} LOGIN; END IF; END $r$")  # nosec B608 - a checked role name
                db.execute(f"GRANT rds_iam TO {writer_role}")
                db.execute(f"GRANT USAGE ON SCHEMA public TO {writer_role}")
            for t in ("entries", "checkpoints"):
                db.execute(f"REVOKE ALL ON {t} FROM {writer_role}")
                db.execute(f"GRANT SELECT, INSERT ON {t} TO {writer_role}")


_LOG = logging.getLogger("warden.audit")


@contextlib.contextmanager
def _said_when_unreachable(pg: bool):
    """B35 self-alarms: the audit database gone (stopped, unreachable, a dropped connection, its disk full) fails
    every activity that records, and an activity's failure is only a WARNING - nobody was paged. Said once as an
    ERROR line, by its kind only: the worker-errors alarm (paging.tf) pages it; a Lambda's error pages by its own.
    A deadlock or a serialization failure is not the database gone - Temporal retries those - and is not said."""
    if not pg:
        yield
        return
    import psycopg

    try:
        yield
    except psycopg.OperationalError as exc:
        # SQLSTATE class 40, "transaction rollback": a deadlock or a serialization failure, which Temporal retries.
        if not str(exc.sqlstate or "").startswith("40") and not getattr(exc, "warden_said", False):
            exc.warden_said = True
            _LOG.error("the audit database could not be reached or could not write (%s): every record, approval and "
                       "fix waits on it", type(exc).__name__)
        raise


class _Rows:
    """A statement's result, read whole while the store's lock is held: a cursor left to be read later shared the
    one connection with another thread's statements."""

    def __init__(self, cursor: Any) -> None:
        self._rows = cursor.fetchall() if getattr(cursor, "description", True) else []
        self.rowcount = getattr(cursor, "rowcount", -1)

    def fetchone(self) -> Any:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list:
        return list(self._rows)


class _Store:
    """The few statements the log runs, on SQLite (a file) or PostgreSQL (a `postgresql://` DSN). One connection, used
    by every activity thread of a worker: each statement and each transaction holds the lock, so no thread's read
    lands inside another's BEGIN ... COMMIT (2026-10-15: "cannot rollback - no transaction is active" and "bad
    parameter or other API misuse" failed a workflow test twice in CI)."""

    def __init__(self, target: str | pathlib.Path) -> None:
        self._lock = threading.RLock()
        self.pg = _is_postgres(target)
        if self.pg:
            with _said_when_unreachable(True):
                self.db = _pg_connect(str(target))
        else:
            self.db = sqlite3.connect(str(target), isolation_level=None, check_same_thread=False)
            self.db.executescript(_SCHEMA)

    def run(self, sql: str, params: tuple | list = ()) -> _Rows:
        with self._lock, _said_when_unreachable(self.pg):
            return _Rows(self.db.execute(sql.replace("?", "%s") if self.pg else sql, params))

    @contextlib.contextmanager
    def transaction(self):
        with self._lock:
            if self.pg:
                with _said_when_unreachable(True), self.db.transaction():
                    self.db.execute("SELECT pg_advisory_xact_lock(%s)", (_PG_LOCK,))
                    yield
                return
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.execute("COMMIT")
            finally:
                # The body raised, the generator was closed early, or COMMIT failed: nothing of it is kept. Only a
                # transaction still open is rolled back - a ROLLBACK with none raised "cannot rollback - no
                # transaction is active" over the error that ended it (Sonar python:S9152, 2026-10-16).
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")

    def insert_checkpoint(self, seq: int, head: str, signature: str) -> int:
        sql = ("INSERT INTO checkpoints VALUES (?, ?, ?) ON CONFLICT (seq) DO NOTHING" if self.pg
               else "INSERT OR IGNORE INTO checkpoints VALUES (?, ?, ?)")
        return self.run(sql, (seq, head, signature)).rowcount

    def close(self) -> None:
        self.db.close()


def _hash(prev: str, seq: int, at: str, correlation_id: str, kind: str, body: str) -> str:
    material = json.dumps([prev, seq, at, correlation_id, kind, body], ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _signed_message(seq: int, head: str) -> bytes:
    return f"warden-audit:{seq}:{head}".encode()


@functools.cache
def code_version() -> str:
    """A hash of WARDEN's own source and policy data (every .py and .yaml in the package), read once per process.
    Recorded with every model call (audit A-P-1) and bound into every plan (register O5)."""
    root = pathlib.Path(__file__).parent
    digest = hashlib.sha256()
    for f in sorted([*root.rglob("*.py"), *root.rglob("*.yaml")]):
        if "__pycache__" not in f.parts:
            digest.update(f.relative_to(root).as_posix().encode() + b"\0" + f.read_bytes())
    return digest.hexdigest()


# How long an anchor cannot be deleted: one day in the lab, configurable per install (Object Lock retention).
ANCHOR_RETENTION = timedelta(days=1)


def short(digest: str) -> str:
    """A hash as a person sees it, in a footer, on a record page or in `warden audit show`: its first 16 hex characters - longer when
    those are all digits, up to the first letter. Sixteen digits read as a phone or card number to redaction and
    the outbound gate, which then blocked the whole message (about one hash in 2,000; CI, 2026-10-03)."""
    end = 16
    while end < len(digest) and digest[:end].isdigit():
        end += 1
    return digest[:end]


class KmsSigner:
    """An Ed25519 key held by AWS KMS (register S12): it signs, and nobody - WARDEN included - can export it, so a
    copy of the database and the code is not enough to sign a rewritten history. ECC_NIST_EDWARDS25519 keys sign
    with ED25519_SHA_512 over the RAW message (KMS Sign API, read 2026-10-03); the signature is plain Ed25519, so
    `verify` checks it with the key's public half like any other."""

    def __init__(self, key_id: str, client: Any = None) -> None:
        if client is None:
            import boto3

            client = boto3.client("kms")
        self.key_id, self._kms = key_id, client

    def sign(self, message: bytes) -> bytes:
        return self._kms.sign(KeyId=self.key_id, Message=message, MessageType="RAW",
                              SigningAlgorithm="ED25519_SHA_512")["Signature"]

    def public_key(self) -> Ed25519PublicKey:
        der = self._kms.get_public_key(KeyId=self.key_id)["PublicKey"]
        return serialization.load_der_public_key(der)


class S3Anchor:
    """Checkpoints copied to an S3 bucket under Object Lock in COMPLIANCE mode, written by a principal other than the
    one that holds the audit database (register S12): until the retention ends, nobody - the account root included -
    can delete or overwrite one. A history rewritten afterwards no longer matches its anchors."""

    def __init__(self, bucket: str, client: Any = None, *, retain: timedelta = ANCHOR_RETENTION,
                 clock: Callable[[], datetime] | None = None) -> None:
        if client is None:
            import boto3

            client = boto3.client("s3")
        self.bucket, self._s3, self.retain = bucket, client, retain
        self.clock = clock or (lambda: datetime.now(UTC))

    def put(self, seq: int, head: str, signature: str) -> None:
        body = json.dumps({"seq": seq, "hash": head, "signature": signature}, sort_keys=True).encode()
        self._s3.put_object(Bucket=self.bucket, Key=f"anchors/{seq:012d}.json", Body=body,
                            ObjectLockMode="COMPLIANCE", ObjectLockRetainUntilDate=self.clock() + self.retain,
                            ChecksumAlgorithm="SHA256")

    def all(self) -> dict[int, tuple[str, str]]:
        out: dict[int, tuple[str, str]] = {}
        for page in self._s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix="anchors/"):
            for obj in page.get("Contents") or []:
                a = json.loads(self._s3.get_object(Bucket=self.bucket, Key=obj["Key"])["Body"].read())
                out[int(a["seq"])] = (a["hash"], a["signature"])
        return out


class AuditLog:
    def __init__(self, path: str | pathlib.Path, *, key: Any = None,
                 checkpoint_every: int = 100, clock: Callable[[], datetime] | None = None,
                 anchor: Any = None) -> None:
        # `key`: anything with sign(bytes) -> bytes - a local Ed25519 key, or a KmsSigner (register S12).
        # `anchor`: where each new checkpoint is also written, out of this process's reach (S3Anchor).
        self.anchor = anchor
        self.key = key
        self.clock = clock or (lambda: datetime.now(UTC))
        self.checkpoint_every = checkpoint_every
        self._lock = threading.Lock()
        # `path`: a SQLite file, or a `postgresql://` DSN for the shared runtime audit (G6).
        self.store = _Store(path)

    def append(self, correlation_id: str, kind: str, body: dict[str, Any]) -> str:
        """Add one row and return its hash."""
        return self._append(correlation_id, kind, body, None)[0]

    def append_unless(self, correlation_id: str, kind: str, body: dict[str, Any],
                      refuse: Callable[[], str]) -> tuple[str, str]:
        """Add one row unless `refuse()` gives a reason: (the row's hash, "") when written, ("", the reason) when not.
        `refuse` reads inside the write's own transaction, and every writer appends under one lock (a transaction-scoped
        advisory lock on PostgreSQL, BEGIN IMMEDIATE on SQLite), so no row from any worker lands between its read and
        the write: a check-and-set across workers (B20, locks.py). `refuse` reads through `entries`, never `append`."""
        return self._append(correlation_id, kind, body, refuse)

    def _append(self, correlation_id: str, kind: str, body: dict[str, Any],
                refuse: Callable[[], str] | None) -> tuple[str, str]:
        text = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
        at = self.clock().astimezone(UTC).isoformat(timespec="microseconds")
        with self._lock, self.store.transaction():
            if refuse is not None and (why := refuse()):
                return "", why
            last = self.store.run("SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (last[0] + 1, last[1]) if last else (1, GENESIS)
            digest = _hash(prev, seq, at, correlation_id, kind, text)
            self.store.run("INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (seq, at, correlation_id, kind, text, prev, digest))
        if self.key is not None and seq % self.checkpoint_every == 0:
            self.checkpoint()
        return digest, ""

    def checkpoint(self) -> int | None:
        """Sign the current head. Returns its sequence number (None for an empty log or no key)."""
        if self.key is None:
            return None
        with self._lock:
            last = self.store.run("SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
            if not last:
                return None
            signature = self.key.sign(_signed_message(*last)).hex()
            new = self.store.insert_checkpoint(last[0], last[1], signature)
        if new and self.anchor is not None:
            # A failed anchor leaves the checkpoint unanchored, and `verify` with the anchors says so: an outage of
            # the anchor store must not stop an incident from being recorded.
            with contextlib.suppress(Exception):
                self.anchor.put(last[0], last[1], signature)
        return last[0]

    def intact(self, seqs: Any) -> set[int]:
        """The rows among `seqs` whose stored hash is their own content's, which link to the row before them, and
        which a signed checkpoint already covers: facts a later diagnosis is shown were not written or changed after
        the fact (research 2026-10-15: a memory read must verify where it came from; `history.plans` read rows
        without checking). ponytail: two rows read per seq and the checkpoint's signature not re-checked here - the
        whole chain and every signature is `warden audit verify`."""
        want = sorted({int(s) for s in seqs if isinstance(s, int) and s > 0})
        if not want:
            return set()
        top = self.store.run("SELECT MAX(seq) FROM checkpoints").fetchone()
        signed = int(top[0]) if top and top[0] is not None else 0
        ok: set[int] = set()
        for s in want:
            if s > signed:
                continue
            rows = self.store.run("SELECT seq, at, correlation_id, kind, body, prev, hash FROM entries "
                                  "WHERE seq IN (?, ?) ORDER BY seq", (s - 1, s)).fetchall()
            by = {r[0]: r for r in rows}
            row, before = by.get(s), by.get(s - 1)
            if row is None or (s > 1 and before is None):
                continue
            prev = before[6] if before else GENESIS
            if row[5] == prev and _hash(row[5], *row[:5]) == row[6] and (
                    before is None or _hash(before[5], *before[:5]) == before[6]):
                ok.add(s)
        return ok

    def signed_through(self) -> int:
        """The last row a signed checkpoint covers (0 when none does): rows after it are not signed yet."""
        top = self.store.run("SELECT MAX(seq) FROM checkpoints").fetchone()
        return int(top[0]) if top and top[0] is not None else 0

    def head(self, correlation_id: str) -> str:
        """The hash of the latest row of one correlation id ("" if it has none): the record a plan was made on."""
        row = self.store.run("SELECT hash FROM entries WHERE correlation_id = ? ORDER BY seq DESC LIMIT 1",
                             (correlation_id,)).fetchone()
        return row[0] if row else ""

    def entries(self, correlation_id: str | None = None, *, kinds: tuple[str, ...] = (),
                since: datetime | None = None) -> list[dict[str, Any]]:
        where, params = [], []
        if correlation_id:
            where.append("correlation_id = ?")
            params.append(correlation_id)
        if kinds:
            where.append(f"kind IN ({','.join('?' * len(kinds))})")
            params.extend(kinds)
        if since:
            # ISO-8601 UTC strings of one fixed shape sort in time order, byte by byte (COLLATE "C" on PostgreSQL).
            where.append('at COLLATE "C" >= ?' if self.store.pg else "at >= ?")
            params.append(since.astimezone(UTC).isoformat(timespec="microseconds"))
        query = "SELECT seq, at, correlation_id, kind, body, hash FROM entries"
        rows = self.store.run(query + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY seq",
                              params).fetchall()
        return [{"seq": s, "at": datetime.fromisoformat(a), "correlation_id": c, "kind": k, "body": json.loads(b),
                 "hash": h} for s, a, c, k, b, h in rows]

    @property
    def db(self) -> Any:
        """The SQLite connection (tests and tools read the file through it); PostgreSQL goes through `store`."""
        if self.store.pg:
            raise AttributeError("a PostgreSQL audit is read through AuditLog's methods")
        return self.store.db

    def close(self) -> None:
        self.store.close()


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


def verify(path: str | pathlib.Path, public_key: Ed25519PublicKey,
           anchors: dict[int, tuple[str, str]] | None = None) -> Verification:
    """Recompute the whole chain and check every checkpoint signature. Never raises on a damaged file:
    damage is a finding. With `anchors` (S3Anchor.all()), every checkpoint must also match the copy written out of
    reach when it was made: whoever holds the key and the database can re-sign a rewritten history, not its anchors
    (register S12)."""
    result = Verification()
    try:
        if _is_postgres(path):
            with _pg_connect(str(path)) as db:
                rows = db.execute("SELECT seq, at, correlation_id, kind, body, prev, hash FROM entries ORDER BY seq").fetchall()
                checkpoints = db.execute("SELECT seq, hash, signature FROM checkpoints ORDER BY seq").fetchall()
        else:
            db = sqlite3.connect(f"file:{pathlib.Path(path).as_posix()}?mode=ro", uri=True)
            try:
                rows = db.execute("SELECT seq, at, correlation_id, kind, body, prev, hash FROM entries ORDER BY seq").fetchall()
                checkpoints = db.execute("SELECT seq, hash, signature FROM checkpoints ORDER BY seq").fetchall()
            finally:
                db.close()
    except Exception as exc:  # noqa: BLE001 - damage or an unreachable store is a finding, never a crash
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
    if anchors is not None:
        stored = {seq: (head, signature) for seq, head, signature in checkpoints}
        for seq, (head, signature) in sorted(stored.items()):
            if seq not in anchors:
                result.problems.append(f"checkpoint {seq} was never anchored")
            elif anchors[seq] != (head, signature):
                result.problems.append(f"checkpoint {seq} differs from its anchor: the history was rewritten")
        for seq in sorted(set(anchors) - set(stored)):
            result.problems.append(f"anchor {seq} has no checkpoint here: the database lost history")
    return result


# --------------------------------------------------------------------------- keys


# Key files are written inside one folder only (Sonar pythonsecurity:S8707, 2026-10-16): the paths come from a command
# line, and an agent can drive that command line, so a path must never reach `~/.bashrc`, a synced folder or a file
# through `..` or a symlink. The folder is WARDEN_KEY_DIR, or ~/.warden.
KEY_DIR_ENV = "WARDEN_KEY_DIR"


def key_dir() -> pathlib.Path:
    return pathlib.Path(os.environ.get(KEY_DIR_ENV) or pathlib.Path.home() / ".warden").expanduser()


def key_path(path: pathlib.Path, base: pathlib.Path | None = None) -> pathlib.Path:
    """The real location of `path` when it lies directly or deeper inside `base` (default: the key folder, created 0700
    if missing); else ValueError. The file itself must not be a symlink, and its folder must already exist. Keys are
    read from there too (cli.py): a --key from the command line names no file outside it."""
    folder = (base or key_dir()).expanduser()
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    folder = folder.resolve(strict=True)
    target = pathlib.Path(path).expanduser()
    if target.is_symlink():
        raise ValueError(f"{path} is a symlink: a key file is never used through one")
    real = target.parent.resolve(strict=True) / target.name
    if not real.is_relative_to(folder) or real == folder:
        raise ValueError(f"{path} is outside {folder}: key files are kept only there (set {KEY_DIR_ENV} to choose "
                         f"another folder)")
    return real


def _create(real: pathlib.Path, data: bytes, mode: int) -> None:
    """Create `real` holding `data`, never over an existing file. A file this call created and could not fill is
    removed again: no half-written key is left to block a retry (CodeRabbit, PR 35)."""
    fd = os.open(real, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except BaseException:
        real.unlink(missing_ok=True)
        raise


def write_private_key(path: pathlib.Path, pem: bytes, base: pathlib.Path | None = None) -> None:
    """Create `path` holding `pem`, inside `base` (default: the key folder): never over an existing file, and never
    readable by others for an instant (2026-10-16: write_bytes then chmod left a window, and replaced a key a racing
    writer had just made). On POSIX the file is created mode 0600. Windows ignores the mode (beyond the read-only flag);
    what keeps other accounts out is the folder's ACL - under the user's profile (%USERPROFILE%) only that user, SYSTEM
    and Administrators can read - and, for a key encrypted with a passphrase, the passphrase."""
    _create(key_path(path, base), pem, 0o600)


def generate_key(private_path: pathlib.Path, public_path: pathlib.Path, passphrase: bytes | None = None,
                 base: pathlib.Path | None = None) -> None:
    """A new Ed25519 pair, both files inside `base` (default: the key folder), neither written over an existing file
    (the public key used to be: a path naming any file would have replaced it)."""
    public_real = key_path(public_path, base)
    private_real = key_path(private_path, base)
    if public_real == private_real:
        raise ValueError(f"{private_path} and {public_path} are the same file: the pair needs two")
    if public_real.exists():
        raise FileExistsError(f"{public_path} exists; refusing to overwrite it")
    key = Ed25519PrivateKey.generate()
    encryption = (serialization.BestAvailableEncryption(passphrase) if passphrase
                  else serialization.NoEncryption())
    _create(private_real, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption),
            0o600)
    try:
        _create(public_real, key.public_key().public_bytes(serialization.Encoding.PEM,
                                                           serialization.PublicFormat.SubjectPublicKeyInfo), 0o644)
    except BaseException:
        private_real.unlink()  # no half pair: "no key was written" must stay true (CodeRabbit, PR 35)
        raise


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
