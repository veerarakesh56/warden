"""The sealed vault: the real values behind an incident's placeholders, for people only (owner, 2026-10-20).

The read zone masks every value it finds (redaction.py) and, until now, threw the map away: the model was shown
`<EMAIL_1>` and nobody could ever learn which address it was. The map is now SEALED where it is made - inside
`prepare`, before it goes out of scope - and only a person can open it, through the reveal on the records page.

- **Sealed with a key no AI zone can use.** AWS KMS envelope encryption: a fresh data key per seal (GenerateDataKey,
  encryption context purpose=vault, the environment and the incident), AES-256-GCM over the map, the data key kept
  only wrapped. The vault key's policy (terraform/modules/warden-runtime/vault.tf) lets the read zone seal and ONLY
  the approval page's Lambda role open (kms:Decrypt, purpose=vault) - not the llm zone, not Eldane's critic zone,
  not the discussion chat's, not any zone a future agent runs in. CloudTrail records every Decrypt.
- **Never through Temporal, never in a log.** `seal` runs inside `prepare` and writes straight to the database; its
  result is not returned, so it never enters a workflow's history. Nothing here logs a value.
- **Stable ids people can correlate.** Each value also gets a pseudonym, `email:3f9a0c7d21b4`: an HMAC-SHA256 of its
  kind and value under the environment's own key, the same in every incident and revealing nothing. The key exists
  only as a KMS ciphertext (no person ever sees it: GenerateDataKeyWithoutPlaintext) that only the read zone may
  open (purpose=pseudonym). The model is shown placeholders only - never a pseudonym.
- **Retention, then gone.** A vault row expires WARDEN_VAULT_DAYS after it is sealed (default and minimum 180, the
  audit's own retention, register B19) and is deleted by the next seal. The signed audit keeps the index (placeholder,
  kind, pseudonym) and the sealed bytes' SHA-256 - what existed stays provable after the values are gone. An erasure
  request deletes an incident's rows (docs/DATA-EGRESS.md).

Without a vault key (a demo, a test with no KMS) nothing is sealed and the map is discarded, as before; a seal that
fails is recorded (`incident.vault_unavailable`, its type only) and the incident goes on - the values stay masked
either way; only the reveal is lost.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

INDEX = "incident.vault"  # the signed audit's row: the index and the sealed bytes' hash, never a value
UNAVAILABLE = "incident.vault_unavailable"
MIN_DAYS = 180
MAX_DAYS = 3650  # ten years: longer than any retention WARDEN documents (docs/DATA-EGRESS.md), and within a date's range
PSEUDONYM_PARAMETER = "WARDEN_PSEUDONYM_KEY_SEALED"  # under /warden/<env>/env/: a KMS ciphertext, never the key

_TABLE = ("CREATE TABLE IF NOT EXISTS vault (incident TEXT NOT NULL, sha256 TEXT NOT NULL, sealed_at TEXT NOT "
                 "NULL, expires_at TEXT NOT NULL, wrapped_key TEXT NOT NULL, sealed TEXT NOT NULL, "
                 "PRIMARY KEY (incident, sha256))")


def migrate(dsn: str, writer_role: str | None = None) -> None:
    """The vault's table on PostgreSQL (lambdas.migrate, after the audit's). Unlike the audit's tables it is not
    append-only: its rows expire. The runtime's writer may read, add and delete them - deleting is how retention and
    erasure work; a row it could read is ciphertext only it cannot open."""
    import re

    from .audit import _pg_connect

    if writer_role and not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", writer_role):
        raise ValueError(f"not a plain database role name: {writer_role!r}")
    with _pg_connect(dsn) as db:
        db.execute(_TABLE)
        db.execute("CREATE INDEX IF NOT EXISTS vault_by_expiry ON vault (expires_at)")
        if writer_role:
            from psycopg import sql

            who = sql.Identifier(writer_role)
            db.execute(sql.SQL("REVOKE ALL ON vault FROM {}").format(who))
            db.execute(sql.SQL("GRANT SELECT, INSERT, DELETE ON vault TO {}").format(who))


def days() -> int:
    """How long a sealed map is kept: WARDEN_VAULT_DAYS, never less than the audit's 180 days nor more than ten
    years."""
    raw = os.environ.get("WARDEN_VAULT_DAYS", "").strip()
    return min(MAX_DAYS, max(MIN_DAYS, int(raw))) if raw.isdigit() else MIN_DAYS


def key_id(env: dict[str, str] | None = None) -> str:
    """The vault key: WARDEN_VAULT_KMS_KEY_ID, else the runtime module's alias for WARDEN_ENV's runtime; "" for none."""
    env = os.environ if env is None else env
    explicit = env.get("WARDEN_VAULT_KMS_KEY_ID", "").strip()
    runtime = env.get("WARDEN_ENV", "").strip()
    return explicit or (f"alias/warden-{runtime}-vault" if runtime else "")


def kind_of(placeholder: str) -> str:
    return placeholder.strip("<>").rsplit("_", 1)[0]


def pseudonym(key: bytes, kind: str, value: str) -> str:
    """`email:3f9a0c7d21b4` - the same for the same value in every incident of the environment; nothing of the value."""
    digest = hmac.new(key, f"{kind}\x00{value}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"{kind.lower()}:{digest}"


def _context(purpose: str, environment: str, incident: str = "") -> dict[str, str]:
    return {"purpose": purpose, "environment": environment, **({"incident": incident} if incident else {})}


@dataclass
class Vault:
    """One environment's vault: its KMS key, its clients and the open pseudonym key. `kms` and `ssm` are boto3 clients
    (or fakes with the same calls)."""

    key: str
    environment: str
    kms: Any
    ssm: Any = None
    _pseudonym_key: bytes | None = None

    @classmethod
    def from_environment(cls, kms: Any = None, ssm: Any = None) -> Vault | None:
        """This process's vault, built once (its pseudonym key is opened once); None without a vault key."""
        key = key_id()
        if not key:
            return None
        environment = os.environ.get("WARDEN_ENV", "").strip() or "local"
        if kms is not None and ssm is not None:
            return cls(key=key, environment=environment, kms=kms, ssm=ssm)
        cached = _BUILT.get((key, environment))
        if cached is None:
            import boto3

            from .environments import region

            where = region()  # the runtime's own region, as every other client of WARDEN's (audit._pg_connect)
            cached = _BUILT[(key, environment)] = cls(
                key=key, environment=environment, kms=kms or boto3.client("kms", region_name=where),
                ssm=ssm or boto3.client("ssm", region_name=where))
        return cached

    def pseudonym_key(self) -> bytes | None:
        """The environment's pseudonym key, opened once per process from its sealed parameter; None when there is none
        (the index then carries no pseudonyms)."""
        if self._pseudonym_key is None and self.ssm is not None:
            from .environments import names

            root = names(self.environment).ssm + "env/"
            sealed = ""
            for page in self.ssm.get_paginator("get_parameters_by_path").paginate(Path=root, Recursive=False):
                sealed = next((p["Value"] for p in page.get("Parameters", [])
                               if p["Name"] == root + PSEUDONYM_PARAMETER), sealed)
            if sealed:
                self._pseudonym_key = self.kms.decrypt(
                    CiphertextBlob=base64.b64decode(sealed), KeyId=self.key,
                    EncryptionContext=_context("pseudonym", self.environment))["Plaintext"]
        return self._pseudonym_key

    def index(self, mapping: dict[str, str]) -> list[dict[str, str]]:
        """What the records page may show without a reveal: each placeholder, its kind and its pseudonym."""
        pkey = self.pseudonym_key()
        return [{"placeholder": p, "kind": kind_of(p),
                 **({"pseudonym": pseudonym(pkey, kind_of(p), v)} if pkey else {})}
                for p, v in sorted(mapping.items(), key=lambda kv: (kind_of(kv[0]), _number(kv[0])))]

    def seal(self, incident: str, mapping: dict[str, str], now: datetime | None = None) -> dict[str, Any]:
        """The sealed row for `mapping` (the database's), with its index and hash (the audit's)."""
        now = (now or datetime.now(UTC)).astimezone(UTC)
        data_key = self.kms.generate_data_key(KeyId=self.key, KeySpec="AES_256",
                                              EncryptionContext=_context("vault", self.environment, incident))
        nonce = os.urandom(12)
        plain = json.dumps(mapping, sort_keys=True, ensure_ascii=False).encode("utf-8")
        sealed = nonce + AESGCM(data_key["Plaintext"]).encrypt(nonce, plain, incident.encode("utf-8"))
        del data_key["Plaintext"]
        digest = hashlib.sha256(sealed).hexdigest()
        return {"incident": incident, "sha256": digest, "sealed_at": now.isoformat(timespec="seconds"),
                "expires_at": (now + timedelta(days=days())).isoformat(timespec="seconds"),
                "wrapped_key": base64.b64encode(data_key["CiphertextBlob"]).decode(),
                "sealed": base64.b64encode(sealed).decode(), "index": self.index(mapping)}

    def open(self, row: dict[str, Any]) -> dict[str, str]:
        """The map a sealed row holds. Only a role the vault key lets Decrypt (the approval page's) can run this
        against AWS; anyone else's call is refused by KMS. Called by the reveal alone (records page)."""
        sealed = base64.b64decode(row["sealed"])
        if hashlib.sha256(sealed).hexdigest() != row["sha256"]:
            raise ValueError("the sealed row does not match its hash")
        key = self.kms.decrypt(CiphertextBlob=base64.b64decode(row["wrapped_key"]), KeyId=self.key,
                               EncryptionContext=_context("vault", self.environment, row["incident"]))["Plaintext"]
        plain = AESGCM(key).decrypt(sealed[:12], sealed[12:], str(row["incident"]).encode("utf-8"))
        return json.loads(plain)


_BUILT: dict[tuple[str, str], Vault] = {}


def _number(placeholder: str) -> int:
    tail = placeholder.strip("<>").rsplit("_", 1)[-1]
    return int(tail) if tail.isdigit() else 0


def _seal_errors() -> tuple[type[BaseException], ...]:
    """What a seal can fail with: KMS refusing or unreachable, the database's errors, a malformed parameter."""
    import sqlite3

    errors: list[type[BaseException]] = [OSError, ValueError, KeyError, TypeError, sqlite3.Error]
    for module, names in (("botocore.exceptions", ("BotoCoreError", "ClientError")), ("psycopg", ("Error",))):
        try:
            imported = __import__(module, fromlist=list(names))
            errors += [getattr(imported, n) for n in names]
        except ImportError:
            continue
    return tuple(errors)


_SEAL_ERRORS = _seal_errors()
_COLUMNS = ("incident", "sha256", "sealed_at", "expires_at", "wrapped_key", "sealed")


def store(log: Any, row: dict[str, Any], run_id: str = "") -> str:
    """Write a sealed row to the vault table, its index and hash to the signed audit, and delete expired rows. The
    hash: what the audit row names."""
    db = log.store
    if not db.pg:
        db.run(_TABLE)
    db.run("INSERT INTO vault VALUES (?, ?, ?, ?, ?, ?)", tuple(row[c] for c in _COLUMNS))
    log.append(row["incident"], INDEX, {"run_id": run_id, "sha256": row["sha256"], "sealed_at": row["sealed_at"],
                                        "expires_at": row["expires_at"], "entries": row["index"]})
    purge(log, datetime.fromisoformat(row["sealed_at"]))
    return row["sha256"]


def purge(log: Any, now: datetime | None = None) -> int:
    """Delete every vault row past its expiry. The number deleted."""
    when = (now or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="seconds")
    return log.store.run("DELETE FROM vault WHERE expires_at < ?", (when,)).rowcount


def sealed_row(log: Any, incident: str, sha256: str) -> dict[str, Any] | None:
    """The sealed row the audit's index row names; None when it has expired or was erased."""
    if not log.store.pg:
        log.store.run(_TABLE)
    got = log.store.run("SELECT incident, sha256, sealed_at, expires_at, wrapped_key, sealed FROM vault "
                        "WHERE incident = ? AND sha256 = ?", (incident, sha256)).fetchone()
    return dict(zip(_COLUMNS, got, strict=True)) if got else None


def seal_incident(log: Any, incident: str, mapping: dict[str, str], *, run_id: str = "",
                  vault: Vault | None = None) -> str:
    """`prepare`'s one call: seal this run's map and record it; "" when there is no vault or nothing to seal. A seal
    that fails is recorded by its type and the incident goes on (the values stay masked; only the reveal is lost)."""
    if not mapping:
        return ""
    try:
        vault = vault or Vault.from_environment()
        if vault is None:
            return ""
        return store(log, vault.seal(incident, mapping), run_id)
    except Exception as exc:  # noqa: BLE001 - whatever stops a seal, the incident goes on (the map is discarded)
        log.append(incident, UNAVAILABLE, {"run_id": run_id, "error": type(exc).__name__, "values": len(mapping)})
        return ""
