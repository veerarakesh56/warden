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
  kind and value under the environment's own HMAC key, the same in every incident and revealing nothing. That key is
  a KMS HMAC key: it never leaves KMS, and only the read zone may use it (kms:GenerateMac). No zone holds kms:Decrypt
  on the vault key but the approval page's (owner, 2026-10-21). The model is shown placeholders only - never a
  pseudonym.
- **Retention, then gone.** A vault row expires WARDEN_VAULT_DAYS after it is sealed (default and minimum 180, the
  audit's own retention, register B19) and is deleted by the next seal. The signed audit keeps the index (placeholder,
  kind, pseudonym) and the sealed bytes' SHA-256 - what existed stays provable after the values are gone. An erasure
  is the database owner's; its procedure is planned on the data-egress page (added by #121).
- **Personal data only.** Only the kinds in SEALED_KINDS (an email, a phone number, a tenant, an account id, an ARN,
  a UUID, an IP or MAC address, an internal host name, a person's name, a street address) are sealed. A credential,
  token, key, webhook, bank or card number, or a national id (a US SSN, an Aadhaar or PAN number) - NEVER_SEALED - is
  never kept: it is thrown away after masking, as before the vault (owner-safe default, review 2026-10-21). Every
  redaction kind is in exactly one of the two sets (tests/test_vault.py), so a new kind must be classified.

Without a vault key (a demo, a test with no KMS) nothing is sealed and the map is discarded, as before; a seal that
fails is recorded (`incident.vault_unavailable`, its type only) and the incident goes on - the values stay masked
either way; only the reveal is lost.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

INDEX = "incident.vault"  # the signed audit's row: the index and the sealed bytes' hash, never a value
UNAVAILABLE = "incident.vault_unavailable"
MIN_DAYS = 180
MAX_DAYS = 3650  # ten years: longer than any retention WARDEN documents, and within a date's range
PURGE_FAILED = "incident.vault_purge_failed"  # a seal that worked, whose expired-row purge did not (its type only)
# The redaction kinds a person may later reveal: personal data that identifies who or what was hit.
SEALED_KINDS = frozenset({"EMAIL", "PHONE", "TENANT", "ACCOUNTID", "ARN", "UUID", "IPV4", "IPV6", "MAC", "HOSTNAME",
                          "NAME", "ADDRESS"})
# Never sealed, never revealable: secrets and financial numbers (redaction.SECRET_KINDS, which holds IBAN and
# CREDITCARD), and national ids (SSN, AADHAAR, PAN: no fix needs one, and a leak cannot be undone) - thrown away after
# masking.
NEVER_SEALED = frozenset({"PRIVKEY", "JWT", "APIKEY", "GCPTOKEN", "AZURESAS", "WEBHOOK", "URLCRED", "BEARER", "BASIC",
                          "SECRET", "HIGHENTROPY", "IBAN", "CREDITCARD", "SSN", "AADHAAR", "PAN"})
_MAC_MAX = 4096  # KMS GenerateMac's largest message, in bytes

_TABLE = ("CREATE TABLE IF NOT EXISTS vault (incident TEXT NOT NULL, sha256 TEXT NOT NULL, sealed_at TEXT NOT "
                 "NULL, expires_at TEXT NOT NULL, wrapped_key TEXT NOT NULL, sealed TEXT NOT NULL, "
                 "PRIMARY KEY (incident, sha256))")


def migrate(dsn: str, writer_role: str | None = None) -> None:
    """The vault's table on PostgreSQL (lambdas.migrate, after the audit's). Unlike the audit's tables it is not
    append-only: its rows expire. The runtime's writer - every zone's login - may read and add rows (ciphertext no zone
    but the approval page can open) and may NOT delete one: an AI zone must not be able to make a reveal impossible
    (review, 2026-10-20). Retention runs through PURGE, a function owned by the migration role that deletes only rows
    past their expiry by the database's own clock; an erasure is the database owner's (procedure planned on
    the data-egress page, added by #121)."""
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
            db.execute(sql.SQL("GRANT SELECT, INSERT ON vault TO {}").format(who))
        db.execute(_PURGE_FUNCTION)
        db.execute("REVOKE ALL ON FUNCTION warden_vault_purge() FROM PUBLIC")
        if writer_role:
            db.execute(sql.SQL("GRANT EXECUTE ON FUNCTION warden_vault_purge() TO {}").format(who))


# Expired by the database's clock, never a caller's: a time passed in could be any time, and purge every row. The
# expiry is written as Python's isoformat (`2026-10-21T07:00:00+00:00`), which compares as text in time order.
_PURGE_FUNCTION = (
    "CREATE OR REPLACE FUNCTION warden_vault_purge() RETURNS integer LANGUAGE plpgsql SECURITY DEFINER "
    "SET search_path = pg_catalog, public AS $f$ DECLARE n integer; BEGIN "
    "DELETE FROM public.vault WHERE expires_at COLLATE \"C\" < to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS') "
    "|| '+00:00'; GET DIAGNOSTICS n = ROW_COUNT; RETURN n; END $f$")


def days() -> int:
    """How long a sealed map is kept: WARDEN_VAULT_DAYS, never less than the audit's 180 days nor more than ten
    years."""
    raw = os.environ.get("WARDEN_VAULT_DAYS", "").strip()
    return min(MAX_DAYS, max(MIN_DAYS, int(raw))) if raw.isdigit() else MIN_DAYS


def key_id(env: dict[str, str] | None = None, *, kind: str = "vault") -> str:
    """The vault key (`kind` "vault") or the pseudonym HMAC key ("pseudonym"): WARDEN_VAULT_KMS_KEY_ID /
    WARDEN_PSEUDONYM_KMS_KEY_ID, else the runtime module's alias for WARDEN_ENV's runtime; "" for none."""
    env = os.environ if env is None else env
    explicit = env.get(f"WARDEN_{kind.upper()}_KMS_KEY_ID", "").strip()
    runtime = env.get("WARDEN_ENV", "").strip()
    return explicit or (f"alias/warden-{runtime}-{kind}" if runtime else "")


def kind_of(placeholder: str) -> str:
    return placeholder.strip("<>").rsplit("_", 1)[0]


def sealable(mapping: dict[str, str]) -> dict[str, str]:
    """The part of a run's map that may be sealed: SEALED_KINDS only. Anything else is never kept."""
    return {p: v for p, v in mapping.items() if kind_of(p) in SEALED_KINDS}


def pseudonym(mac: bytes, kind: str) -> str:
    """`email:3f9a0c7d21b4` from the value's HMAC - the same for the same value in every incident of the environment;
    nothing of the value."""
    return f"{kind.lower()}:{mac.hex()[:12]}"


def _context(purpose: str, environment: str, incident: str = "") -> dict[str, str]:
    return {"purpose": purpose, "environment": environment, **({"incident": incident} if incident else {})}


@dataclass
class Vault:
    """One environment's vault: its KMS key, the pseudonym HMAC key's id, and the KMS client (boto3's, or a fake with
    the same calls)."""

    key: str
    environment: str
    kms: Any
    mac_key: str = ""
    _macs: dict[bytes, str] = field(default_factory=dict)  # keyed by a digest: the process keeps no value

    @classmethod
    def from_environment(cls, kms: Any = None) -> Vault | None:
        """This process's vault, built once; None without a vault key."""
        key = key_id()
        if not key:
            return None
        environment = os.environ.get("WARDEN_ENV", "").strip() or "local"
        if kms is not None:
            return cls(key=key, environment=environment, kms=kms, mac_key=key_id(kind="pseudonym"))
        cached = _BUILT.get((key, environment))
        if cached is None:
            import boto3

            from .environments import region

            where = region()  # the runtime's own region, as every other client of WARDEN's (audit._pg_connect)
            cached = _BUILT[(key, environment)] = cls(key=key, environment=environment,
                                                      kms=boto3.client("kms", region_name=where),
                                                      mac_key=key_id(kind="pseudonym"))
        return cached

    def pseudonym_of(self, kind: str, value: str) -> str:
        """The value's stable id: KMS computes the HMAC with the environment's key, which never leaves KMS. "" without
        a pseudonym key."""
        if not self.mac_key:
            return ""
        message = f"{kind}\x00{value}".encode()
        if len(message) > _MAC_MAX:  # beyond what KMS takes: its SHA-256 stands for it, as stable
            message = f"{kind}\x00sha256:{hashlib.sha256(message).hexdigest()}".encode()
        slot = hashlib.sha256(message).digest()
        if slot not in self._macs:
            if len(self._macs) >= 4096:
                self._macs.clear()  # a bound on what one process keeps; KMS answers again
            mac = self.kms.generate_mac(KeyId=self.mac_key, MacAlgorithm="HMAC_SHA_256", Message=message)["Mac"]
            self._macs[slot] = pseudonym(mac, kind)
        return self._macs[slot]

    def index(self, mapping: dict[str, str]) -> list[dict[str, str]]:
        """What the records page may show without a reveal: each placeholder, its kind and its pseudonym."""
        out = []
        for p, v in sorted(mapping.items(), key=lambda kv: (kind_of(kv[0]), _number(kv[0]))):
            pid = self.pseudonym_of(kind_of(p), v)
            out.append({"placeholder": p, "kind": kind_of(p), **({"pseudonym": pid} if pid else {})})
        return out

    def seal(self, incident: str, mapping: dict[str, str], now: datetime | None = None) -> dict[str, Any]:
        """The sealed row for `mapping`'s sealable part (the database's), with its index and hash (the audit's)."""
        mapping = sealable(mapping)
        if not mapping:
            raise ValueError("nothing sealable in this map")
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
    """What opening or storing a sealed row can fail with: KMS refusing or unreachable, the database's errors, a
    malformed parameter, a ciphertext whose tag does not verify (InvalidTag)."""
    import sqlite3

    errors: list[type[BaseException]] = [OSError, ValueError, KeyError, TypeError, sqlite3.Error]
    for module, names in (("botocore.exceptions", ("BotoCoreError", "ClientError")), ("psycopg", ("Error",)),
                          ("cryptography.exceptions", ("InvalidTag",))):
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
    try:
        purge(log, datetime.fromisoformat(row["sealed_at"]))
    except _SEAL_ERRORS as exc:  # the seal stands: the next seal purges again
        log.append(row["incident"], PURGE_FAILED, {"run_id": run_id, "error": type(exc).__name__})
    return row["sha256"]


def purge(log: Any, now: datetime | None = None) -> int:
    """Delete every vault row past its expiry. The number deleted. On PostgreSQL through warden_vault_purge(), by the
    database's clock (the writer may not delete); `now` is the local SQLite file's clock."""
    if log.store.pg:
        row = log.store.run("SELECT warden_vault_purge()").fetchone()
        return int(row[0]) if row else 0
    when = (now or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="seconds")
    return log.store.run("DELETE FROM vault WHERE expires_at < ?", (when,)).rowcount


# One complete statement per dialect: on PostgreSQL the expiry compares in byte order (COLLATE "C"), as the audit
# compares times; SQLite's text comparison is byte order already.
_SEALED_ROW_SQLITE = ("SELECT incident, sha256, sealed_at, expires_at, wrapped_key, sealed FROM vault "
                      "WHERE incident = ? AND sha256 = ? AND expires_at >= ?")
_SEALED_ROW_PG = ("SELECT incident, sha256, sealed_at, expires_at, wrapped_key, sealed FROM vault "
                  'WHERE incident = ? AND sha256 = ? AND expires_at COLLATE "C" >= ?')


def sealed_row(log: Any, incident: str, sha256: str, now: datetime | None = None) -> dict[str, Any] | None:
    """The sealed row the audit's index row names; None when it has expired or was erased. Expired is judged here
    too, as purge judges it: a row past its expiry that no purge has reached yet is not read (review)."""
    if not log.store.pg:
        log.store.run(_TABLE)
    when = (now or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="seconds")
    query = _SEALED_ROW_PG if log.store.pg else _SEALED_ROW_SQLITE
    got = log.store.run(query, (incident, sha256, when)).fetchone()
    return dict(zip(_COLUMNS, got, strict=True)) if got else None


def seal_incident(log: Any, incident: str, mapping: dict[str, str], *, run_id: str = "",
                  vault: Vault | None = None) -> str:
    """`prepare`'s one call: seal this run's map (its SEALED_KINDS part) and record it; "" when there is no vault or
    nothing to seal. A seal that fails is recorded by its type and the incident goes on (the values stay masked; only
    the reveal is lost). Any failure, not only _SEAL_ERRORS: an environment not configured or a date out of range
    must not stop an incident either (review, 2026-10-20)."""
    mapping = sealable(mapping)
    if not mapping:
        return ""
    try:
        vault = vault or Vault.from_environment()
        if vault is None:
            return ""
        return store(log, vault.seal(incident, mapping), run_id)
    except Exception as exc:  # noqa: BLE001  # whatever stops a seal, the incident goes on (the map is discarded)
        log.append(incident, UNAVAILABLE, {"run_id": run_id, "error": type(exc).__name__, "values": len(mapping)})
        return ""
