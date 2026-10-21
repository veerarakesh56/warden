"""The sealed vault (owner, 2026-10-20): the real values behind an incident's placeholders are sealed where they are
found, only a person's reveal can open them, no AI zone can reach them, and they expire.

KMS is a fake that holds the vault key's policy (terraform/modules/warden-runtime/vault.tf) as data - which role may
do what, for which purpose - and the policy itself is checked against the Terraform below. Canaries are built from
parts (tests/fakes.py's rule)."""

from __future__ import annotations

import base64
import json
import os
import pathlib
import re
from datetime import UTC, datetime, timedelta

import pytest
from botocore.exceptions import ClientError

from warden import vault
from warden.audit import AuditLog

ROOT = pathlib.Path(__file__).resolve().parents[1]
VAULT_TF = (ROOT / "terraform" / "modules" / "warden-runtime" / "vault.tf").read_text(encoding="utf-8")
EMAIL = "canary.person" + "@" + "example.org"
IP = "203.0.113." + "77"
MAPPING = {"<EMAIL_1>": EMAIL, "<IPV4_1>": IP, "<TENANT_1>": "acme" + "-42"}

# The key policy, as the fake enforces it: (role, action, purpose).
POLICY = {("read", "GenerateDataKey", "vault"), ("read", "Decrypt", "pseudonym"), ("approval", "Decrypt", "vault")}


def AccessDenied(message: str = "") -> ClientError:  # what boto3 raises for a refusal by the key policy
    return ClientError({"Error": {"Code": "AccessDeniedException", "Message": message}}, "kms")


class FakeKms:
    """KMS for one role. A ciphertext is bound to its encryption context, as KMS binds it."""

    _master = os.urandom(32)

    def __init__(self, role: str):
        self.role = role
        self.calls: list[tuple[str, dict]] = []

    def _allow(self, action: str, context: dict) -> None:
        self.calls.append((action, context))
        if (self.role, action, context.get("purpose")) not in POLICY:
            raise AccessDenied(f"{self.role} may not {action} for {context.get('purpose')}")

    def _wrap(self, key: bytes, context: dict) -> bytes:
        return json.dumps({"k": base64.b64encode(key).decode(), "c": context}).encode()

    def generate_data_key(self, *, KeyId, KeySpec, EncryptionContext):
        self._allow("GenerateDataKey", EncryptionContext)
        key = os.urandom(32)
        return {"Plaintext": key, "CiphertextBlob": self._wrap(key, EncryptionContext)}

    def decrypt(self, *, CiphertextBlob, KeyId, EncryptionContext):
        self._allow("Decrypt", EncryptionContext)
        blob = json.loads(CiphertextBlob)
        if blob["c"] != EncryptionContext:
            raise AccessDenied("InvalidCiphertextException: another context")
        return {"Plaintext": base64.b64decode(blob["k"])}


PSEUDONYM_KEY = os.urandom(32)


class FakeSsm:
    """The environment's settings path, holding the sealed pseudonym key."""

    def __init__(self, sealed: str | None):
        self.params = [] if sealed is None else [{"Name": "/warden/ops/env/" + vault.PSEUDONYM_PARAMETER,
                                                  "Value": sealed}]

    def get_paginator(self, _name):
        params = self.params

        class P:
            def paginate(self, **_kw):
                return [{"Parameters": params}]

        return P()


def _sealed_pseudonym_key() -> str:
    blob = json.dumps({"k": base64.b64encode(PSEUDONYM_KEY).decode(),
                       "c": {"purpose": "pseudonym", "environment": "ops"}}).encode()
    return base64.b64encode(blob).decode()


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("WARDEN_ENV", "ops")
    monkeypatch.delenv("WARDEN_VAULT_KMS_KEY_ID", raising=False)
    monkeypatch.setattr("warden.environments.region", lambda: "test-region-1")


def _vault(role: str, ssm: FakeSsm | None = None) -> vault.Vault:
    return vault.Vault(key="alias/warden-ops-vault", environment="ops", kms=FakeKms(role),
                       ssm=ssm if ssm is not None else FakeSsm(_sealed_pseudonym_key()))


# --------------------------------------------------------------------------- sealing and opening


def test_the_read_zone_seals_and_cannot_open(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    row = _vault("read").seal("inc-1", MAPPING)
    vault.store(log, row)
    stored, reader = vault.sealed_row(log, "inc-1", row["sha256"]), _vault("read")
    with pytest.raises(ClientError):
        reader.open(stored)


def test_only_the_approval_page_opens_a_sealed_map(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    digest = vault.store(log, _vault("read").seal("inc-1", MAPPING))
    assert _vault("approval").open(vault.sealed_row(log, "inc-1", digest)) == MAPPING
    stored = vault.sealed_row(log, "inc-1", digest)
    for ai_zone in ("llm", "critic", "notify", "core", "act"):
        zone = _vault(ai_zone)
        with pytest.raises(ClientError):
            zone.open(stored)


def test_a_sealed_map_opens_only_as_its_own_incidents():
    row, opener = _vault("read").seal("inc-1", MAPPING), _vault("approval")
    moved, changed = {**row, "incident": "inc-2"}, {**row, "sha256": "0" * 64}
    with pytest.raises(ClientError):  # the wrapped key is bound to its incident
        opener.open(moved)
    with pytest.raises(ValueError, match="hash"):
        opener.open(changed)


def test_nothing_but_the_index_and_a_hash_is_on_the_signed_audit(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    digest = vault.store(log, _vault("read").seal("inc-1", MAPPING), run_id="r1")
    [row] = log.entries("inc-1", kinds=(vault.INDEX,))
    text = json.dumps(row["body"])
    assert all(v not in text for v in MAPPING.values())
    assert row["body"]["sha256"] == digest
    assert [e["placeholder"] for e in row["body"]["entries"]] == ["<EMAIL_1>", "<IPV4_1>", "<TENANT_1>"]
    stored = vault.sealed_row(log, "inc-1", digest)
    assert all(v not in json.dumps(stored) for v in MAPPING.values())  # the database holds ciphertext only


def test_pseudonyms_are_stable_across_incidents_and_reveal_nothing():
    a = _vault("read").index({"<EMAIL_1>": EMAIL})
    b = _vault("read").index({"<EMAIL_7>": EMAIL, "<EMAIL_8>": "other" + "@" + "example.org"})
    assert a[0]["pseudonym"] == b[0]["pseudonym"] != b[1]["pseudonym"]
    assert re.fullmatch(r"email:[0-9a-f]{12}", a[0]["pseudonym"])
    assert "canary" not in a[0]["pseudonym"]
    other_key = vault.pseudonym(os.urandom(32), "EMAIL", EMAIL)
    assert other_key != a[0]["pseudonym"]  # another environment's key: no correlation across environments


def test_without_a_pseudonym_key_the_index_has_no_ids():
    assert "pseudonym" not in _vault("read", FakeSsm(None)).index({"<EMAIL_1>": EMAIL})[0]


def test_a_sealed_map_expires_and_is_deleted(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDEN_VAULT_DAYS", raising=False)
    log = AuditLog(tmp_path / "a.db")
    then = datetime(2026, 1, 1, tzinfo=UTC)
    old = _vault("read").seal("inc-old", MAPPING, now=then)
    vault.store(log, old)
    assert old["expires_at"] == (then + timedelta(days=180)).isoformat(timespec="seconds")
    vault.store(log, _vault("read").seal("inc-new", MAPPING, now=then + timedelta(days=181)))
    assert vault.sealed_row(log, "inc-old", old["sha256"]) is None  # gone; its audit index stays
    assert log.entries("inc-old", kinds=(vault.INDEX,))


@pytest.mark.parametrize(("raw", "days"), [("30", 180), ("365", 365), ("x", 180), ("", 180), ("9" * 30, 3650)])
def test_retention_is_never_shorter_than_the_audits(monkeypatch, raw, days):
    monkeypatch.setenv("WARDEN_VAULT_DAYS", raw)
    assert vault.days() == days


def test_the_key_is_named_by_the_runtime_or_set(monkeypatch):
    monkeypatch.delenv("WARDEN_VAULT_KMS_KEY_ID", raising=False)
    monkeypatch.delenv("WARDEN_ENV", raising=False)
    assert vault.key_id() == ""
    monkeypatch.setenv("WARDEN_ENV", "ops")
    assert vault.key_id() == "alias/warden-ops-vault"


# --------------------------------------------------------------------------- prepare


def _prepare(tmp_path, monkeypatch, kms):
    import boto3

    from warden.activities import IncidentActivities
    from warden.cli import DEMO_ALERTS
    from warden.models import Alert

    clients = {"kms": kms, "ssm": FakeSsm(_sealed_pseudonym_key())}
    monkeypatch.setattr(boto3, "client", lambda name, *a, **k: clients[name])
    monkeypatch.setattr(vault, "_BUILT", {})
    log = AuditLog(tmp_path / "a.db")
    pack = IncidentActivities(audit=log).prepare(Alert(**DEMO_ALERTS["inc-001"]))
    return log, pack


def test_prepare_seals_the_map_and_returns_none_of_it(tmp_path, monkeypatch, env):
    log, pack = _prepare(tmp_path, monkeypatch, FakeKms("read"))
    [index] = log.entries("inc-001", kinds=(vault.INDEX,))
    assert len(index["body"]["entries"]) == pack.masked > 0
    returned = pack.model_dump_json()  # what Temporal would carry
    assert "priya.nair" not in returned
    assert index["body"]["sha256"] not in returned
    opened = _vault("approval").open(vault.sealed_row(log, "inc-001", index["body"]["sha256"]))
    assert "priya.nair@corp.io" in opened.values()


def test_a_failed_seal_is_recorded_and_the_incident_goes_on(tmp_path, monkeypatch, env):
    log, pack = _prepare(tmp_path, monkeypatch, FakeKms("llm"))  # a role the key refuses
    [row] = log.entries("inc-001", kinds=(vault.UNAVAILABLE,))
    assert row["body"]["error"] == "ClientError"
    assert row["body"]["values"] == pack.masked
    assert not log.entries("inc-001", kinds=(vault.INDEX,))
    assert pack.prompt  # the incident went on


def test_without_a_vault_nothing_is_sealed(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDEN_ENV", raising=False)
    monkeypatch.delenv("WARDEN_VAULT_KMS_KEY_ID", raising=False)
    log, _ = _prepare(tmp_path, monkeypatch, FakeKms("read"))
    assert not log.entries("inc-001", kinds=(vault.INDEX, vault.UNAVAILABLE))


# --------------------------------------------------------------------------- no AI zone can reach it


def _statements() -> dict[str, str]:
    key = VAULT_TF.split('resource "aws_kms_alias"', 1)[0]
    return {m.group(1): m.group(0) for m in re.finditer(r'Sid\s*=\s*"(\w+)"[\s\S]*?\n      }', key)}


def test_the_key_policy_lets_only_the_read_zone_seal_and_only_a_persons_reveal_open():
    st = _statements()
    assert set(st) == {"AdministerNeverRead", "MakeThePseudonymKeyUnseen", "TheReadZoneSeals",
                       "TheReadZoneOpensThePseudonymKey", "OnlyAPersonsRevealOpens"}
    decrypt = {sid for sid, s in st.items() if "kms:Decrypt" in s}
    assert decrypt == {"TheReadZoneOpensThePseudonymKey", "OnlyAPersonsRevealOpens"}
    assert 'aws_iam_role.front_door["approval"]' in st["OnlyAPersonsRevealOpens"]
    assert '"kms:EncryptionContext:purpose" = "vault"' in st["OnlyAPersonsRevealOpens"]
    assert '"kms:EncryptionContext:purpose" = "pseudonym"' in st["TheReadZoneOpensThePseudonymKey"]
    assert 'aws_iam_role.zone["read"]' in st["TheReadZoneSeals"]
    assert "kms:GenerateDataKey\"" in st["TheReadZoneSeals"]
    admin = st["AdministerNeverRead"]
    assert not re.search(r'"kms:(\*|Create\*|CreateGrant|Decrypt|Encrypt|GenerateDataKey|ReEncrypt)', admin)
    assert "CreateGrant" not in VAULT_TF.replace("that takes in CreateGrant", "")  # no statement grants it


def test_no_ai_zone_is_named_by_the_vault_key_or_given_it():
    """The llm zone (diagnosis, discussion chat), Eldane's critic zone and every other zone: not a principal of the
    key, and no IAM grant of it."""
    principals = set(re.findall(r'aws_iam_role\.(\w+)\["(\w+)"\]', VAULT_TF))
    assert principals == {("zone", "read"), ("front_door", "approval")}
    module = ROOT / "terraform" / "modules" / "warden-runtime"
    for tf in module.glob("*.tf"):
        if tf.name != "vault.tf":
            assert "aws_kms_key.vault" not in tf.read_text(encoding="utf-8"), tf.name


def test_the_vault_rows_are_on_no_ai_reading_list():
    """What an AI may read from the audit is a list of kinds; the vault's are on none of them."""
    import importlib

    src = ROOT / "src" / "warden"
    reads = re.findall(r"kinds=\(([^)]*)\)", (src / "activities.py").read_text(encoding="utf-8"))
    assert all(vault.INDEX not in r for r in reads)
    try:
        eldane = importlib.import_module("warden.eldane")
    except ImportError:
        return  # Eldane (#42) not merged yet
    assert vault.INDEX not in eldane.READS
    assert vault.UNAVAILABLE not in eldane.READS


def test_only_people_paths_open_the_vault():
    """A static check: `.open(` of a sealed row appears in vault.py and in the reveal alone - never in a module an AI
    zone runs (activities' llm activities, eldane, discuss, the MCP server, providers)."""
    src = ROOT / "src" / "warden"
    callers = {p.name for p in src.rglob("*.py")
               if re.search(r"vault\.(?:Vault|sealed_row)\b|import[^\n]*\bVault\b|\bVault\(", p.read_text(encoding="utf-8"))}
    assert callers <= {"vault.py", "records.py", "approval_page.py"}


def test_any_failure_of_a_seal_is_recorded_and_returns(tmp_path):
    """Not only KMS's and the database's errors: an environment not configured, a date out of range (review)."""
    class Broken:
        def seal(self, *_a, **_k):
            raise OverflowError("date value out of range")

    log = AuditLog(tmp_path / "a.db")
    assert vault.seal_incident(log, "inc-1", MAPPING, vault=Broken()) == ""
    [row] = log.entries("inc-1", kinds=(vault.UNAVAILABLE,))
    assert row["body"]["error"] == "OverflowError"


def test_the_vaults_clients_are_in_the_runtimes_region(monkeypatch, env):
    import boto3

    asked = []
    monkeypatch.setattr(boto3, "client", lambda name, **kw: asked.append((name, kw.get("region_name"))) or object())
    monkeypatch.setattr(vault, "_BUILT", {})
    vault.Vault.from_environment()
    assert asked == [("kms", "test-region-1"), ("ssm", "test-region-1")]



def test_on_postgresql_the_writer_purges_through_the_function_by_the_databases_clock():
    """The runtime's writer may not delete a vault row (review): retention calls warden_vault_purge(), which takes no
    time from its caller."""
    ran = []

    class Store:
        pg = True

        def run(self, sql, params=()):
            ran.append((sql, params))
            return type("R", (), {"fetchone": lambda self: (2,)})()

    assert vault.purge(type("Log", (), {"store": Store()})(), datetime(2099, 1, 1, tzinfo=UTC)) == 2
    assert ran == [("SELECT warden_vault_purge()", ())]
    assert "SECURITY DEFINER" in vault._PURGE_FUNCTION
    assert "now()" in vault._PURGE_FUNCTION
    assert "$1" not in vault._PURGE_FUNCTION


def test_what_an_ai_is_given_to_read_holds_nothing_of_the_vault(tmp_path, monkeypatch, env):
    """Behaviour, not only source: an incident sealed and a seal that failed both on the record, then the discussion's
    evidence (what its model is shown) read back - no vault row, id or hash in it."""
    from warden.activities import DiscussActivities

    log, pack = _prepare(tmp_path, monkeypatch, FakeKms("read"))
    log.append("inc-001", vault.UNAVAILABLE, {"run_id": "r0", "error": "ClientError", "values": 1})
    [index] = log.entries("inc-001", kinds=(vault.INDEX,))
    marks = [index["body"]["sha256"], *(e["pseudonym"] for e in index["body"]["entries"])]
    acts = DiscussActivities(audit=log, incident=type("I", (), {"prepare": None})())
    shown = json.dumps(acts.discuss_evidence("inc-001", False))
    assert pack.prompt in json.loads(shown)["evidence"]
    for mark in marks:
        assert mark not in shown
    assert "vault" not in shown
