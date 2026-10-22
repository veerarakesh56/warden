"""The sealed vault (owner, 2026-10-20): the real values behind an incident's placeholders are sealed where they are
found, only a person's reveal can open them, no AI zone can reach them, and they expire.

KMS is a fake that holds the vault key's policy (terraform/modules/warden-runtime/vault.tf) as data - which role may
do what, for which purpose - and the policy itself is checked against the Terraform below. Canaries are built from
parts (tests/fakes.py's rule)."""

from __future__ import annotations

import base64
import hashlib
import hmac
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

# The key policies, as the fake enforces them: (role, action, purpose). The read zone has no Decrypt at all.
POLICY = {("read", "GenerateDataKey", "vault"), ("read", "GenerateMac", None), ("approval", "Decrypt", "vault")}


def AccessDenied(message: str = "") -> ClientError:  # what boto3 raises for a refusal by the key policy
    return ClientError({"Error": {"Code": "AccessDeniedException", "Message": message}}, "kms")


class FakeKms:
    """KMS for one role. A ciphertext is bound to its encryption context, as KMS binds it."""

    _mac_key = os.urandom(32)  # the environment's HMAC key: inside "KMS", never handed out

    def __init__(self, role: str, mac_key: bytes | None = None):
        self.role = role
        self.mac_key = mac_key or self._mac_key
        self.calls: list[tuple[str, dict]] = []
        self.messages: list[bytes] = []

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

    def generate_mac(self, *, KeyId, MacAlgorithm, Message):
        self._allow("GenerateMac", {})
        assert MacAlgorithm == "HMAC_SHA_256"
        if len(Message) > 4096:  # KMS's own limit
            raise ClientError({"Error": {"Code": "ValidationException", "Message": "too long"}}, "kms")
        self.messages.append(Message)
        return {"Mac": hmac.new(self.mac_key, Message, hashlib.sha256).digest()}

    def decrypt(self, *, CiphertextBlob, KeyId, EncryptionContext):
        self._allow("Decrypt", EncryptionContext)
        blob = json.loads(CiphertextBlob)
        if blob["c"] != EncryptionContext:
            raise AccessDenied("InvalidCiphertextException: another context")
        return {"Plaintext": base64.b64decode(blob["k"])}


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("WARDEN_ENV", "ops")
    monkeypatch.delenv("WARDEN_VAULT_KMS_KEY_ID", raising=False)
    monkeypatch.setattr("warden.environments.region", lambda: "test-region-1")


def _vault(role: str, mac_key: str = "alias/warden-ops-pseudonym", kms: FakeKms | None = None) -> vault.Vault:
    return vault.Vault(key="alias/warden-ops-vault", environment="ops", kms=kms or FakeKms(role), mac_key=mac_key)


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


def test_the_vault_reaches_kms_in_warden_own_account_only_and_its_ledger_rows_hold_no_value(tmp_path):
    """Egress (#104): the vault's only network client is KMS in WARDEN's own account (the "aws" destination, by
    name). Each KMS request is checked on its REAL parameters: the data key's encryption context (CloudTrail
    keeps it in clear) holds no value the redactor finds; only GenerateMac's message carries a value, to the HMAC
    key that never leaves KMS. The audit's index row - what the records page shows - holds none either."""
    from warden import egress

    dest = egress.destination_of("kms.ap-south-2.amazonaws.com")
    assert dest is not None
    assert dest.name == "aws"
    assert not dest.outside
    kms, log = FakeKms("read"), AuditLog(tmp_path / "a.db")
    row = _vault("read", kms=kms).seal("inc-1", MAPPING)
    vault.store(log, row)
    assert {action for action, _ in kms.calls} == {"GenerateDataKey", "GenerateMac"}
    for action, params in kms.calls:
        assert egress.kinds_in(json.dumps(params)) == [], action
    assert len(kms.messages) == len(MAPPING)  # one HMAC per value: the only request that carries one
    entries = json.dumps(row["index"])
    assert egress.kinds_in(entries) == []
    assert not any(value in entries for value in MAPPING.values())


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
    assert a[0]["pseudonym"] == b[0]["pseudonym"]
    assert b[0]["pseudonym"] != b[1]["pseudonym"]
    assert re.fullmatch(r"email:[0-9a-f]{12}", a[0]["pseudonym"])
    assert "canary" not in a[0]["pseudonym"]
    other = _vault("read", kms=FakeKms("read", os.urandom(32))).index({"<EMAIL_1>": EMAIL})
    assert other[0]["pseudonym"] != a[0]["pseudonym"]  # another environment's key: no correlation across environments


def test_without_a_pseudonym_key_the_index_has_no_ids():
    assert "pseudonym" not in _vault("read", mac_key="").index({"<EMAIL_1>": EMAIL})[0]


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


def test_a_row_past_its_expiry_is_not_read_before_any_purge(tmp_path, monkeypatch):
    """Review: sealed_row read a row past its expiry until a later seal's purge deleted it."""
    monkeypatch.delenv("WARDEN_VAULT_DAYS", raising=False)
    log = AuditLog(tmp_path / "a.db")
    then = datetime(2026, 1, 1, tzinfo=UTC)
    row = _vault("read").seal("inc-old", MAPPING, now=then)
    vault.store(log, row)  # its own purge runs at `then`: the row is kept
    expiry = datetime.fromisoformat(row["expires_at"])
    assert vault.sealed_row(log, "inc-old", row["sha256"], now=expiry) is not None  # the last moment it is kept
    assert vault.sealed_row(log, "inc-old", row["sha256"], now=expiry + timedelta(seconds=1)) is None
    assert vault.sealed_row(log, "inc-old", row["sha256"]) is None  # today: long past


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

    clients = {"kms": kms}
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


def _resource(name: str) -> str:
    start = VAULT_TF.index(f'resource "{name}"')
    end = VAULT_TF.find("\nresource ", start + 1)
    return VAULT_TF[start:end if end >= 0 else len(VAULT_TF)]


def _statements(key: str = "aws_kms_key\" \"vault") -> dict[str, str]:
    return {m.group(1): m.group(0) for m in re.finditer(r'Sid\s*=\s*"(\w+)"[\s\S]*?\n      }', _resource(key))}


def test_the_key_policy_lets_only_the_read_zone_seal_and_only_a_persons_reveal_open():
    st = _statements()
    assert set(st) == {"AdministerNeverRead", "TheReadZoneSeals", "OnlyAPersonsRevealOpens"}
    decrypt = {sid for sid, s in st.items() if "kms:Decrypt" in s}
    assert decrypt == {"OnlyAPersonsRevealOpens"}  # owner, 2026-10-21: the read zone has none either
    assert 'aws_iam_role.front_door["approval"]' in st["OnlyAPersonsRevealOpens"]
    assert '"kms:EncryptionContext:purpose" = "vault"' in st["OnlyAPersonsRevealOpens"]
    assert 'aws_iam_role.zone["read"]' in st["TheReadZoneSeals"]
    assert "kms:GenerateDataKey\"" in st["TheReadZoneSeals"]
    mac = _statements('aws_kms_key" "pseudonym')
    assert set(mac) == {"AdministerNeverUse", "TheReadZoneComputesIds"}
    assert '"kms:GenerateMac"' in mac["TheReadZoneComputesIds"]
    assert 'aws_iam_role.zone["read"]' in mac["TheReadZoneComputesIds"]
    admin = VAULT_TF[VAULT_TF.index("vault_administration ="):VAULT_TF.index("]", VAULT_TF.index("vault_administration ="))]
    assert not re.search(r'"kms:(\*|Create\*|CreateGrant|Decrypt|Encrypt|GenerateDataKey|ReEncrypt|GenerateMac)', admin)
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
    assert asked == [("kms", "test-region-1")]


def test_the_vaults_kms_client_has_a_bounded_timeout_and_retry_budget(monkeypatch, env):
    """Review (PR 119): a degraded KMS fails a seal in seconds instead of holding `prepare` for its whole timeout."""
    import boto3

    configs = []
    monkeypatch.setattr(boto3, "client", lambda name, **kw: configs.append(kw.get("config")) or object())
    monkeypatch.setattr(vault, "_BUILT", {})
    vault.Vault.from_environment()
    [config] = configs
    assert config is not None
    assert (config.connect_timeout, config.read_timeout) == (vault.KMS_CONNECT_S, vault.KMS_READ_S)
    assert config.retries == {"max_attempts": vault.KMS_ATTEMPTS, "mode": "standard"}
    assert vault.KMS_CONNECT_S + vault.KMS_READ_S <= 30
    assert vault.KMS_ATTEMPTS <= 3


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


def test_what_eldane_is_given_to_read_holds_nothing_of_the_vault(tmp_path, monkeypatch, env):
    """Eldane (#42, now on main) reads only its READS kinds: each read back from an incident with sealed and failed
    vault rows holds none of them, and a vault kind cannot be read at all."""
    from warden import eldane

    log, _pack = _prepare(tmp_path, monkeypatch, FakeKms("read"))
    log.append("inc-001", vault.UNAVAILABLE, {"run_id": "r0", "error": "ClientError", "values": 1})
    [index] = log.entries("inc-001", kinds=(vault.INDEX,))
    marks = [index["body"]["sha256"], *(e["pseudonym"] for e in index["body"]["entries"])]
    shown = json.dumps([eldane._read(log, "inc-001", kind) for kind in eldane.READS])
    assert "incident.evidence" in eldane.READS
    assert shown != "[[], []]"  # the evidence was read: the check below is not of an empty page
    for mark in marks:
        assert mark not in shown
    for kind in (vault.INDEX, vault.UNAVAILABLE):
        with pytest.raises(ValueError, match="does not read"):
            eldane._read(log, "inc-001", kind)


# The modules a model is reached from, or that an AI's tools run in: none may import the vault or the reveal.
MODEL_FACING = ("llm.py", "providers.py", "graph.py", "discuss.py", "mcp_server.py", "eldane.py", "codefix.py",
                "code_fix.py", "routing.py")
# The activities that run a model (workflows.ZONES["llm"], and Eldane's critic zone once #42 lands).
MODEL_ACTIVITIES = ("diagnose", "discuss_answer", "critic_review")


def test_no_ai_zone_role_holds_decrypt_on_the_vault_key():
    """IAM, structurally (owner, 2026-10-21): the llm, critic, read, core, notify and act roles hold no kms:Decrypt on
    the vault key - in its key policy or in any role policy; the approval page's role is the only one."""
    module = ROOT / "terraform" / "modules" / "warden-runtime"
    for tf in module.glob("*.tf"):
        text = tf.read_text(encoding="utf-8")
        if tf.name == "vault.tf":
            continue
        assert "kms:Decrypt" not in text, tf.name  # no zone policy decrypts anything
    grants = [VAULT_TF[m.start():VAULT_TF.index("}", m.start())] for m in re.finditer(r'"kms:Decrypt"', VAULT_TF)]
    assert len(grants) == 2  # the key policy's statement and the approval role's policy, both purpose=vault
    assert _resource('aws_iam_role_policy" "vault_reveal').count("kms:Decrypt") == 1
    assert 'aws_iam_role.front_door["approval"]' in _resource('aws_iam_role_policy" "vault_reveal')
    assert "kms:Decrypt" not in _resource('aws_iam_role_policy" "vault_read_zone')
    assert "kms:Decrypt" not in _resource('aws_kms_key" "pseudonym')


def test_no_model_facing_code_path_imports_the_vault_or_the_reveal():
    """No module a model is reached from imports vault or reveal, and no activity that runs a model names them."""
    import ast

    src = ROOT / "src" / "warden"

    def imports(tree: ast.AST) -> set[str]:
        out = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                out |= {node.module or "", *(a.name for a in node.names)}
            elif isinstance(node, ast.Import):
                out |= {a.name for a in node.names}
        return {n.rsplit(".", 1)[-1] for n in out}

    for name in MODEL_FACING:
        path = src / name
        if path.exists():
            assert not imports(ast.parse(path.read_text("utf-8"))) & {"vault", "reveal"}, name
    tree = ast.parse((src / "activities.py").read_text("utf-8"))
    found = [f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef) and f.name in MODEL_ACTIVITIES]
    assert {f.name for f in found} >= {"diagnose", "discuss_answer"}
    for fn in found:
        names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)} | imports(fn)
        assert not names & {"vault", "reveal"}, fn.name


# --------------------------------------------------------------------------- what is sealed: personal data only


def test_every_redaction_kind_is_classified_sealed_or_never():
    """Owner-safe default (review, 2026-10-21): only personal data is sealed; secrets and financial numbers never are.
    A new redaction kind fails this until someone decides which it is."""
    from warden import redaction

    kinds = set(redaction._LABELS)
    assert vault.SEALED_KINDS | vault.NEVER_SEALED == kinds
    assert not vault.SEALED_KINDS & vault.NEVER_SEALED
    assert redaction.SECRET_KINDS <= vault.NEVER_SEALED
    status = {k: k in vault.SEALED_KINDS for k in sorted(kinds)}
    assert status == {
        "AADHAAR": False, "ACCOUNTID": True, "ADDRESS": True, "APIKEY": False, "ARN": True, "AZURESAS": False,
        "BASIC": False, "BEARER": False, "CREDITCARD": False, "EMAIL": True, "GCPTOKEN": False, "HIGHENTROPY": False,
        "HOSTNAME": True, "IBAN": False, "IPV4": True, "IPV6": True, "JWT": False, "MAC": True, "NAME": True,
        "PAN": False, "PHONE": True, "PRIVKEY": False, "SECRET": False, "SSN": False, "TENANT": True, "URLCRED": False,
        "UUID": True, "WEBHOOK": False}


SECRET_VALUE = "AKIA" + "IOSFODNN7EXAMPLE"
CARD = "4111" + "1111" + "1111" + "1111"


def test_a_secret_or_a_card_number_is_never_sealed(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    mixed = {"<EMAIL_1>": EMAIL, "<APIKEY_1>": SECRET_VALUE, "<CREDITCARD_1>": CARD, "<PRIVKEY_1>": "k" * 40}
    digest = vault.seal_incident(log, "inc-1", mixed, vault=_vault("read"))
    [index] = log.entries("inc-1", kinds=(vault.INDEX,))
    assert [e["placeholder"] for e in index["body"]["entries"]] == ["<EMAIL_1>"]
    assert _vault("approval").open(vault.sealed_row(log, "inc-1", digest)) == {"<EMAIL_1>": EMAIL}


def test_a_national_id_is_never_sealed_and_a_name_is(tmp_path):
    """Main's redactor (#110) added national ids and a person's name, address and internal host: the ids are
    thrown away after masking as a card number is; the rest is personal data a person may reveal."""
    log = AuditLog(tmp_path / "a.db")
    ssn, aadhaar, pan = "123-" + "45-" + "6789", "2345 " + "6789 " + "0123", "ABCPE" + "1234F"
    mixed = {"<NAME_1>": "Asha" + " Rao", "<SSN_1>": ssn, "<AADHAAR_1>": aadhaar, "<PAN_1>": pan}
    digest = vault.seal_incident(log, "inc-1", mixed, vault=_vault("read"))
    [index] = log.entries("inc-1", kinds=(vault.INDEX,))
    assert [e["placeholder"] for e in index["body"]["entries"]] == ["<NAME_1>"]
    assert _vault("approval").open(vault.sealed_row(log, "inc-1", digest)) == {"<NAME_1>": "Asha" + " Rao"}


def test_a_map_of_secrets_alone_seals_and_records_nothing(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    kms = FakeKms("read")
    assert vault.seal_incident(log, "inc-1", {"<APIKEY_1>": SECRET_VALUE}, vault=_vault("read", kms=kms)) == ""
    assert not log.entries("inc-1")
    assert not kms.calls  # not even an id was computed for it


def test_a_failed_purge_keeps_the_seal_and_is_recorded(tmp_path, monkeypatch):
    log = AuditLog(tmp_path / "a.db")

    def broken(*_a, **_k):
        raise OSError("purge refused")

    monkeypatch.setattr(vault, "purge", broken)
    digest = vault.seal_incident(log, "inc-1", MAPPING, vault=_vault("read"))
    assert digest
    assert log.entries("inc-1", kinds=(vault.INDEX,))
    assert not log.entries("inc-1", kinds=(vault.UNAVAILABLE,))
    [row] = log.entries("inc-1", kinds=(vault.PURGE_FAILED,))
    assert row["body"]["error"] == "OSError"


def test_a_value_longer_than_kms_takes_still_gets_a_stable_id():
    kms = FakeKms("read")
    long_value = "x" * 5000 + "@" + "example.org"
    first = _vault("read", kms=kms).pseudonym_of("EMAIL", long_value)
    again = _vault("read", kms=kms).pseudonym_of("EMAIL", long_value)
    assert first == again
    assert re.fullmatch(r"email:[0-9a-f]{12}", first)
    assert len(kms.messages[-1]) <= 4096  # what KMS was asked stays within its limit


def test_the_id_cache_keeps_no_value():
    v = _vault("read")
    v.pseudonym_of("EMAIL", EMAIL)
    assert EMAIL not in repr(v._macs)
    assert all(isinstance(k, bytes) for k in v._macs)


def test_a_discussions_re_read_seals_nothing(tmp_path, monkeypatch, env):
    import boto3

    from warden.activities import IncidentActivities
    from warden.cli import DEMO_ALERTS
    from warden.models import Alert

    kms = FakeKms("read")
    monkeypatch.setattr(boto3, "client", lambda name, *a, **k: {"kms": kms}[name])
    monkeypatch.setattr(vault, "_BUILT", {})
    log = AuditLog(tmp_path / "a.db")
    alert = Alert(**{**DEMO_ALERTS["inc-001"], "alert_id": "discuss-inc-001"})
    pack = IncidentActivities(audit=log).prepare(alert)
    assert pack.masked > 0  # there was something it could have sealed
    assert not log.entries("discuss-inc-001", kinds=(vault.INDEX, vault.UNAVAILABLE))
    assert not kms.calls
