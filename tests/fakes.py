"""Credential-shaped test fixtures, each built from parts at run time.

2026-10-16 (naming audit, items 5 and 16): a test that proves a secret is masked needs a value with the secret's
shape, and a literal of that shape in a tracked file is exactly what gitleaks, trufflehog, GitHub push protection
and scripts/check_publishable.py exist to stop. The publish check used to skip seven whole files to make room for
such literals, so a real secret pasted into any of those files would have been published unscanned. Joining the
parts gives the same string at run time, so every assertion keeps its meaning, and no file holds the literal.
tests/test_fixture_literals.py fails the day one comes back.
"""

from __future__ import annotations

# AWS's own documented example key pair (the IAM user guide's "Manage access keys" page): the shape, never a key.
AWS_ACCESS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalr" + "XUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
# An operator's long-lived key id, the one the scenario harness must never pass on to WARDEN.
OPERATOR_ACCESS_KEY_ID = "AKIA" + "OPERATORKEYDONOTUSE"
# An HS256 JWT: header {"alg":"HS256"}, payload {"sub":"1234"}, and a made-up signature segment.
JWT = ".".join(("eyJ" + "hbGciOiJIUzI1NiJ9", "eyJ" + "zdWIiOiIxMjM0In0", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"))
# The stock fake password. Tests add to it, so each fixture stays a distinct value.
HUNTER2 = "hun" + "ter2"
# The prefix every Anthropic API key starts with.
ANTHROPIC_KEY_PREFIX = "sk-" + "ant-"


def private_key_block(kind: str, body: str) -> str:
    """An armoured private key around `body`: "RSA" gives the PEM form, "PGP" the PGP `PRIVATE KEY BLOCK` form."""
    label = f"{kind} PRIVATE KEY" + (" BLOCK" if kind == "PGP" else "")
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----"


def dsn(scheme: str, user: str, password: str, rest: str) -> str:
    """A connection string with its password inline: `scheme://user:<password>@rest`."""
    return f"{scheme}://{user}:" + f"{password}@{rest}"


class PlainKms:
    """KMS for the vault with no key policy and no botocore (the db job installs no AWS extra): a data key wrapped
    with its encryption context, an HMAC for ids, Decrypt bound to the same context. Every call is counted."""

    def __init__(self):
        import os

        self._mac_key = os.urandom(32)
        self.calls: list[str] = []

    def generate_data_key(self, *, KeyId, KeySpec, EncryptionContext):
        import base64
        import json
        import os

        self.calls.append("GenerateDataKey")
        key = os.urandom(32)
        return {"Plaintext": key,
                "CiphertextBlob": json.dumps({"k": base64.b64encode(key).decode(), "c": EncryptionContext}).encode()}

    def generate_mac(self, *, KeyId, MacAlgorithm, Message):
        import hashlib
        import hmac

        self.calls.append("GenerateMac")
        return {"Mac": hmac.new(self._mac_key, Message, hashlib.sha256).digest()}

    def decrypt(self, *, CiphertextBlob, KeyId, EncryptionContext):
        import base64
        import json

        self.calls.append("Decrypt")
        blob = json.loads(CiphertextBlob)
        if blob["c"] != EncryptionContext:
            raise ValueError("another encryption context")
        return {"Plaintext": base64.b64decode(blob["k"])}


def race_reveals(open_log, monkeypatch, *, parallel: int = 6, slots: int = 2, limit: int = 4):
    """Many approvers' tabs at once (concurrent Lambda invocations), each with its own audit connection from
    `open_log()`: `limit - slots` reveals already this hour, then `parallel` valid reveals together. Every count of
    the hourly limit waits for the others (a barrier with a timeout), so a check made apart from its write would let
    them all through. Returns the sorted statuses, the reveal rows and the Decrypt calls (review, PR 119)."""
    import threading
    import urllib.parse

    from warden import reveal, vault

    incident, member, cookie = "inc-race", "U" + "0RACE", "c" * 43
    email = "race.person" + "@" + "example.org"
    kms = PlainKms()
    sealer = vault.Vault(key="alias/warden-ops-vault", environment="ops", kms=kms,
                         mac_key="alias/warden-ops-pseudonym")
    log = open_log()
    vault.store(log, sealer.seal(incident, {"<EMAIL_1>": email}))
    for _ in range(limit - slots):
        log.append(incident, reveal.REVEAL, {"member": member, "placeholders": ["<EMAIL_1>"], "why": "earlier"})
    monkeypatch.setattr(reveal, "MAX_PER_HOUR", limit)
    opener = vault.Vault(key="alias/warden-ops-vault", environment="ops", kms=kms)
    barrier, counted = threading.Barrier(parallel), reveal._recent

    def waiting(*args, **kwargs):
        got = counted(*args, **kwargs)
        try:
            barrier.wait(timeout=1)
        except threading.BrokenBarrierError:
            pass  # a count made inside the writer's lock waits alone: it times out once, then never waits again
        return got

    monkeypatch.setattr(reveal, "_recent", waiting)
    # The admission is under test, not the HTML: the pages are rendered with records' shell, which imports the
    # approval page (webauthn) - not installed in the db job, where this runs against PostgreSQL.
    for page in ("form_page", "message_page", "revealed_page"):
        monkeypatch.setattr(reveal, page, lambda *_a, **_k: "")
    form = urllib.parse.urlencode([("reveal", "1"), ("t", reveal.token(cookie, incident)),
                                   ("why", "which customer the outage hit"), ("p", "<EMAIL_1>")])
    statuses: list[int] = []
    errors: list[BaseException] = []

    def one():
        mine = open_log()
        try:
            statuses.append(reveal.reveal(mine, incident, member=member, cookie=cookie, form=form, approver=True,
                                          opener=opener)[0])
        except Exception as exc:  # noqa: BLE001 - re-raised below, in the test's own thread
            errors.append(exc)
        finally:
            mine.close()

    threads = [threading.Thread(target=one) for _ in range(parallel)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    if errors:
        raise errors[0]
    rows = log.entries(incident, kinds=(reveal.REVEAL,))
    log.close()
    return sorted(statuses), len(rows), kms.calls.count("Decrypt")
