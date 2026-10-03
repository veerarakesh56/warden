"""Register H6: approver impersonation. A passkey approval is a WebAuthn assertion over exactly one plan, verified by
py_webauthn - proven here against a software authenticator that produces real ceremonies (P-256, CBOR, signatures)."""

from __future__ import annotations

import hashlib
import json
import os
import struct
from datetime import UTC, datetime, timedelta

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from warden import passkeys

RP = "approve.example.test"
ORIGIN = f"https://{RP}"
NOW = datetime(2026, 10, 3, 9, 0, tzinfo=UTC)
UP, UV, BE, AT = 0x01, 0x04, 0x08, 0x40


class SoftAuthenticator:
    """A passkey in software: what a phone's secure element does, minus the hardware."""

    def __init__(self, *, synced=False, uv=True):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(16)
        self.count, self.synced, self.uv = 0, synced, uv

    def _flags(self, extra=0):
        return UP | (UV if self.uv else 0) | (BE if self.synced else 0) | extra

    def _cose(self):
        n = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def register(self, options_json, origin=ORIGIN):
        opts = json.loads(options_json)
        client = json.dumps({"type": "webauthn.create", "challenge": opts["challenge"], "origin": origin,
                             "crossOrigin": False}).encode()
        auth = (hashlib.sha256(opts["rp"]["id"].encode()).digest() + bytes([self._flags(AT)])
                + struct.pack(">I", self.count) + bytes(16) + struct.pack(">H", len(self.credential_id))
                + self.credential_id + self._cose())
        cid = bytes_to_base64url(self.credential_id)
        return {"id": cid, "rawId": cid, "type": "public-key", "response": {
            "clientDataJSON": bytes_to_base64url(client),
            "attestationObject": bytes_to_base64url(cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth}))}}

    def assert_(self, options_json, origin=ORIGIN, rp_id=RP):
        opts = json.loads(options_json)
        self.count += 1
        client = json.dumps({"type": "webauthn.get", "challenge": opts["challenge"], "origin": origin,
                             "crossOrigin": False}).encode()
        auth = hashlib.sha256(rp_id.encode()).digest() + bytes([self._flags()]) + struct.pack(">I", self.count)
        sig = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        cid = bytes_to_base64url(self.credential_id)
        return {"id": cid, "rawId": cid, "type": "public-key", "response": {
            "clientDataJSON": bytes_to_base64url(client), "authenticatorData": bytes_to_base64url(auth),
            "signature": bytes_to_base64url(sig), "userHandle": None}}


def _enrol(device, approver="owner"):
    options, challenge = passkeys.registration_options(rp_id=RP, rp_name="WARDEN", approver=approver)
    assert json.loads(options)["authenticatorSelection"]["userVerification"] == "required"
    return passkeys.finish_registration(device.register(options), approver=approver, challenge=challenge,
                                        rp_id=RP, origin=ORIGIN)


def _ask(cred, tier="T2", plan_hash="h" * 64, now=NOW):
    return passkeys.approval_options(rp_id=RP, credentials=[cred], workflow_id="rem-dev-1", plan_hash=plan_hash,
                                     tier=tier, now=now)


def test_an_enrolled_passkey_approves_exactly_the_plan_it_was_shown():
    device = SoftAuthenticator()
    cred = _enrol(device)
    assert cred.device_bound and cred.approver == "owner"
    options, pending = _ask(cred)
    expected = passkeys.challenge_for("rem-dev-1", "h" * 64, "T2", pending.nonce, pending.expires_at)
    assert base64url_to_bytes(json.loads(options)["challenge"]) == expected
    approval, problems = passkeys.verify_approval(device.assert_(options), pending=pending, credential=cred,
                                                  rp_id=RP, origin=ORIGIN, now=NOW, used_nonces=set())
    assert problems == [] and approval.plan_hash == "h" * 64 and approval.new_sign_count == 1


def test_an_assertion_for_one_plan_does_not_approve_another():
    device = SoftAuthenticator()
    cred = _enrol(device)
    options, _ = _ask(cred, plan_hash="a" * 64)
    _, other = _ask(cred, plan_hash="b" * 64)
    approval, problems = passkeys.verify_approval(device.assert_(options), pending=other, credential=cred,
                                                  rp_id=RP, origin=ORIGIN, now=NOW, used_nonces=set())
    assert approval is None and any("invalid" in p for p in problems)


@pytest.mark.parametrize(("attack", "reason"), [
    ("expired", "expired"),
    ("replayed", "already used"),
    ("wrong_origin", "Unexpected client data origin"),
    ("no_user_verification", "User verification is required"),
    ("other_key", "not owner's enrolled one"),
    ("cloned_counter", "was not greater than current count"),
    ("synced_for_t3", "device-bound"),
])
def test_each_impersonation_is_refused_for_its_own_reason(attack, reason):
    device = SoftAuthenticator(synced=attack == "synced_for_t3")
    cred = _enrol(device)
    if attack == "no_user_verification":
        device.uv = False  # enrolled with a fingerprint, asserting without one
    options, pending = _ask(cred, tier="T3" if attack == "synced_for_t3" else "T2")
    response = device.assert_(options, origin="https://evil.example.test" if attack == "wrong_origin" else ORIGIN)
    now, used = NOW, set()
    if attack == "expired":
        now = pending.expires_at + timedelta(seconds=1)
    if attack == "replayed":
        used = {pending.nonce}
    if attack == "other_key":  # the owner's enrolled passkey is another device
        cred = _enrol(SoftAuthenticator())
    if attack == "cloned_counter":  # the real key has signed 5 times; this copy says 1
        cred = passkeys.Credential(cred.approver, cred.credential_id, cred.public_key, 5, cred.device_bound)
    approval, problems = passkeys.verify_approval(response, pending=pending, credential=cred, rp_id=RP,
                                                  origin=ORIGIN, now=now, used_nonces=used)
    assert approval is None and any(reason in p for p in problems), (attack, problems)


def test_enrolment_needs_the_right_origin_and_user_verification():
    device = SoftAuthenticator()
    options, challenge = passkeys.registration_options(rp_id=RP, rp_name="WARDEN", approver="owner")
    with pytest.raises(passkeys.InvalidRegistrationResponse):
        passkeys.finish_registration(device.register(options, origin="https://evil.example.test"), approver="owner",
                                     challenge=challenge, rp_id=RP, origin=ORIGIN)
    lazy = SoftAuthenticator(uv=False)
    with pytest.raises(passkeys.InvalidRegistrationResponse):
        passkeys.finish_registration(lazy.register(options), approver="owner", challenge=challenge, rp_id=RP,
                                     origin=ORIGIN)
    assert _enrol(SoftAuthenticator(synced=True)).device_bound is False
