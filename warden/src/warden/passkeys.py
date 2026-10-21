"""Passkey approvals (decision D14, register H6): a person's WebAuthn assertion over exactly one plan of one workflow.

The authenticator signs a challenge that IS the plan: SHA-256 over the workflow id, the plan hash, the tier, a
single-use nonce and the expiry. So an assertion approves that plan and no other, once, until it expires - the
same binding as the Ed25519 break-glass approval in approvals.py, but the private key never leaves the person's
device, and using it needs their fingerprint, face or PIN (user verification is required, not preferred).

Verification is py_webauthn's (duo-labs, BSD-3-Clause, 3.0.1 read 2026-10-03): the signature, the RP ID hash, the
origin, the challenge, the flags. Added here: the expiry, the nonce used once, the credential belonging to the
approver it names, a signature counter that must not go backwards (a cloned key), and for T3 a device-bound key
- a synced passkey lives on every device of the account, so it alone may not approve the riskiest tier.

Honest limit: without attestation (none is requested yet), "device-bound" is what the authenticator says about
itself. Checking it against an AAGUID allowlist needs attestation and is the enrolment page's work (G5).
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    CredentialDeviceType,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

# How long an approval page's challenge stays valid (the link's own expiry, decision D14).
CHALLENGE_TTL = timedelta(minutes=15)
# Tiers only a device-bound passkey may approve.
DEVICE_BOUND_TIERS = frozenset({"T3"})


@dataclass(frozen=True)
class Credential:
    """One enrolled passkey: whose it is, its id and public key, its counter, and whether it is device-bound."""

    approver: str
    credential_id: str  # base64url
    public_key: str  # base64url COSE key
    sign_count: int
    device_bound: bool


@dataclass(frozen=True)
class Pending:
    """An approval challenge WARDEN issued and must find again: kept server-side, used once."""

    workflow_id: str
    plan_hash: str
    tier: str
    nonce: str
    expires_at: datetime
    challenge: str  # base64url


@dataclass(frozen=True)
class PasskeyApproval:
    approver: str
    workflow_id: str
    plan_hash: str
    tier: str
    nonce: str
    credential_id: str
    new_sign_count: int
    approved_at: datetime


def challenge_for(workflow_id: str, plan_hash: str, tier: str, nonce: str, expires_at: datetime) -> bytes:
    material = json.dumps({"workflow_id": workflow_id, "plan_hash": plan_hash, "tier": tier, "nonce": nonce,
                           "expires_at": expires_at.isoformat()}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode()).digest()


def registration_options(*, rp_id: str, rp_name: str, approver: str) -> tuple[str, bytes]:
    """Options for enrolling a passkey, and the challenge to keep until the response comes back."""
    challenge = secrets.token_bytes(32)
    options = generate_registration_options(
        rp_id=rp_id, rp_name=rp_name, user_name=approver, user_id=hashlib.sha256(approver.encode()).digest(),
        challenge=challenge, authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.REQUIRED))
    return options_to_json(options), challenge


def finish_registration(response: str | dict, *, approver: str, challenge: bytes, rp_id: str,
                        origin: str) -> Credential:
    """The enrolled credential, or InvalidRegistrationResponse. User verification is required at enrolment too."""
    verified = verify_registration_response(credential=response, expected_challenge=challenge, expected_rp_id=rp_id,
                                            expected_origin=origin, require_user_verification=True)
    return Credential(approver=approver, credential_id=bytes_to_base64url(verified.credential_id),
                      public_key=bytes_to_base64url(verified.credential_public_key), sign_count=verified.sign_count,
                      device_bound=verified.credential_device_type == CredentialDeviceType.SINGLE_DEVICE)


def approval_options(*, rp_id: str, credentials: list[Credential], workflow_id: str, plan_hash: str, tier: str,
                     now: datetime) -> tuple[str, Pending]:
    """The options an approval page hands the browser, and the pending challenge WARDEN keeps."""
    nonce = secrets.token_urlsafe(16)
    expires_at = now + CHALLENGE_TTL
    challenge = challenge_for(workflow_id, plan_hash, tier, nonce, expires_at)
    options = generate_authentication_options(
        rp_id=rp_id, challenge=challenge, timeout=int(CHALLENGE_TTL.total_seconds() * 1000),
        allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id)) for c in credentials],
        user_verification=UserVerificationRequirement.REQUIRED)
    return options_to_json(options), Pending(workflow_id=workflow_id, plan_hash=plan_hash, tier=tier, nonce=nonce,
                                             expires_at=expires_at, challenge=bytes_to_base64url(challenge))


def verify_approval(response: str | dict, *, pending: Pending, credential: Credential, rp_id: str, origin: str,
                    now: datetime, used_nonces: set[str]) -> tuple[PasskeyApproval | None, list[str]]:
    """The approval, or every reason it is refused. Never raises on a bad response: a refusal is a finding."""
    problems = []
    if now >= pending.expires_at:
        problems.append("the approval challenge has expired")
    if pending.nonce in used_nonces:
        problems.append("the approval challenge was already used")
    expected = challenge_for(pending.workflow_id, pending.plan_hash, pending.tier, pending.nonce, pending.expires_at)
    if bytes_to_base64url(expected) != pending.challenge:
        problems.append("the pending challenge does not match its plan")
    if pending.tier in DEVICE_BOUND_TIERS and not credential.device_bound:
        problems.append(f"{pending.tier} needs a device-bound passkey; this one is synced")
    payload = json.loads(response) if isinstance(response, str) else response
    if payload.get("id") != credential.credential_id:
        problems.append(f"the passkey used is not {credential.approver}'s enrolled one")
    try:
        verified = verify_authentication_response(
            credential=payload, expected_challenge=expected, expected_rp_id=rp_id, expected_origin=origin,
            credential_public_key=base64url_to_bytes(credential.public_key),
            credential_current_sign_count=credential.sign_count, require_user_verification=True)
    except (InvalidAuthenticationResponse, ValueError, KeyError, TypeError) as exc:
        return None, [*problems, f"the passkey assertion is invalid: {exc}"]
    if problems:
        return None, problems
    return PasskeyApproval(approver=credential.approver, workflow_id=pending.workflow_id, plan_hash=pending.plan_hash,
                           tier=pending.tier, nonce=pending.nonce, credential_id=credential.credential_id,
                           new_sign_count=verified.new_sign_count, approved_at=now), []


__all__ = ["CHALLENGE_TTL", "Credential", "InvalidRegistrationResponse", "PasskeyApproval", "Pending",
           "approval_options", "challenge_for", "finish_registration", "registration_options", "verify_approval"]
