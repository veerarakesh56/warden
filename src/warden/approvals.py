"""Signed approvals: a person's Ed25519 signature over exactly one plan of exactly one workflow.

An approval says "I, <approver>, approve plan <plan_hash> of workflow <workflow_id>, at tier <tier>,
until <expires_at>". The workflow accepts it only if every check in `check()` passes:

- the approver is on the allowlist for that tier, and the signature is theirs;
- it names this workflow and this exact plan (a changed plan is a new plan, needing a new approval);
- it is inside its validity window (a small allowance for clock skew, never more);
- its nonce has not been used before (one approval, one use);
- for T3 (irreversible, IAM, network, Terraform), the plan has existed for the cooling-off time before
  it was approved, so a rushed "yes" at 3 am cannot follow a plan made seconds earlier.

The private key stays with the approver (passphrase-encrypted, `warden audit keygen` makes one).
The MCP server and the model never hold one, so neither can approve anything.

⛔ Honest limit: with a single approver who also runs the agent's machine, the signature proves
the key was used, not that a second person looked. Two-person approval is supported by requiring two
valid approvals from different approvers (`required` in the allowlist); it is never faked.
"""

from __future__ import annotations

import json
import pathlib
import secrets
from datetime import UTC, datetime, timedelta

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, Field

TIERS = ("T1", "T2", "T3")
CLOCK_SKEW = timedelta(seconds=60)
MAX_TTL = timedelta(hours=4)


class SignedApproval(BaseModel):
    approver: str
    workflow_id: str
    plan_hash: str
    tier: str
    issued_at: datetime
    expires_at: datetime
    nonce: str
    signature: str = ""

    def message(self) -> bytes:
        fields = self.model_dump(mode="json", exclude={"signature"})
        return b"warden-approval:v1:" + json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


class Approver(BaseModel):
    public_key: str  # PEM
    tiers: list[str] = Field(default_factory=list)


class ApproverPolicy(BaseModel):
    approvers: dict[str, Approver]
    required: dict[str, int] = Field(default_factory=lambda: dict.fromkeys(TIERS, 1))
    cooling_off_minutes: dict[str, int] = Field(default_factory=lambda: {"T3": 10})

    @classmethod
    def load(cls, path: str | pathlib.Path) -> ApproverPolicy:
        return cls.model_validate(yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8")))

    def key_of(self, name: str) -> Ed25519PublicKey | None:
        approver = self.approvers.get(name)
        if approver is None:
            return None
        key = serialization.load_pem_public_key(approver.public_key.encode())
        return key if isinstance(key, Ed25519PublicKey) else None


def sign(key: Ed25519PrivateKey, *, approver: str, workflow_id: str, plan_hash: str, tier: str,
         ttl: timedelta = timedelta(minutes=30), now: datetime | None = None) -> SignedApproval:
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier!r}")
    now = now or datetime.now(UTC)
    approval = SignedApproval(approver=approver, workflow_id=workflow_id, plan_hash=plan_hash, tier=tier,
                              issued_at=now, expires_at=now + min(ttl, MAX_TTL),
                              nonce=secrets.token_hex(16))
    approval.signature = key.sign(approval.message()).hex()
    return approval


def check(approval: SignedApproval, *, policy: ApproverPolicy, workflow_id: str, plan_hash: str,
          tier: str, plan_created_at: datetime, used_nonces: set[str], now: datetime | None = None) -> list[str]:
    """Every reason this approval must NOT be acted on. An empty list means it is valid."""
    now = now or datetime.now(UTC)
    problems: list[str] = []
    key = policy.key_of(approval.approver)
    if key is None:
        return [f"{approval.approver!r} is not an approver"]
    try:
        key.verify(bytes.fromhex(approval.signature), approval.message())
    except (InvalidSignature, ValueError):
        return [f"the signature is not {approval.approver}'s"]
    if tier not in policy.approvers[approval.approver].tiers:
        problems.append(f"{approval.approver} may not approve {tier}")
    if approval.tier != tier:
        problems.append(f"approval is for {approval.tier}, the plan is {tier}")
    if approval.workflow_id != workflow_id:
        problems.append("approval is for a different workflow")
    if approval.plan_hash != plan_hash:
        problems.append("approval is for a different plan (the plan changed after it was approved)")
    if approval.issued_at > now + CLOCK_SKEW:
        problems.append("approval is issued in the future")
    if approval.expires_at <= now:
        problems.append("approval has expired")
    if approval.expires_at - approval.issued_at > MAX_TTL:
        problems.append("approval is valid for longer than allowed")
    if approval.nonce in used_nonces:
        problems.append("approval was already used")
    cooling = timedelta(minutes=policy.cooling_off_minutes.get(tier, 0))
    if approval.issued_at < plan_created_at + cooling:
        problems.append(f"{tier} needs the plan to exist for {cooling} before it is approved")
    return problems


def enough(valid: list[SignedApproval], tier: str, policy: ApproverPolicy) -> bool:
    """Are there as many valid approvals from DIFFERENT approvers as the tier requires?"""
    return len({a.approver for a in valid}) >= policy.required.get(tier, 1)
