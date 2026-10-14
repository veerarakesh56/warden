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
# What a tier means, in the words of the person asked to approve one (owner, 2026-10-12: a message said "(T1)" and
# nothing else). Said wherever a tier is shown to a person.
TIER_MEANS = {"T1": "low risk: one small, bounded change to one resource",
              "T2": "medium risk: a reversible change to a service's settings or version",
              "T3": "high risk: hard to undo, or it changes access, the network or infrastructure"}
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


class PasskeyCredential(BaseModel):
    """A passkey enrolled for an approver (passkeys.py): its id and public key (base64url), the signature counter at
    enrolment - the audit holds every later one - and whether it is device-bound (T3 needs that)."""

    credential_id: str
    public_key: str
    sign_count: int = 0
    device_bound: bool = True


class Approver(BaseModel):
    # How the person is shown to people (owner, 2026-10-12: "it should give its name"): on the approval page once
    # their passkey has said who they are, and in the messages that say who approved. The list's key stays the id.
    name: str = Field(default="", max_length=80)
    team: str = Field(default="", max_length=80)
    # The person's Slack member id (`U...`, from their Slack profile): a message that names them mentions them, so a
    # reader can open who that is. Configuration, like the rest of this list - never in the repository.
    slack: str = Field(default="", pattern=r"^$|^[UW][A-Z0-9]{6,14}$")
    public_key: str  # PEM: the Ed25519 break-glass key (decision D14)
    tiers: list[str] = Field(default_factory=list)
    passkeys: list[PasskeyCredential] = Field(default_factory=list)


# An approver's own words beside a decision (owner, 2026-10-14: a note with an approval as with a denial, "no matter
# how lengthy and which kind of characters", tracked and stored, and "no prompt injection risk from those texts").
# Any characters, any length: never refused, kept up to NOTE_MAX characters. Not text, and so not kept: control codes
# and the invisible marks that make stored words read differently from how they were typed (zero-width space, byte
# order mark, word joiner, the direction marks and overrides). The joiners Indic and Arabic scripts and emoji need
# are text and are kept. The words are data everywhere they go: the audit, and a message - where they are written as
# one inert line (activities._words). No model is ever shown them: the diagnosis reads the alert and the evidence.
NOTE_MAX = 2000
_NOT_TEXT = frozenset(map(chr, [0x200B, 0x200E, 0x200F, 0x061C, 0x2060, 0xFEFF, *range(0x202A, 0x202F),
                                *range(0x2066, 0x206A)]))


def note(text: object) -> str:
    """What is kept of the words an approver typed with a decision. Whatever is sent - a list, a number, nothing -
    this answers with a string of at most NOTE_MAX characters."""
    import unicodedata

    typed = str(text if text is not None else "").replace("\r\n", "\n").replace("\r", "\n")
    kept = [ch for ch in typed if ch not in _NOT_TEXT
            and (ch in "\n\t" or unicodedata.category(ch) not in ("Cc", "Cs"))]
    return "".join(kept).strip()[:NOTE_MAX]


class Denial(BaseModel):
    """An approver's "no" (requirement R28), sent by the approval page after a passkey ceremony over the plan. Fail-safe
    by construction: a denial can only end a plan with nothing changed, so the workflow takes it as it comes - for
    this workflow and this exact plan only."""

    approver: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    workflow_id: str
    plan_hash: str
    reason: str = Field(default="", max_length=NOTE_MAX)


class PasskeyAssertion(BaseModel):
    """What an approval page sends the workflow: the browser's WebAuthn assertion and the challenge it answered.
    Nothing in it is trusted - the workflow re-verifies the assertion against the approver's enrolled passkey, and the
    challenge must be the plan's own (register H6)."""

    approver: str
    workflow_id: str
    plan_hash: str
    tier: str
    nonce: str
    expires_at: datetime
    challenge: str
    response: dict
    # The approver's own words with this approval (approvals.note): recorded with it, never part of what is verified.
    note: str = Field(default="", max_length=NOTE_MAX)


class ApproverPolicy(BaseModel):
    approvers: dict[str, Approver]
    required: dict[str, int] = Field(default_factory=lambda: dict.fromkeys(TIERS, 1))
    cooling_off_minutes: dict[str, int] = Field(default_factory=lambda: {"T3": 10})

    @classmethod
    def load(cls, path: str | pathlib.Path) -> ApproverPolicy:
        return cls.loads(pathlib.Path(path).read_text(encoding="utf-8"))

    @classmethod
    def loads(cls, text: str) -> ApproverPolicy:
        return cls.model_validate(yaml.safe_load(text))

    def fingerprint(self) -> str:
        """This exact list, as a short hash: recorded with every approval it accepts, so a later reader can tell the
        list was not swapped around one (the approver-list alarm says when it changed, and by whom)."""
        import hashlib

        return hashlib.sha256(json.dumps(self.model_dump(mode="json"), sort_keys=True,
                                         separators=(",", ":")).encode()).hexdigest()[:16]

    def shown(self, approver: str) -> str:
        """The approver as people read them: their name, with their team when the list gives one. The list's own
        key for them is its id, not a name for a reader (owner, 2026-10-12: a message that said "owner" "feels
        unprofessional and off") - it is shown only for an approver the list gives no name."""
        entry = self.approvers.get(approver)
        if not entry or not entry.name.strip():
            return approver
        return entry.name.strip() + (f" ({entry.team.strip()})" if entry.team.strip() else "")

    def said(self, approver: str) -> str:
        """The approver as a MESSAGE names them. A typed name proves nothing to its readers (owner, 2026-10-12: "if
        they wanted to, they would write a different name"), so the text holds only a mark for that approver. With a
        Slack member id the Slack sinks turn it into Slack's own mention where the sentence names them
        (chatops.name_people) - Slack shows that member's real profile, and the member is told. Without one, and for
        every other reader, it becomes the name from the list."""
        return f"@@{approver}@@"

    def people(self) -> tuple[tuple[str, str, str], ...]:
        """(approver id, Slack member id, name as shown) of every approver: what a message's marks become."""
        return tuple((a, entry.slack, self.shown(a)) for a, entry in sorted(self.approvers.items()))

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
