"""Approver labels (audit A-P-2): a person's verdict on what WARDEN said, kept for calibration (G7).

After an incident the approver records whether the diagnosis and the proposed action were right, wrong or unclear
to them - `warden label <incident> --diagnosis right --action wrong`. Calibration learns from these, so a label is
signed with the approver's own key and verified before it is recorded: an unsigned label could be planted to teach
WARDEN that a wrong action was right. A label signs other fields than an approval does, under its own prefix
(`warden-label:v1:`), so a label can never be replayed as an approval, nor an approval as a label.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, Field

from .approvals import ApproverPolicy
from .audit import AuditLog

Judgement = Literal["right", "wrong", "unsure"]
KIND = "label"


class Label(BaseModel):
    incident_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    approver: str
    diagnosis: Judgement
    action: Judgement
    note: str = Field(default="", max_length=500)
    at: datetime
    signature: str = ""

    def message(self) -> bytes:
        fields = self.model_dump(mode="json", exclude={"signature"})
        return b"warden-label:v1:" + json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


def sign(key: Ed25519PrivateKey, *, incident_id: str, approver: str, diagnosis: str, action: str, note: str = "",
         now: datetime | None = None) -> Label:
    label = Label(incident_id=incident_id, approver=approver, diagnosis=diagnosis, action=action, note=note,
                  at=now or datetime.now(UTC))
    label.signature = key.sign(label.message()).hex()
    return label


def record(log: AuditLog, label: Label, policy: ApproverPolicy) -> list[str]:
    """Record the label if it is an approver's and signed by them; otherwise every reason it is not."""
    key = policy.key_of(label.approver)
    if key is None:
        return [f"{label.approver!r} is not an approver"]
    try:
        key.verify(bytes.fromhex(label.signature), label.message())
    except (InvalidSignature, ValueError):
        return [f"the signature is not {label.approver}'s"]
    log.append(label.incident_id, KIND, label.model_dump(mode="json"))
    return []


def export(log: AuditLog) -> list[dict]:
    """Every recorded label, oldest first: what calibration (G7) reads."""
    return [e["body"] for e in log.entries(kinds=(KIND,))]
