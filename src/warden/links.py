"""Linked incident records (item 16a): a person's signed word that two incidents are related, and how.

`warden link <incident> <other> --as same-root-cause|recurrence-of|caused-by` records a typed link between two
incidents on WARDEN's record. It is two-way: the link is written on both incidents' records, each with the type as
read from its side (`recurrence-of` on one is `recurred-as` on the other; `caused-by` is `caused`), so either record
page shows it. A link can be taken back the same way (`--remove`); the newest signed word for a pair and type stands.

What a link is for: a similar incident finds the PROVEN fix. `proven_fix` follows the links that say two incidents
share a cause - `same-root-cause`, `recurrence-of` and `recurred-as`, a few steps deep, never `caused-by` (a fix of
the cause is not a fix of what it caused) - and returns the newest fix on one of those records that was applied and
verified: its run ended `recovered` (three healthy checks and the re-checks after them, RemediationWorkflow) and
nothing on the record later says it did not hold. A fix that relapsed, was undone, failed or was denied is not
proven. It is a fact from the signed record for a person to read, never an input that lets WARDEN act.

Who may link: an approver, with their own key, for incidents of the same environment that their entry covers - not
the bench approver, a test identity, whose word must not make a fix look proven. A link signs its own fields under
its own prefix (`warden-link:v1:`), so it can never be replayed as an approval or a label, nor they as a link.
"""

from __future__ import annotations

import json
import re
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, Field

KIND = "record.link"
LinkType = Literal["same-root-cause", "recurrence-of", "caused-by"]
TYPES: tuple[str, ...] = ("same-root-cause", "recurrence-of", "caused-by")
# Each type as read from the other incident's side.
INVERSE = {"same-root-cause": "same-root-cause", "recurrence-of": "recurred-as", "caused-by": "caused"}
# Each side's type in a person's words: "<this incident> <words> <the other>".
WORDS = {"same-root-cause": "has the same root cause as", "recurrence-of": "is a recurrence of",
         "recurred-as": "came back as", "caused-by": "was caused by", "caused": "caused"}
# The links along which a fix of one incident is a fix of the other: they share a cause.
SHARES_A_FIX = frozenset({"same-root-cause", "recurrence-of", "recurred-as"})
DEPTH, MOST_REACHED = 3, 50  # how far proven_fix follows links, and how many records it reads at most
SKEW = timedelta(minutes=5)  # a link signed this far in the future is refused
_ID = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"


class Link(BaseModel):
    incident: str = Field(pattern=_ID)
    other: str = Field(pattern=_ID)
    type: LinkType
    approver: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    note: str = Field(default="", max_length=500)
    removed: bool = False
    at: datetime
    signature: str = ""

    def message(self) -> bytes:
        fields = self.model_dump(mode="json", exclude={"signature"})
        return b"warden-link:v1:" + json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


def sign(key: Ed25519PrivateKey, *, incident: str, other: str, type: str, approver: str, note: str = "",
         removed: bool = False, now: datetime | None = None) -> Link:
    link = Link(incident=incident, other=other, type=type, approver=approver, note=note, removed=removed,
                at=now or datetime.now(UTC))
    link.signature = key.sign(link.message()).hex()
    return link


def _environment(log: Any, incident: str) -> str | None:
    """The incident's environment from its own record; None when the record holds no such incident."""
    found = None
    for e in log.entries(incident, kinds=("incident.alert", "incident.ingest")):
        b = e["body"]
        env = (b.get("alert") or {}).get("environment") if e["kind"] == "incident.alert" else b.get("env")
        if env:
            return str(env)
        found = ""
    return found


def record(log: Any, link: Link, policy: Any, *, now: datetime | None = None) -> list[str]:
    """Record the link on both incidents if it is an approver's, signed by them, for two incidents of one environment
    their entry covers; otherwise every reason it is not, and nothing is written."""
    from . import approvals

    now = now or datetime.now(UTC)
    problems: list[str] = []
    entry = policy.approvers.get(link.approver)
    key = policy.key_of(link.approver)
    if entry is None or key is None:
        return ["the signer is not an approver"]  # never echo a name the list does not hold
    try:
        key.verify(bytes.fromhex(link.signature), link.message())
    except (InvalidSignature, ValueError):
        return ["the signature is not the approver's"]
    if approvals.is_bench(link.approver, entry):
        problems.append("the bench approver is a test identity: it does not link records")
    if link.incident == link.other:
        problems.append("an incident cannot be linked to itself")
    if link.at.astimezone(UTC) > now + SKEW:
        problems.append("the link is dated in the future")
    here, there = _environment(log, link.incident), _environment(log, link.other)
    for name, env in ((link.incident, here), (link.other, there)):
        if env is None:
            problems.append(f"{name} is not on WARDEN's record")
    if here is not None and there is not None:
        if here != there:
            problems.append("the two incidents are in different environments: a fix in one proves nothing in the other")
        elif approvals.environment_refusal(link.approver, entry, here):
            problems.append(f"the approver's entry does not cover {here}")
    if problems:
        return problems
    body = link.model_dump(mode="json")
    log.append(link.incident, KIND, {**body, "side": link.type, "with": link.other})
    log.append(link.other, KIND, {**body, "side": INVERSE[link.type], "with": link.incident})
    return []


def _valid(body: dict[str, Any], incident: str) -> bool:
    return (body.get("side") in WORDS and isinstance(body.get("with"), str) and bool(re.fullmatch(_ID, body["with"]))
            and incident in (body.get("incident"), body.get("other")))


def links_of(log: Any, incident: str) -> list[dict[str, Any]]:
    """This incident's links as they stand, oldest first: for each other incident and type, the newest signed word
    (by its own signed time), dropped when that word took the link back."""
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for e in log.entries(incident, kinds=(KIND,)):
        b = e["body"]
        if not _valid(b, incident):
            continue
        key = (str(b["with"]), str(b["side"]))
        if key not in latest or str(b.get("at")) >= str(latest[key].get("at")):
            latest[key] = b
    return sorted((b for b in latest.values() if not b.get("removed")), key=lambda b: str(b.get("at")))


def _fixes(log: Any, incident: str) -> list[dict[str, Any]]:
    """Each fix plan on this incident's record that was applied and verified - its run ended `recovered` and nothing
    later on the record says it did not hold - newest first."""
    rows = log.entries(incident, kinds=("remediation.plan", "workflow.end", "remediation.did_not_hold"))
    ends = {(e["body"].get("workflow_id"), e["body"].get("run_id")): e for e in rows if e["kind"] == "workflow.end"}
    undone = {e["body"].get("workflow_id") for e in rows if e["kind"] == "remediation.did_not_hold"}
    out = []
    for e in rows:
        b = e["body"]
        if e["kind"] != "remediation.plan":
            continue
        end = ends.get((b.get("workflow_id"), b.get("run_id")))
        if end and end["body"].get("status") == "recovered" and b.get("workflow_id") not in undone:
            out.append({"incident": incident, "entry": str(b.get("entry") or ""), "target": str(b.get("target") or ""),
                        "environment": str(b.get("environment") or ""), "workflow_id": str(b.get("workflow_id") or ""),
                        "verified_at": end["at"]})
    return sorted(out, key=lambda f: f["verified_at"], reverse=True)


def proven_fix(log: Any, incident: str) -> dict[str, Any] | None:
    """The newest proven fix on a record that shares this incident's cause through its links (breadth first, at most
    DEPTH links away), with the path of links that reached it; None when there is none. This incident's own fixes are
    not counted: a fix of this incident is in its own record."""
    seen, queue, found = {incident}, deque([(incident, [])]), []
    while queue and len(seen) <= MOST_REACHED:
        here, path = queue.popleft()
        if len(path) >= DEPTH:
            continue
        for link in links_of(log, here):
            other = link["with"]
            if link["side"] not in SHARES_A_FIX or other in seen:
                continue
            seen.add(other)
            step = [*path, {"from": here, "side": link["side"], "to": other}]
            found += [{**fix, "path": step} for fix in _fixes(log, other)]
            queue.append((other, step))
    if not found:
        return None
    return max(found, key=lambda f: (f["verified_at"], -len(f["path"])))


def describe(link: dict[str, Any]) -> str:
    """A link in a person's words, from this incident's side."""
    return f"{WORDS[link['side']]} {link['with']}"
