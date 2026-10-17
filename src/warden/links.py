"""Linked incident records (item 16a): a person's signed word that two incidents are related, and how.

`warden link <incident> <other> --as same-root-cause|recurrence-of|caused-by` records a typed link between two
incidents on WARDEN's record. It is two-way: one signed row, written in one step, read from either incident's side
with its type as seen from there (`recurrence-of` on one is `recurred-as` on the other; `caused-by` is `caused`), so
either record page shows it. A link can be taken back the same way (`--remove`); the newest signed word for a pair and type stands.

What a link is for: a similar incident finds the PROVEN fix. `proven_fix` follows the links that say two incidents
share a cause - `same-root-cause`, `recurrence-of` and `recurred-as`, a few steps deep, never `caused-by` (a fix of
the cause is not a fix of what it caused) - and returns the newest fix on one of those records that was applied and
verified: its run ended `recovered` (three healthy checks and the re-checks after them, RemediationWorkflow) and
nothing on the record later says it did not hold (`remediation.did_not_hold`, or a failed result for that fix after its
run ended - a later incident that cited it as its cause). A fix that relapsed, was undone, failed or was denied is not
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
    """A link signed with the approver's key. The note is kept as an approval's note is (approvals.note): control
    characters out, anything that looks like a secret removed, before it is signed."""
    from .approvals import note as kept

    link = Link(incident=incident, other=other, type=type, approver=approver, note=kept(note, incoming=True)[:500],
                removed=removed, at=now or datetime.now(UTC))
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


def _signer(link: Link, policy: Any) -> list[str]:
    """[] when the link is signed by the approver it names; else why not."""
    key = policy.key_of(link.approver) if link.approver in policy.approvers else None
    if key is None:
        return ["the signer is not an approver"]  # never echo a name the list does not hold
    try:
        key.verify(bytes.fromhex(link.signature), link.message())
    except (InvalidSignature, ValueError):
        return ["the signature is not the approver's"]
    return []


def _problems(log: Any, link: Link, entry: Any, now: datetime) -> list[str]:
    """Every reason a signed link may not be recorded: who signed it, what it links, when."""
    from . import approvals

    problems = []
    if approvals.is_bench(link.approver, entry):
        problems.append("the bench approver is a test identity: it does not link records")
    if link.incident == link.other:
        problems.append("an incident cannot be linked to itself")
    if link.at.astimezone(UTC) > now + SKEW:
        problems.append("the link is dated in the future")
    here, there = _environment(log, link.incident), _environment(log, link.other)
    problems += [f"{name} is not on WARDEN's record" for name, env in ((link.incident, here), (link.other, there))
                 if env is None]
    if here is None or there is None:
        return problems
    if here != there:
        problems.append("the two incidents are in different environments: a fix in one proves nothing in the other")
    elif approvals.environment_refusal(link.approver, entry, here):
        problems.append(f"the approver's entry does not cover {here}")
    return problems


def record(log: Any, link: Link, policy: Any, *, now: datetime | None = None) -> list[str]:
    """Record the link if it is an approver's, signed by them, for two incidents of one environment their entry
    covers; otherwise every reason it is not, and nothing is written. One row, so it is written whole or not at all;
    links_of reads it from either side."""
    problems = _signer(link, policy) or _problems(log, link, policy.approvers[link.approver], now or datetime.now(UTC))
    if not problems:
        log.append(link.incident, KIND, link.model_dump(mode="json"))
    return problems


def _signed_at(body: dict[str, Any]) -> datetime:
    """A link row's own signed time, as a time (CodeRabbit, PR 56: as text, `...:00Z` sorted after `...:00.5Z`)."""
    try:
        at = datetime.fromisoformat(str(body.get("at")))
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)
    return at.astimezone(UTC) if at.tzinfo else at.replace(tzinfo=UTC)


def _sides(body: dict[str, Any], incident: str) -> tuple[str, str] | None:
    """(the other incident, the type as read from `incident`'s side) of a well-formed link row naming it; else None."""
    kind, a, b = body.get("type"), body.get("incident"), body.get("other")
    if kind not in INVERSE or not all(isinstance(x, str) and re.fullmatch(_ID, x) for x in (a, b)) or a == b:
        return None
    if incident == a:
        return str(b), str(kind)
    return (str(a), INVERSE[str(kind)]) if incident == b else None


def links_of(log: Any, incident: str) -> list[dict[str, Any]]:
    """This incident's links as they stand, oldest first, each as {with, side, approver, note, at}: for each other
    incident and type, the newest signed word (by its own signed time), dropped when that word took the link back."""
    return _standing(log.entries(kinds=(KIND,)), incident)


def _standing(rows: list[dict[str, Any]], incident: str) -> list[dict[str, Any]]:
    """links_of over link rows already read: a walk reads them once, not once per record it reaches (CodeRabbit)."""
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for e in rows:
        b = e["body"]
        sides = _sides(b, incident)
        if sides is None:
            continue
        if sides not in latest or _signed_at(b) >= _signed_at(latest[sides]):
            latest[sides] = {**b, "with": sides[0], "side": sides[1]}
    return sorted((b for b in latest.values() if not b.get("removed")), key=_signed_at)


def _fixes(log: Any, incident: str) -> list[dict[str, Any]]:
    """Each fix plan on this incident's record that was applied and verified - its run ended `recovered` and nothing
    later on the record says it did not hold - newest first."""
    from .bounds import RESULT

    rows = log.entries(incident, kinds=("remediation.plan", "workflow.end", "remediation.did_not_hold", RESULT))
    ends = {(e["body"].get("workflow_id"), e["body"].get("run_id")): e for e in rows if e["kind"] == "workflow.end"}
    out = []
    for e in rows:
        b = e["body"]
        end = ends.get((b.get("workflow_id"), b.get("run_id"))) if e["kind"] == "remediation.plan" else None
        if end is None or end["body"].get("status") != "recovered":
            continue
        wid = b.get("workflow_id")
        later = [r for r in rows if r["body"].get("workflow_id") == wid and r["at"] > end["at"]
                 and (r["kind"] == "remediation.did_not_hold" or (r["kind"] == RESULT and r["body"].get("ok") is False))]
        if not later:
            out.append({"incident": incident, "entry": str(b.get("entry") or ""), "target": str(b.get("target") or ""),
                        "environment": str(b.get("environment") or ""), "workflow_id": str(wid or ""),
                        "verified_at": end["at"]})
    return sorted(out, key=lambda f: f["verified_at"], reverse=True)


def proven_fix(log: Any, incident: str) -> dict[str, Any] | None:
    """The newest proven fix on a record that shares this incident's cause through its links (breadth first, at most
    DEPTH links away and MOST_REACHED records, this one included), with the path of links that reached it; None when
    there is none. This incident's own fixes are not counted: a fix of this incident is in its own record."""
    rows = log.entries(kinds=(KIND,))
    seen, queue, found = {incident}, deque([(incident, [])]), []
    while queue and len(seen) < MOST_REACHED:
        here, path = queue.popleft()
        if len(path) >= DEPTH:
            continue
        for link in _standing(rows, here):
            other = link["with"]
            if link["side"] not in SHARES_A_FIX or other in seen:
                continue
            if len(seen) >= MOST_REACHED:
                break
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


# ------------------------------------------------------------------ links WARDEN finds in its own record (owner B8)
# Derived when a record is read, from rows WARDEN itself wrote and signed - nothing is stored, nothing is guessed:
# - rediagnosis: a fix that failed a re-check started a new diagnosis of the same alarm (remediation.rediagnose);
# - followed after a fix: another incident started while, or shortly after, a fix was applied (incident.later_alarm,
#   remediation.side_effects);
# - relapse: a fix being watched heard its alarm fire again, which started a new incident (intake.relapse);
# - same alarm (the same intake fingerprint) or same resource (the same environment and service), in the last
#   FOUND_DAYS days, the newest FOUND_MOST of each.
# A found link is shown as WARDEN's and is never followed for a proven fix: only a person's signed link says two
# incidents share a cause.
FOUND_WORDS = {
    "rediagnosis-of": "is a new diagnosis, after a failed fix, of", "rediagnosed-as": "was diagnosed again as",
    "followed-fix-of": "started after a fix of", "followed-by": "was followed, after its fix, by",
    "relapse-of": "is the alarm coming back after a fix of", "relapsed-as": "came back, after its fix, as",
    "same-alarm": "has the same alarm as", "same-resource": "is on the same resource as"}
FOUND_DAYS, FOUND_MOST = 30, 5
_FP = re.compile(r"^([0-9a-f]{16})-\d{8}T\d{6}Z$")


def _incident_id(value: Any) -> str:
    text = str(value or "")
    return text if re.fullmatch(_ID, text) else ""


# Each row that ties a later incident to a fix: (the fix's incident's side, the later incident's side).
_FIX_ROWS = {"remediation.rediagnose": ("rediagnosed-as", "rediagnosis-of"),
             "incident.later_alarm": ("followed-by", "followed-fix-of"),
             "remediation.side_effects": ("followed-by", "followed-fix-of")}


def _later(e: dict[str, Any]) -> list[str]:
    """The later incidents a fix row names."""
    b = e["body"]
    if e["kind"] == "remediation.rediagnose":
        return [_incident_id(b.get("new"))]
    if e["kind"] == "incident.later_alarm":
        return [_incident_id(b.get("incident"))]
    named = b.get("incidents")
    # These are the incidents' workflow ids (intake.submit): `inc-` and the incident's id.
    return [_incident_id(str(i).removeprefix("inc-")) for i in named] if isinstance(named, list) else []


def _fix_links(log: Any, incident: str) -> list[tuple[str, str]]:
    """(other incident, side) from the rows that tie one incident to another through a fix."""
    out = []
    for e in log.entries(kinds=tuple(_FIX_ROWS)):
        owner, (ahead, behind) = str(e["correlation_id"]), _FIX_ROWS[e["kind"]]
        later = [n for n in _later(e) if n]
        if owner == incident:
            out += [(n, ahead) for n in later if n != incident]
        elif incident in later:
            out.append((owner, behind))
    return out


def _relapse_links(log: Any, incident: str) -> list[tuple[str, str]]:
    """(other incident, side) from a watched fix that heard its alarm again: the incident that alarm started is the
    fingerprint and the alarm's time (intake.decide), and the fix's incident is its plan's."""
    fixed = {str(e["body"].get("workflow_id")): str(e["correlation_id"])
             for e in log.entries(kinds=("remediation.plan",))}
    out = []
    for e in log.entries(kinds=("intake.relapse",)):
        b = e["body"]
        try:
            at = datetime.fromisoformat(str(b.get("at"))).astimezone(UTC)
        except ValueError:
            continue
        new, old = f"{b.get('fingerprint')}-{at:%Y%m%dT%H%M%SZ}", fixed.get(str(b.get("workflow_id")), "")
        if old and new == incident:
            out.append((old, "relapse-of"))
        elif old == incident and _FP.match(new):
            out.append((new, "relapsed-as"))
    return out


def _alike_links(log: Any, incident: str, now: datetime) -> list[tuple[str, str]]:
    """(other incident, side) for the same alarm or the same resource, newest first, FOUND_MOST of each."""
    seen: dict[str, tuple[str, str, datetime]] = {}
    for e in log.entries(kinds=("incident.alert",), since=now - timedelta(days=FOUND_DAYS)):
        a = e["body"].get("alert") or {}
        seen[str(e["correlation_id"])] = (str(a.get("environment") or ""), str(a.get("service") or ""), e["at"])
    if incident not in seen:
        return []
    env, service, _ = seen[incident]
    fp = _FP.match(incident)
    newest = sorted((k for k in seen if k != incident and seen[k][0] == env), key=lambda k: seen[k][2], reverse=True)
    same_alarm = [k for k in newest if fp and _FP.match(k) and k.startswith(fp.group(1))][:FOUND_MOST]
    same_resource = [k for k in newest if service and seen[k][1] == service and k not in same_alarm][:FOUND_MOST]
    return [(k, "same-alarm") for k in same_alarm] + [(k, "same-resource") for k in same_resource]


def found(log: Any, incident: str, *, now: datetime | None = None) -> list[dict[str, Any]]:
    """The links WARDEN finds for this incident in its own record, one per other incident and side, in a fixed order:
    through a fix first, then the same alarm, then the same resource."""
    pairs = _fix_links(log, incident) + _relapse_links(log, incident) + _alike_links(log, incident,
                                                                                     now or datetime.now(UTC))
    out, kept = [], set()
    for other, side in pairs:
        if (other, side) not in kept and other != incident:
            kept.add((other, side))
            out.append({"with": other, "side": side, "words": FOUND_WORDS[side]})
    return out
