"""WARDEN's records, as web pages (owner, 2026-10-14): every incident, its plan, who approved or denied it with their
note, anything that tried to steer WARDEN, and how it ended - stored, kept up to date, and readable at any time,
instead of a stream of Slack messages. The list shows each incident's summary, its details unfold beneath it, and
each incident has a page of its own with the whole report and every step WARDEN recorded, in UTC and local time.

Everything here is read from WARDEN's signed audit record; nothing is written. Every value on a page is escaped: the
alert's text, a person's note and the model's words are data on these pages, never markup. The pages carry no
script but one (a quiet refresh of the list) and no style or image from anywhere else (approval_page._headers).
"""

from __future__ import annotations

import dataclasses
import html
import re
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

PER_PAGE = 50  # incidents on one page of the list by default; every incident stays on the record, without a time limit
SIZES = (10, 25, 50, 100)  # the page sizes a reader may choose (owner, 2026-10-16)
REFRESH_S = 60
# The steps and words the record and its pages look for in more than one place.
_INGEST, _AFTER_HOLD = "incident.ingest", "incident.after_hold"
_REPORT, _EVIDENCE = "incident.report", "incident.evidence"
_ANNOUNCE = "remediation.announce"
IN_PROGRESS, NO_PLAN = "In progress", "No fix plan"
_UL_END = "</ul>"
_TITLE = "WARDEN records"

# A fix run's end, in words, and how it reads at a glance: the kind is said in words too, never by colour alone.
ENDED = {
    "verified": ("Fixed", "ok"), "recovered": ("Fixed and held", "ok"), "relapsed": ("Fixed, then failed again", "bad"),
    "rolled_back": ("Did not work - undone", "bad"), "not_recovered": ("Did not work", "bad"),
    "rollback_failed": ("Undo failed - state unknown", "bad"), "refused_at_apply": ("Not applied", "warn"),
    "apply_failed": ("Apply failed - state unknown", "bad"), "drifted": ("Changed since planned - not applied", "warn"),
    "denied": ("Denied", "warn"), "expired": ("Expired - nothing changed", "warn"),
    "cancelled_after_apply": ("Stopped after applying", "bad"), "failed_after_apply": ("Failed after applying", "bad"),
    "side_effects": ("Worked, but other alarms started after it", "bad"),
}

# Each step on the record, in plain words, for an incident's page.
STEP = {
    "intake.grouped": "Another alert on the same resource joined this incident",
    "incident.reopened": "Reopened: the alarm came back while the fix was being watched",
    "remediation.did_not_hold": "The fix did not hold - WARDEN will not offer it again on its own",
    "remediation.offer_again": "An approver let WARDEN offer this fix again",
    "intake.decision": "The alarm came in", "incident.alert": "The alarm was recorded",
    _INGEST: "WARDEN started reading", "incident.gather": "Evidence read",
    "incident.redact": "Secrets removed from the evidence", "incident.tripwire": "Injection check on the evidence",
    "incident.diagnose": "Diagnosis", "incident.investigate": "Read more of what the alarm names",
    "incident.reread": "Read again: a source was empty right after the alarm",
    "incident.verify": "Safety policies checked", "incident.changes": "Recent changes looked up",
    _REPORT: "Report written", "incident.notify": "Report sent", "incident.plan_fix": "Fix plan looked for",
    "incident.no_plan": NO_PLAN, _AFTER_HOLD: "Looked at again after expected down",
    _EVIDENCE: "Evidence kept for questions",
    "record.link": "Linked to another record by an approver",
    "intake.side_effect": "Another alarm started while this fix was checked",
    "remediation.side_effects": "Other alarms started after this fix - each diagnosed on its own", "remediation.rediagnose": "Diagnosed again",
    "incident.later_alarm": "Another alarm started after this fix - diagnosed beside it",
    "remediation.plan": "Fix plan made", "remediation.gate": "Fix plan checked", _ANNOUNCE: "Asked for approval",
    "approval.link_viewed": "Approval page opened", "approval.slack_verified": "Signed in with Slack",
    "approval.accepted": "Approved", "approval.refused": "An approval was refused",
    "remediation.precheck": "Target checked before applying", "remediation.intent": "About to apply",
    "remediation.check": "Health checked after the fix", "remediation.rollback": "Fix undone",
    "remediation.rollback_failed": "Undoing the fix failed", "remediation.refused": "Apply refused",
    "workflow.end": "Fix run ended", "change.recorded": "Change recorded", "discuss.turn": "Asked about in the discussion",
    "discuss.answer": "WARDEN answered in the discussion", "discuss.reply": "Answer posted",
    "eldane.verdict": "Reviewed by Eldane, the AI critic", "eldane.call": "Eldane asked its model",
    "eldane.trial": "A catch trial for Eldane: a planted bad plan, a test, never applied",
    "autonomy.outcome": "Scored for autonomy",
}
# What each message about a fix plan was, by its `what` (activities.announce).
TOLD = {"waiting": "Asked for approval", "approved": "Approved", "denied": "Denied", "expired": "Expired",
        "verified": "Fixed - its health checks passed", "recovered": "Fixed and held", "relapsed": "Failed again",
        "rolled_back": "Did not work - undone", "not_recovered": "Did not work", "drifted": "Changed since planned",
        "refused_at_apply": "Not applied", "rollback_failed": "Undo failed", "apply_failed": "Apply failed",
        "refused": "Refused before asking", "blocked": "Blocked before asking",
        "side_effects": "Worked, but other alarms started after it"}
# A verdict and a plan's state in words, where the step table would show the machine's.
PLAIN = {"approved_for_human": "passed its checks - waits for a person", "escalated": "sent to a person",
         "rejected": "refused", "ran": "ran", "off": "off"}
# Every status a record can say (record(), below), in the order the list's filter offers them.
STATUSES = tuple(dict.fromkeys((IN_PROGRESS, "Diagnosed", NO_PLAN, "Waiting for approval",
                                "Approved - being applied", "Cleared while expected down",
                                *(label for label, _ in ENDED.values()), "Failed", "Cancelled")))
_QUIET = {"incident.llm_spend", "incident.llm_reserve", "approval.challenge", "approval.challenge_taken",
          "approval.link", "approval.link_used", "chatops.thread", "discuss.reply", "intake.reopen_started"}


@dataclass
class Record:
    """One incident as its record says it is."""

    id: str
    first: datetime
    last: datetime
    alarm: str = ""
    environment: str = ""
    service: str = ""
    severity: str = ""
    summary: str = ""
    status: str = IN_PROGRESS
    kind: str = "info"
    hypothesis: str = ""
    confidence: float | None = None
    action: str = ""
    target: str = ""
    verdict: str = ""
    policies: list[str] = field(default_factory=list)
    plan: dict[str, Any] = field(default_factory=dict)
    no_plan: str = ""
    decisions: list[dict[str, Any]] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    asked: int = 0
    report: str = ""
    evidence: str = ""  # what the model was shown, as kept with the incident (incident.evidence)
    also: list[str] = field(default_factory=list)  # other alerts on the same resource that joined it (intake.grouped)
    rows: list[dict[str, Any]] = field(default_factory=list)
    shown: Any = None  # approver id -> the name a reader sees; never the list's id
    # The record's own integrity, checked when it is read (not `light`): the incident's audit head - the hash every
    # Slack footer names - and how many of its rows a signed checkpoint covers and are intact, how many are not signed
    # yet, and how many do not check out (owner, 2026-10-15: a footer's command nobody could run).
    head: str = ""
    signed_ok: int = 0
    unsigned: int = 0
    broken: int = 0
    named: Any = None  # a machine text with each approver id replaced by their name
    # Its links to other records as they stand, and the proven fix they lead to (links.py); not read for the list.
    links: list[dict[str, Any]] = field(default_factory=list)
    proven: dict[str, Any] | None = None
    found: list[dict[str, Any]] = field(default_factory=list)  # links WARDEN finds in its own rows (links.found)


def incident_ids(log: Any) -> list[str]:
    """Every incident on the record, newest first - with no time limit (owner, 2026-10-14: "should be even available
    after a year too ... no time limit"): WARDEN's record is append-only, so nothing in it expires. A discussion's own
    reading of an incident (`discuss-...`) is part of that incident, not one of its own.
    ponytail: reads every start row; a SELECT DISTINCT on the audit table when there are tens of thousands."""
    seen: dict[str, datetime] = {}
    for e in log.entries(kinds=(_INGEST, _AFTER_HOLD)):
        cid = str(e["correlation_id"])
        if not cid.startswith("discuss-"):
            seen[cid] = max(seen.get(cid, e["at"]), e["at"])
    return sorted(seen, key=lambda c: seen[c], reverse=True)


def record(log: Any, incident: str, policy: Any = None, *, light: bool = False) -> Record | None:
    """One incident from its rows; None when the record holds nothing for it. `light`: for the list - every row but
    the kept evidence and the whole report, which only the incident's own page shows."""
    rows = log.entries(incident)
    if light:
        rows = [e for e in rows if e["kind"] not in (_EVIDENCE, _REPORT)]
    if not rows:
        return None
    r = Record(id=incident, first=rows[0]["at"], last=rows[-1]["at"], rows=rows)
    if not light and hasattr(log, "intact"):
        _check_signatures(r, log, rows)
    r.shown, r.named = _namers(policy)
    for e in rows:
        if read := _READ.get(e["kind"]):
            read(r, e)
    r.asked = sum(1 for e in rows if e["kind"] == "discuss.turn")
    if r.status == IN_PROGRESS and (settled := _open_status(r, rows)):
        r.status, r.kind = settled
    if not light:
        from . import links

        r.links, r.proven = links.links_of(log, incident), links.proven_fix(log, incident)
        r.found = links.found(log, incident)
    return r


def _check_signatures(r: Record, log: Any, rows: list[dict[str, Any]]) -> None:
    """The record's own integrity: its audit head, and how many of its rows are signed and intact, not signed yet, or
    do not check out."""
    try:
        seqs = [int(e["seq"]) for e in rows]
        through, ok = log.signed_through(), log.intact(seqs)
        r.head = log.head(r.id)
        r.signed_ok = len(ok)
        r.unsigned = sum(1 for s in seqs if s > through)
        r.broken = len(seqs) - r.signed_ok - r.unsigned
    except Exception:  # noqa: BLE001 - the page still shows the record; its check says it could not run
        r.head, r.broken = r.head or "", -1


def _namers(policy: Any) -> tuple[Callable[[str], str], Callable[[str], str]]:
    """How a page names an approver - by the name the list gives, never the list's id - and machine text that names
    one by the list's id (a refusal's problems), with their name instead."""
    ids = sorted(getattr(policy, "approvers", {}) if policy is not None else {}, key=len, reverse=True)

    def shown(approver: str) -> str:
        if policy is not None and approver in getattr(policy, "approvers", {}):
            return policy.shown(approver)
        return "an approver"  # never the list's id

    def named(text: str) -> str:
        """Machine text that names an approver by the list's id (a refusal's problems), with their name instead."""
        for a in ids:
            text = re.sub(rf"(?<![A-Za-z0-9._-]){re.escape(a)}(?![A-Za-z0-9._-])", shown(a), text)
        return text

    return shown, named


def _open_status(r: Record, rows: list[dict[str, Any]]) -> tuple[str, str] | None:
    """The status of a record no fix run has ended yet, from how far it got; None where it is still in progress."""
    if any(d["what"] == "Approved" for d in r.decisions):
        return "Approved - being applied", "info"
    if r.plan:
        return "Waiting for approval", "warn"
    if r.no_plan:
        return NO_PLAN, "info"
    if any(e["kind"] == _AFTER_HOLD and e["body"].get("firing") is False for e in rows):
        return "Cleared while expected down", "ok"
    if r.verdict:
        return "Diagnosed", "info"
    return None


# What each kind of row adds to the record (record(), above). A kind not here adds nothing.

def _read_alert(r: Record, e: dict[str, Any]) -> None:
    a = e["body"].get("alert") or {}
    r.alarm = str((a.get("labels") or {}).get("alarm") or a.get("name") or "")
    r.environment, r.service = str(a.get("environment") or ""), str(a.get("service") or "")
    r.severity, r.summary = str(a.get("severity") or ""), str(a.get("summary") or "")


def _read_ingest(r: Record, e: dict[str, Any]) -> None:
    if not r.environment:
        r.environment = str(e["body"].get("env") or "")


def _read_diagnosis(r: Record, e: dict[str, Any]) -> None:
    b = e["body"]
    r.hypothesis, r.action, r.target = str(b.get("hypothesis") or ""), str(b.get("action") or ""), str(
        b.get("target") or "")
    r.confidence = b.get("confidence") if isinstance(b.get("confidence"), int | float) else None
    if b.get("degraded"):
        r.hypothesis = r.hypothesis or f"No diagnosis: {b['degraded']}"


def _read_verify(r: Record, e: dict[str, Any]) -> None:
    b = e["body"]
    r.verdict, r.policies = str(b.get("status") or ""), [str(p) for p in b.get("policies") or []]


def _read_tripwire(r: Record, e: dict[str, Any]) -> None:
    b = e["body"]
    if b.get("flagged"):
        r.flags.append("The injection check flagged evidence that tried to instruct WARDEN: "
                       + ", ".join(str(f) for f in b["flagged"][:8]) + ". It was held away from any decision.")
    elif str(b.get("status") or "ran") not in ("ran", "off"):
        r.flags.append(f"The injection check did not finish ({b.get('status')}): the incident went to a person.")


def _read_report(r: Record, e: dict[str, Any]) -> None:
    r.report = str(e["body"].get("markdown") or "")


def _read_evidence(r: Record, e: dict[str, Any]) -> None:
    r.evidence = str(e["body"].get("prompt") or "")


def _read_grouped(r: Record, e: dict[str, Any]) -> None:
    from .reporting import ALERT_SOURCES

    b = e["body"]
    src = ALERT_SOURCES.get(str(b.get("via") or ""), "")
    r.also.append(str(b.get("name") or b.get("rule") or "") + (f" ({src})" if src else ""))


def _read_no_plan(r: Record, e: dict[str, Any]) -> None:
    r.no_plan = str(e["body"].get("why") or r.no_plan)


def _read_plan_fix(r: Record, e: dict[str, Any]) -> None:
    if not e["body"].get("planned") and e["body"].get("why"):
        _read_no_plan(r, e)


def _read_plan(r: Record, e: dict[str, Any]) -> None:
    b = e["body"]
    r.plan = {"entry": b.get("entry"), "target": b.get("target"), "tier": b.get("tier"),
              "plan_hash": b.get("plan_hash"), "made": e["at"], "workflow_id": b.get("workflow_id")}


def _read_accepted(r: Record, e: dict[str, Any]) -> None:
    from . import approvals

    b = e["body"]
    note = str(b.get("note") or "")
    ai = bool(b.get("ai"))  # Eldane (autonomy.py): always said to be an AI, with the level it approved at
    how = "passkey" if b.get("method") == "passkey" else "signing key"
    if ai:
        how = f"own signing key - an AI approval at autonomy level {b.get('autonomy', 'L2')}"
    r.decisions.append({"what": "Approved", "who": approvals.AI_LABEL if ai else r.shown(str(b.get("approver"))),
                        "at": e["at"], "how": how, "note": note,
                        "hasty": bool(b.get("hasty")), "latency": b.get("latency_s")})
    r.flags += [f"A note from {r.shown(str(b.get('approver')))} held {t}." for t in approvals.note_tries(note)]


def _read_eldane(r: Record, e: dict[str, Any]) -> None:
    from . import approvals

    b = e["body"]
    if b.get("agree") is None:
        return
    r.decisions.append({"what": "Agreed with the plan" if b.get("agree") else "Did not agree with the plan",
                        "who": approvals.AI_LABEL, "at": e["at"],
                        "how": f"review - an AI, autonomy level {b.get('level', '?')}",
                        "note": "; ".join(x.get("text", "") for p in (b.get("passes") or [])[-1:]
                                          for x in p.get("reasons", [])[:3]),
                        "hasty": False, "latency": None})


def _read_refused(r: Record, e: dict[str, Any]) -> None:
    r.flags.append("An approval was refused: "
                   + r.named("; ".join(str(p) for p in (e["body"].get("problems") or [])[:3])))


def _read_answer(r: Record, e: dict[str, Any]) -> None:
    if e["body"].get("asks_for_change") and not e["body"].get("approver"):
        r.flags.append("Someone who is not an approver asked WARDEN for a change in the discussion; WARDEN changes "
                       "nothing from there.")


def _read_end(r: Record, e: dict[str, Any]) -> None:
    b = e["body"]
    status = str(b.get("status") or "")
    for why in b.get("reasons") or []:
        _read_denial(r, e, str(why))
    if status in ENDED:
        r.status, r.kind = ENDED[status]
    elif status:
        r.status, r.kind = status.replace("_", " ").capitalize(), "info"


def _read_denial(r: Record, e: dict[str, Any], why: str) -> None:
    """A fix run's reason that is a denial: who denied it, and their reason as their note."""
    from . import approvals

    if why.startswith("denied by "):
        who, _, reason = why.removeprefix("denied by ").partition(": ")
        r.decisions.append({"what": "Denied", "who": r.shown(who), "at": e["at"], "how": "passkey",
                            "note": reason, "hasty": False, "latency": None})
        r.flags += [f"A reason from {r.shown(who)} held {t}." for t in approvals.note_tries(reason)]


_READ: dict[str, Callable[[Record, dict[str, Any]], None]] = {
    "incident.alert": _read_alert, _INGEST: _read_ingest, "incident.diagnose": _read_diagnosis,
    "incident.verify": _read_verify, "incident.tripwire": _read_tripwire, _REPORT: _read_report,
    _EVIDENCE: _read_evidence, "intake.grouped": _read_grouped, "incident.no_plan": _read_no_plan,
    "incident.plan_fix": _read_plan_fix, "remediation.plan": _read_plan, "approval.accepted": _read_accepted,
    "eldane.verdict": _read_eldane, "approval.refused": _read_refused, "discuss.answer": _read_answer,
    "workflow.end": _read_end,
}


# ------------------------------------------------------------------ the list's paging and filters (owner, 2026-10-16)
# A query string is the reader's own text: each field is read strictly, and anything unknown, repeated or malformed
# refuses the whole query rather than being guessed at. A page past the end is the last page; a page size not offered
# is the default one.

_KEYS = ("page", "size", "env", "status", "service", "from", "to", "q")
_ENV = re.compile(r"[a-z][a-z0-9-]{0,30}")  # environments.py's own shape for a name
_SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,63}")
_DAY = re.compile(r"\d{4}-\d{2}-\d{2}", re.ASCII)
_PAGE_NO = re.compile(r"[1-9]\d{0,6}", re.ASCII)
TEXT_MAX = 100


@dataclass(frozen=True)
class Query:
    """One reading of the list: which page, how many a page, and the filters - all of them must hold."""

    page: int = 1
    size: int = PER_PAGE
    env: str = ""
    status: str = ""
    service: str = ""
    since: date | None = None  # `from`, the display zone's day, inclusive
    until: date | None = None  # `to`, inclusive
    text: str = ""  # `q`: in the incident's title or id, any case

    @property
    def filtered(self) -> bool:
        return bool(self.env or self.status or self.service or self.since or self.until or self.text)

    def admits(self, r: Record) -> bool:
        from .environments import display_zone

        day = r.first.astimezone(display_zone()).date()
        return ((not self.env or r.environment.lower() == self.env)
                and (not self.status or r.status == self.status)
                and (not self.service or r.service.lower() == self.service.lower())
                and (self.since is None or day >= self.since) and (self.until is None or day <= self.until)
                and (not self.text or self.text.lower() in f"{r.alarm or r.id} {r.id}".lower()))

    def href(self, page: int = 1, incident: str = "") -> str:
        """This reading's own address - the list at `page`, or an incident's page within the same filters."""
        pairs = [("page", str(page))] if page > 1 and not incident else []
        pairs += [("size", str(self.size))] if self.size != PER_PAGE else []
        pairs += [(k, v) for k, v in (("env", self.env), ("status", self.status), ("service", self.service),
                                       ("from", self.since.isoformat() if self.since else ""),
                                       ("to", self.until.isoformat() if self.until else ""), ("q", self.text)) if v]
        path = f"/r/{incident}" if incident else "/r"
        return path + ("?" + urllib.parse.urlencode(pairs) if pairs else "")


def parse_query(query: str) -> Query | None:
    """The reader's query string as a Query; None when any part of it is not one the list reads."""
    try:
        pairs = urllib.parse.parse_qsl(query or "", keep_blank_values=True, strict_parsing=bool(query),
                                       max_num_fields=len(_KEYS))
    except ValueError:
        return None
    got = dict(pairs)
    if len(got) != len(pairs) or set(got) - set(_KEYS):
        return None
    page = got.get("page") or "1"
    env, status, service = got.get("env", ""), got.get("status", ""), got.get("service", "")
    text = " ".join(got.get("q", "").split())
    if not _readable(page, env, status, service, text):
        return None
    days = _days(got)
    if days is None:
        return None
    since, until = days
    size = int(got["size"]) if got.get("size") in {str(s) for s in SIZES} else PER_PAGE
    return Query(page=int(page), size=size, env=env, status=status, service=service, since=since, until=until,
                 text=text)


def _readable(page: str, env: str, status: str, service: str, text: str) -> bool:
    """Each of these fields is one the list reads: a page number, an environment's name, a status the list says, a
    service's name, and printable text no longer than TEXT_MAX."""
    return not (not _PAGE_NO.fullmatch(page) or (env and not _ENV.fullmatch(env)) or (status and status not in STATUSES)
                or (service and not _SERVICE.fullmatch(service)) or len(text) > TEXT_MAX or not text.isprintable())


def _days(got: dict[str, str]) -> tuple[date | None, date | None] | None:
    """`from` and `to` as days (None where not given); None when either is not a day, or the first comes after the
    last."""
    days = []
    for key in ("from", "to"):
        raw = got.get(key, "")
        try:
            days.append(date.fromisoformat(raw) if raw and _DAY.fullmatch(raw) else None)
        except ValueError:
            return None
        if raw and days[-1] is None:
            return None
    since, until = days
    if since and until and since > until:
        return None
    return since, until


def matching(log: Any, asked: Query, allowed: set[str] | None, policy: Any = None
             ) -> tuple[list[str], dict[str, Record], int]:
    """The incidents this reading lists, newest first; the records read on the way; and how many the reader may read
    at all. `allowed`: the environments the reader may read (None: every one).
    ponytail: with a filter or a limited reader, reads every incident's rows (light); an index on the audit's
    environment and status when there are thousands."""
    ids = incident_ids(log)
    if allowed is None and not asked.filtered:
        return ids, {}, len(ids)
    out, loaded, seen = [], {}, 0
    for i in ids:
        r = record(log, i, policy, light=True)
        if r is None or (allowed is not None and r.environment not in allowed):
            continue
        seen += 1
        if asked.admits(r):
            out.append(i)
            loaded[i] = r
    return out, loaded, seen


# ------------------------------------------------------------------ pages


def _e(value: Any) -> str:
    # Braces too: a page's placeholders ({{NONCE}}, {{SCRIPT}}) are filled after its content is in, and a record's
    # text must never be one of them.
    return html.escape(str(value), quote=True).replace("{", "&#123;").replace("}", "&#125;")


def _when(t: datetime | None) -> str:
    from .environments import both_times

    return both_times(t, seconds=False) if t else "-"


def _badge(r: Record) -> str:
    return f'<span class="badge {r.kind}">{_e(r.status)}</span>'


def _facts(pairs: list[tuple[str, str]]) -> str:
    return '<dl class="facts">' + "".join(f"<dt>{_e(k)}</dt><dd>{v}</dd>" for k, v in pairs if v) + "</dl>"


def _decisions(r: Record) -> str:
    if not r.decisions:
        return '<p class="quiet">No decision on the record.</p>'
    out = []
    for d in r.decisions:
        lat = f" after {d['latency']:.0f} s" if isinstance(d.get("latency"), int | float) else ""
        hasty = ' <span class="badge warn">Quick decision</span>' if d.get("hasty") else ""
        note = (f'<blockquote class="note">{_e(d["note"])}</blockquote>' if d.get("note")
                else '<p class="quiet">No note.</p>')
        out.append(f'<li><p><strong>{_e(d["what"])}</strong> by {_e(d["who"])} with their {_e(d["how"])} at '
                   f'<time>{_e(_when(d["at"]))}</time>{_e(lat)}{hasty}</p>{note}</li>')
    return '<ul class="decisions">' + "".join(out) + _UL_END


def _flags(r: Record) -> str:
    if not r.flags:
        return '<p class="quiet">Nothing on the record tried to steer WARDEN.</p>'
    return '<ul class="flags">' + "".join(f"<li>{_e(f)}</li>" for f in r.flags) + _UL_END


def _summary_facts(r: Record) -> list[tuple[str, str]]:
    conf = f" (confidence {r.confidence:.2f})" if r.confidence is not None else ""
    plan = (f'<span class="mono">{_e(r.plan.get("entry"))}</span> on <span class="mono">{_e(r.plan.get("target"))}'
            f'</span> - risk {_e(r.plan.get("tier"))}' if r.plan else "")
    policies = f" ({', '.join(r.policies)})" if r.policies else ""
    return [("Alarm", _e(r.alarm)), ("Where", _e(" / ".join(x for x in (r.environment, r.service) if x))),
            ("Severity", _e(r.severity)), ("Alert says", _e(r.summary)), ("First seen", _e(_when(r.first))),
            ("Last step", _e(_when(r.last))), ("WARDEN thinks", _e(r.hypothesis + conf) if r.hypothesis else ""),
            ("Safety check", _e(r.verdict.replace("_", " ") + policies) if r.verdict else ""),
            ("Fix plan", plan or (_e("None: " + r.no_plan) if r.no_plan else "")),
            ("Also fired", _e("; ".join(r.also)) if r.also else ""),
            ("Discussion", _e(f"{r.asked} question(s) in the discussion channel") if r.asked else "")]


def _day(t: datetime) -> str:
    """The day a row starts under: the display zone's date, as people say it."""
    from .environments import display_zone

    return t.astimezone(display_zone()).strftime("%A %d %B %Y")


def _filters(asked: Query, envs: tuple[str, ...]) -> str:
    """The list's filters: a plain GET form, so it works with no script at all; every field labelled."""
    def options(values: Any, chosen: str) -> str:
        return '<option value="">Any</option>' + "".join(
            f'<option value="{_e(v)}"{" selected" if v == chosen else ""}>{_e(v)}</option>' for v in values)

    def field(key: str, label: str, control: str, wide: bool = False) -> str:
        return (f'<p class="field{" wide" if wide else ""}"><label for="f-{key}">{label}</label>'
                + control.replace("ID", f'id="f-{key}" name="{key}"', 1) + "</p>")

    def day(d: date | None) -> str:
        return d.isoformat() if d else ""

    envs = tuple(dict.fromkeys((*envs, *((asked.env,) if asked.env else ()))))
    keep = f'<input type="hidden" name="size" value="{asked.size}">' if asked.size != PER_PAGE else ""
    fields = [
        field("q", "Title or id contains", f'<input ID type="search" maxlength="{TEXT_MAX}" autocomplete="off" '
                                           f'value="{_e(asked.text)}">', wide=True),
        field("env", "Environment", f"<select ID>{options(envs, asked.env)}</select>"),
        field("status", "Status", f"<select ID>{options(STATUSES, asked.status)}</select>"),
        field("service", "Service", f'<input ID maxlength="64" autocomplete="off" spellcheck="false" '
                                    f'value="{_e(asked.service)}">'),
        field("from", "From day", f'<input ID type="date" value="{_e(day(asked.since))}">'),
        field("to", "To day", f'<input ID type="date" value="{_e(day(asked.until))}">'),
    ]
    return (f'<details class="filters"{" open" if asked.filtered else ""}><summary>Filter'
            f'{" - on" if asked.filtered else ""}</summary>'
            '<form method="get" action="/r" role="search" aria-label="Filter the incidents">' + "".join(fields)
            + f'{keep}<p class="go"><button class="primary" type="submit">Show</button>'
            f'<a class="button plain" href="{_e(Query(size=asked.size).href())}">Clear</a></p></form></details>')


def _pager(asked: Query, page: int, pages: int) -> str:
    """Newest, newer, where, older, oldest - each a plain link; the ends of the list say so instead."""
    def go(label: str, to: int, rel: str) -> str:
        if to < 1 or to > pages or to == page:
            return f'<span class="step {rel} off" aria-disabled="true">{label}</span>'
        rel_attr = f' rel="{rel}"' if rel in ("prev", "next") else ""
        return f'<a class="step {rel}" href="{_e(asked.href(to))}"{rel_attr}>{label}</a>'

    newest, oldest = '<span class="t">Newest</span>', '<span class="t">Oldest</span>'
    return (f'<nav class="pager" aria-label="Pages">{go(newest, 1, "first")}{go("Newer", page - 1, "prev")}'
            f'<span class="quiet at">Page {page} of {pages}</span>{go("Older", page + 1, "next")}'
            f'{go(oldest, pages, "last")}</nav>')


def _sizes(asked: Query) -> str:
    links = "".join(f'<span class="chip" aria-current="true">{s}</span>' if s == asked.size else
                    f'<a class="chip" href="{_e(dataclasses.replace(asked, size=s).href())}">{s}</a>'
                    for s in SIZES)
    return f'<p class="sizes"><span class="quiet">Per page</span>{links}</p>'


def list_page(records: list[Record], *, page: int = 1, pages: int = 1, total: int | None = None,
              matched: int | None = None, asked: Query | None = None, envs: tuple[str, ...] = ()) -> str:
    """One page of the list: one row per incident under its day, newest first, its summary in view and its details
    folded beneath it - the filters, how many match, the page size, and the way to the newer and older pages.
    `total`: the incidents the reader may read; `matched`: how many of them the filters keep."""
    asked = asked or Query(page=page)
    if matched is None:
        matched = total if total is not None else len(records)
    body = _list_body(records, asked)
    plural = "s" if total != 1 else ""
    count = f"{total} incident{plural} on the record" if total is not None else ""
    first = (page - 1) * asked.size + 1 if matched else 0
    last = min(page * asked.size, matched)
    showing = (f'<p class="showing">Showing <strong>{first}–{last}</strong> of '
               f'<strong>{matched}</strong>{" matching the filters" if asked.filtered else ""}</p>')
    bar = f'<div class="toolbar">{showing}{_sizes(asked)}</div>'
    nav = _pager(asked, page, pages) if pages > 1 else ""
    return _shell(_TITLE, "Records", "<h1>Incidents</h1><p class=\"lede\">Every incident WARDEN has "
                  "handled, newest first" + (f" - {_e(count)}" if count else "") + ". Open a row for its details, or "
                  "its full record for everything WARDEN found, read and did.</p>" + _filters(asked, envs) + bar
                  + nav + body + nav, refresh=page == 1)


def _list_body(records: list[Record], asked: Query) -> str:
    """The list's rows, each under its day - or, with none, why there is nothing to show."""
    if not records:
        return ('<p class="quiet pad empty">No incident matches these filters.</p>' if asked.filtered
                else '<p class="quiet pad empty">No incident on the record yet.</p>')
    items, day = [], ""
    for r in records:
        if _day(r.first) != day:
            day = _day(r.first)
            items.append(f'<h2 class="day">{_e(day)}</h2>')
        items.append(_list_row(r, asked))
    return '<div class="rows">' + "".join(items) + "</div>"


def _list_row(r: Record, asked: Query) -> str:
    """One incident's row: its summary in view, its details folded beneath it."""
    title = r.alarm or r.id
    return (f'<details class="row"><summary><span class="when"><time>{_e(_when(r.first))}</time></span>'
            f'<span class="what"><strong>{_e(title)}</strong><span class="sub">{_e(r.environment)}'
            f'{" / " + _e(r.service) if r.service else ""}</span></span><span class="tags">{_badge(r)}'
            f'{"<span class=" + chr(34) + "badge bad" + chr(34) + ">Flagged</span>" if r.flags else ""}</span>'
            f'</summary>'
            f'<div class="more">{_facts(_summary_facts(r))}'
            f'<h3>Decisions</h3>{_decisions(r)}<h3>Anything that tried to steer WARDEN</h3>{_flags(r)}'
            f'<p><a class="open" href="{_e(asked.href(incident=r.id))}">Open the full record</a></p>'
            f'</div></details>')


def bad_query_page() -> str:
    return _shell(_TITLE, "Records", '<h1>That list cannot be shown</h1><p class="lede">The address asks '
                  "for a page or a filter the list does not read: a page is a whole number from 1, a day is written "
                  'YYYY-MM-DD, and the first day comes before the last. <a href="/r">See every incident</a>.</p>')


def integrity(r: Record) -> str:
    """The record's check, in words: its audit head - the one the Slack footers name - and what the signatures say."""
    if not r.head:
        return ""
    from .audit import short

    if r.broken < 0:
        state = "its signatures could not be checked just now"
    elif r.broken:
        state = f"{r.broken} row(s) DO NOT CHECK OUT - the record was changed after it was written"
    else:
        state = (f"{r.signed_ok} row(s) signed and intact"
                 + (f", the newest {r.unsigned} not signed yet (a checkpoint signs them shortly)" if r.unsigned else ""))
    return f"Signed record: audit head {short(r.head)} - {len(r.rows)} row(s), {state}. Checked when this page opened."


def neighbours(ids: list[str], incident: str, asked: Query | None = None) -> str:
    """The way back to the list - to the page this incident is on - and to the newer and older incident, within the
    same filters (owner, 2026-10-16: "same arrows on a record page")."""
    asked = asked or Query()
    if incident not in ids:
        return f'<nav class="recnav" aria-label="Incidents"><a class="step back" href="{_e(asked.href())}">All incidents</a></nav>'
    at = ids.index(incident)

    def go(label: str, to: int, rel: str) -> str:
        if not 0 <= to < len(ids):
            return f'<span class="step {rel} off" aria-disabled="true">{label}</span>'
        return f'<a class="step {rel}" href="{_e(asked.href(incident=ids[to]))}" rel="{rel}">{label}</a>'

    return (f'<nav class="recnav" aria-label="Incidents"><a class="step back" href="{_e(asked.href(at // asked.size + 1))}">'
            f'All incidents</a><span class="quiet at">{at + 1} of {len(ids)}</span>'
            f'{go("Newer", at - 1, "prev")}{go("Older", at + 1, "next")}</nav>')


def incident_page(r: Record, *, approve: str = "", near: str = "") -> str:
    """One incident: its summary, decisions and flags, the report as WARDEN wrote it, and every step on the record.
    `approve`: this site's own address that opens the plan for the reader, when they may approve it now (owner,
    2026-10-15: "the approve button i dont see here"). `near`: neighbours(), the way to the list and the next ones."""
    act = (f'<p class="pad act"><a class="primary button" href="{_e(approve)}">{_e(APPROVE_LABEL)}</a>'
           '<span class="hint">Your passkey decides; this only opens the plan.</span></p>') if approve else ""
    checked = f'<p class="small mono">{_e(integrity(r))}</p>' if integrity(r) else ""
    main = (f'{near or neighbours([], r.id)}<h1>{_e(r.alarm or r.id)}</h1>'
            f'<p class="lede">{_badge(r)} Incident <span class="mono">{_e(r.id)}</span></p>{checked}{act}'
            '<p class="pad tools"><button type="button" class="link" id="all" aria-controls="sections">'
            'Open all sections</button></p>'
            f'<h2>Summary</h2>{_facts(_summary_facts(r))}'
            f'<h2>Decisions</h2>{_decisions(r)}{linked(r)}{found_links(r)}'
            f'<h2>Anything that tried to steer WARDEN</h2>{_flags(r)}{_told(r)}{_report(r)}'
            f'<details class="block"><summary>Every step on the record</summary><div class="scroll"><table>'
            f'<thead><tr><th scope="col">When</th><th scope="col">Step</th><th scope="col">Details</th></tr></thead>'
            f'<tbody>{_steps(r)}</tbody></table></div></details>')
    return _shell(f"WARDEN - {r.alarm or r.id}", "Record", main, script=_OPEN_ALL_JS)


def _steps(r: Record) -> str:
    """Every step on the record but the quiet ones, one table row each: when, what, and its own facts."""
    steps = []
    for e in r.rows:
        if e["kind"] in _QUIET:
            continue
        said = (TOLD.get(str(e["body"].get("what")), "Told people how the fix ended")
                if e["kind"] == _ANNOUNCE else _step(e))
        brief = _brief(e, r.shown)
        steps.append(f'<tr><td><time>{_e(_when(e["at"]))}</time></td><td>{_e(said)}</td>'
                     f'<td class="small">{_e(r.named(brief) if r.named else brief)}</td></tr>')
    return "".join(steps)


def _told(r: Record) -> str:
    """What WARDEN told people about the fix, each message where it went - nothing when it told nobody."""
    told = [e for e in r.rows if e["kind"] == _ANNOUNCE]
    if not told:
        return ""
    return ('<h2>What WARDEN told people</h2><ul class="decisions">' + "".join(_told_item(r, e) for e in told)
            + _UL_END)


def _told_item(r: Record, e: dict[str, Any]) -> str:
    b = e["body"]
    text = ""
    if b.get("said"):
        said = r.named(str(b["said"])) if r.named else b["said"]
        text = f'<blockquote class="note">{_e(said)}</blockquote>'
    return (f'<li><p><strong>{_e(TOLD.get(str(b.get("what")), "How the fix ended"))}</strong> - '
            f'<time>{_e(_when(e["at"]))}</time> - {_e(_where_told(b))}</p>{text}</li>')


def _where_told(b: dict[str, Any]) -> str:
    if b.get("recorded_only"):
        return "kept here, not posted"
    return "posted in the alerts channel" if b.get("delivered") else "not delivered"


def _report(r: Record) -> str:
    """The report as WARDEN wrote it, and the evidence its model was shown."""
    report = ""
    if r.report:
        report = ('<h2>Complete findings</h2><p class="lede">Everything WARDEN found and proposed, as its report says '
                  'it. Open a section to read it.</p>' + findings(r.report))
    if r.evidence:
        report += ('<details class="block"><summary>The evidence WARDEN read, exactly as its model was shown it'
                   f'</summary><pre class="report">{_e(r.evidence)}</pre></details>')
    return report


def _at(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def _step(e: dict[str, Any]) -> str:
    """A step's plain words; a link taken back says so (CodeRabbit, PR 56: it read as a new link)."""
    if e["kind"] == "record.link" and e["body"].get("removed"):
        return "A link to another record was taken back by an approver"
    return STEP.get(e["kind"], e["kind"])


def linked(r: Record) -> str:
    """The incident's links to other records - each in plain words, who linked it and when, the other record one
    click away - and the proven fix they lead to (links.py). Nothing when it has none."""
    if not r.links and not r.proven:
        return ""
    from . import links

    def who(approver: str) -> str:
        name = r.shown(approver) if r.shown else ""
        return name if name and name != approver else "an approver"  # never the list's id

    items = []
    for k in r.links:
        note = f'<blockquote class="note">{_e(k["note"])}</blockquote>' if k.get("note") else ""
        items.append(f'<li><p>This incident {_e(links.WORDS[k["side"]])} <a href="{_e(Query().href(incident=k["with"]))}">'
                     f'<span class="mono">{_e(k["with"])}</span></a> - linked by {_e(who(str(k.get("approver"))))} '
                     f'at <time>{_e(_when(_at(k.get("at"))))}</time></p>{note}</li>')
    out = '<h2>Linked records</h2><ul class="decisions">' + "".join(items) + _UL_END if items else ""
    if r.proven:
        f = r.proven
        out += (f'<p class="pad"><strong>Proven fix on a linked record:</strong> <span class="mono">{_e(f["entry"])}</span>'
                f' on <span class="mono">{_e(f["target"])}</span> was applied and verified in '
                f'<a href="{_e(Query().href(incident=f["incident"]))}"><span class="mono">{_e(f["incident"])}</span></a> '
                f'at <time>{_e(_when(f["verified_at"]))}</time> ({len(f["path"])} link(s) away). A fact from the '
                'record for a person to weigh: WARDEN does not apply it on that account.</p>')
    return out


def found_links(r: Record) -> str:
    """The links WARDEN found in its own record (links.found): a re-diagnosis, an alarm after a fix, a relapse, the
    same alarm or resource - each one click away, said to be WARDEN's finding and not a person's link."""
    if not r.found:
        return ""
    items = "".join(f'<li>This incident {_e(k["words"])} <a href="{_e(Query().href(incident=k["with"]))}">'
                    f'<span class="mono">{_e(k["with"])}</span></a></li>' for k in r.found)
    return ('<h2>Related records WARDEN found</h2><p class="lede">From WARDEN\'s own signed rows. A person confirms a '
            'shared cause with <code>warden link</code>; only then can a fix there count as proven here.</p>'
            f'<ul class="flags">{items}</ul>')


_FENCE = "```"
_INLINE = (
    (re.compile(r"`([^`\n]+)`"), r"<code>\1</code>"),
    (re.compile(r"\*\*([^*\n]+)\*\*"), r"<strong>\1</strong>"),
)


def _inline(text: str) -> str:
    """One line of the report as HTML: escaped first, then only code spans and bold - nothing else becomes markup."""
    out = _e(text)
    for pattern, tag in _INLINE:
        out = pattern.sub(tag, out)
    if len(text) > 2 and text.startswith("_") and text.endswith("_"):
        out = f"<em>{out[1:-1]}</em>"
    return out


def _section(lines: list[str]) -> str:
    """A report section's lines as paragraphs, lists (one level of nesting) and code blocks."""
    s = _Section()
    for line in lines:
        if line.strip().startswith(_FENCE):
            s.fence()
        elif s.in_code:
            s.code.append(line)
        else:
            s.text(line)
    if s.in_code and s.code:
        s.out.append(f'<pre class="code">{_e(chr(10).join(s.code))}</pre>')
    s.close_list()
    return "".join(s.out)


@dataclass
class _Section:
    """_section's reading so far: the HTML, the code block being read, and whether a list is open."""

    out: list[str] = field(default_factory=list)
    code: list[str] = field(default_factory=list)
    in_code: bool = False
    open_list: bool = False

    def close_list(self) -> None:
        if self.open_list:
            self.out.append(_UL_END)
            self.open_list = False

    def fence(self) -> None:
        """A fence line closes the code block being read, or opens one (closing any open list first)."""
        if self.in_code:
            self.out.append(f'<pre class="code">{_e(chr(10).join(self.code))}</pre>')
            self.code, self.in_code = [], False
        else:
            self.close_list()
            self.in_code = True

    def text(self, line: str) -> None:
        """A line outside code: a list item, a list item's own second line, or a paragraph."""
        item = line.lstrip()
        if item.startswith("- "):
            if not self.open_list:
                self.out.append("<ul>")
                self.open_list = True
            nested = ' class="sub"' if line.startswith("  ") else ""
            self.out.append(f"<li{nested}>{_inline(item[2:])}</li>")
        elif self.open_list and line.startswith("  ") and item:  # a list item's own second line
            self.out.append(f'<li class="more-line">{_inline(item)}</li>')
        else:
            self.close_list()
            if item:
                self.out.append(f"<p>{_inline(item)}</p>")


def findings(markdown: str) -> str:
    """The report WARDEN wrote, section by section, each its own panel that unfolds - the whole of it, in-depth,
    laid out as a page rather than as a message (owner, 2026-10-14: "complete findings on page to refer if needed")."""
    head, *parts = re.split(r"(?m)^## ", markdown)
    intro = [ln for ln in head.splitlines() if ln.strip() and not ln.startswith("# ")]
    out = [f'<div class="intro">{_section(intro)}</div>'] if intro else []
    for part in parts:
        title, _, body = part.partition("\n")
        if title.strip().startswith("Summary"):
            continue  # its facts are at the top of the page
        out.append(f'<details class="block finding"><summary>{_inline(title.strip())}</summary>'
                   f'<div class="body">{_section(body.splitlines())}</div></details>')
    return "".join(out)


# "Open all": every panel on the page - the findings, the evidence the model was shown, every step (owner,
# 2026-10-15: "open all ... didnt open all, the evidence ... every step on the record these 2 didnt open").
_OPEN_ALL_JS = """
const all = document.getElementById("all");
if (all) all.addEventListener("click", () => {
  const panels = [...document.querySelectorAll("details.block")];
  const open = panels.some(d => !d.open);
  panels.forEach(d => { d.open = open; });
  all.textContent = open ? "Close all sections" : "Open all sections";
});
"""
APPROVE_LABEL = "Open the plan to approve or deny"


_DENIED = re.compile(r"^denied by ([A-Za-z0-9._-]{1,64})(?:: .*)?$", re.DOTALL)


def _brief(e: dict[str, Any], shown: Any = None) -> str:
    """A step's own facts, short: the fields a reader looks for. A person by their name, never the list's id, and
    never their whole note (that is in Decisions, above)."""
    b = e["body"]
    parts = [f"{k}: {_brief_value(k, b[k], shown)}" for k in _BRIEF_KEYS if k in b and b[k] not in (None, "", [], {})]
    return "; ".join(parts)[:400]


_BRIEF_KEYS = ("status", "action", "target", "entry", "tier", "planned", "why", "flagged", "delivered", "verdict",
               "policies", "healthy", "found", "firing", "problems", "reasons", "hasty")


def _brief_value(k: str, v: Any, shown: Any) -> Any:
    """One field of a step, as _brief shows it: a denial by the approver's name, a verdict in words, a list joined."""
    if k == "reasons":
        v = [_reason(w, shown) for w in v]
    if k in ("status", "verdict") and str(v) in PLAIN:
        v = PLAIN[str(v)]
    return ', '.join(map(str, v)) if isinstance(v, list) else v


def _reason(w: Any, shown: Any) -> str:
    """A fix run's reason; a denial names the approver by their name, never the list's id."""
    m = _DENIED.match(str(w))
    if not m:
        return str(w)
    return f"denied by {shown(m.group(1)) if shown else 'an approver'}"


def signed_out_page(go: str) -> str:
    return _shell(_TITLE, "Records", f'<h1>Sign in to read the records</h1><p class="lede">WARDEN\'s '
                  f'records are for the people on its approver and viewer lists.</p><p class="pad"><a class="primary '
                  f'slack" href="{_e(go)}">Sign in with Slack</a></p>')


def missing_page() -> str:
    return _shell(_TITLE, "Records", "<h1>No such incident</h1><p class=\"lede\">WARDEN's record holds "
                  "nothing under that id. <a href=\"/r\">See every incident</a>.</p>")


def unavailable_page() -> str:
    return _shell(_TITLE, "Records", "<h1>Sign-in is not set up</h1><p class=\"lede\">WARDEN's records open "
                  "only after Slack says who is reading, and this runtime has no Slack sign-in configured.</p>")


def refused_page() -> str:
    return _shell(_TITLE, "Records", '<h1>Not on the list</h1><p class="lede">This Slack account is not on '
                  "WARDEN's approver or viewer list, so its records are not shown. Ask an approver to add you.</p>")


# ------------------------------------------------------------------ pilot metrics (pilot.py)

# `/r/pilot`: the pilot metrics, for the same readers as the records and limited to the environments they may read. No
# incident id is this word: intake names incidents `<fingerprint>-<time>` (intake.py).
PILOT = "pilot"
PILOT_DAYS = (7, 30, 90)


def pilot_since(query: str, now: datetime | None = None) -> datetime | None:
    """The page's one field, `since=YYYY-MM-DD` (UTC; the last 7 days when absent); None when the query is anything
    else, or a day still to come."""
    from . import pilot

    try:
        pairs = urllib.parse.parse_qsl(query or "", keep_blank_values=True, strict_parsing=bool(query), max_num_fields=1)
    except ValueError:
        return None
    if any(k != "since" for k, _ in pairs):
        return None
    raw = pairs[0][1] if pairs else ""
    if not raw:
        return pilot.default_since(now)
    if not _DAY.fullmatch(raw):
        return None
    try:
        return pilot.parse_since(raw, now)
    except ValueError:
        return None


def pilot_page(r: Any) -> str:
    """The pilot metrics of `r` (pilot.Report): the same lines as `warden report pilot`, without naming the rows that
    failed verification (their count is shown)."""
    from . import pilot

    rows = "".join(f'<tr><th scope="row">{_e(k)}</th><td>{_e(v)}</td></tr>' for k, v in pilot.lines(r, detail=False))
    chips = "".join(f'<a class="chip" href="/r/{PILOT}?since={pilot.default_since(r.until, d).date().isoformat()}">'
                    f"{d} days</a>" for d in PILOT_DAYS)
    failed = 0 if r.scoped else len(r.checked.failed)  # audit-wide: only for readers of every environment
    warn = (f'<p class="lede"><span class="badge bad">Not counted</span>{_e(failed)} row(s) of the record failed '
            "verification and are left out of every number below. <code>warden audit verify</code> names them.</p>"
            if failed else "")
    return _shell("WARDEN pilot metrics", "Pilot metrics",
                  '<h1>Pilot metrics</h1><p class="lede">Read only from rows of WARDEN\'s record whose signatures and '
                  "hash chain check out. How each number is counted: docs/OPERATIONS.md, Pilot metrics.</p>" + warn
                  + f'<p class="sizes pad"><span class="quiet">Since</span>{chips}</p>'
                  + f'<div class="scroll pad"><table>{rows}</table></div>')


def pilot_unchecked_page() -> str:
    return _shell("WARDEN pilot metrics", "Pilot metrics", '<h1>Pilot metrics cannot be shown</h1><p class="lede">'
                  "This runtime cannot check the record's signatures, and no number is shown from rows that were not "
                  'checked. <a href="/r">See every incident</a>.</p>')


_RECORDS_STYLE = """
.page.wide{max-width:66rem}
.sheet h1{margin-top:1.375rem}
h2{font-size:1.0625rem;margin:1.75rem 1.25rem .5rem}
h3{font-size:.9375rem;margin:1.25rem 0 .5rem}
.quiet{color:var(--muted)}
.pad{padding:0 1.25rem 1.25rem}
.small{font-size:.8125rem}
.empty{padding-top:1.25rem}
.badge{display:inline-flex;align-items:center;gap:.3125rem;font-size:.75rem;font-weight:650;padding:.1875rem .5625rem;
border-radius:999px;border:1px solid currentColor;white-space:nowrap;margin-left:.375rem;background:var(--sheet)}
.badge::before{font-size:.6875rem;line-height:1}
.badge.ok{color:var(--ok)}.badge.ok::before{content:"✓";content:"✓"/""}
.badge.warn{color:var(--warn)}.badge.warn::before{content:"!";content:"!"/""}
.badge.bad{color:var(--bad)}.badge.bad::before{content:"✕";content:"✕"/""}
.badge.info{color:var(--muted)}.badge.info::before{content:"•";content:"•"/""}
.rows{border-top:1px solid var(--line)}
.row{border-bottom:1px solid var(--line)}
.row>summary{display:grid;grid-template-columns:minmax(9rem,13rem) 1fr auto;gap:.5rem 1rem;align-items:center;
min-height:3.5rem;padding:.875rem 1.25rem;cursor:pointer;list-style:none;transition:background-color .16s,box-shadow .16s}
.row>summary::-webkit-details-marker{display:none}
.row>summary:hover,.row[open]>summary{background:var(--well);box-shadow:inset 3px 0 0 var(--accent)}
.when{color:var(--muted);font-size:.8125rem}
.what{display:flex;flex-direction:column;min-width:0;overflow-wrap:anywhere}
.sub{color:var(--muted);font-size:.8125rem}
.tags{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:.375rem}
.tags .badge{margin-left:0}
.more{padding:.25rem 1.25rem 1.25rem;background:var(--well);box-shadow:var(--in)}
.more .facts{margin:0}
.decisions,.flags{margin:0;padding-left:1.125rem}
.decisions li,.flags li{margin:.375rem 0}
.sheet>.decisions,.sheet>.flags,.sheet>.quiet{margin:0 1.25rem}
.note{margin:.375rem 0 .75rem;padding:.625rem .875rem;border-radius:.625rem;background:var(--sheet);
border:1px solid var(--line);white-space:pre-wrap;overflow-wrap:anywhere}
a{color:var(--accent);text-underline-offset:.18em}
a:hover{text-decoration-thickness:2px}
a.open{font-weight:600}
.top .nav{margin-left:auto;font-weight:600;font-size:.875rem;display:inline-flex;align-items:center;min-height:2.25rem;
padding:0 .25rem}
.top .nav~.theme{margin-left:0}
.act{display:grid;gap:.375rem;max-width:26rem}
a.button{display:block;text-align:center;text-decoration:none;font-weight:600;border-radius:.75rem;padding:.75rem 1rem}
a.plain{color:var(--ink);background:var(--sheet);border:1px solid var(--line)}
a.plain:hover{border-color:var(--muted)}
.tools{padding-bottom:0}
.block{margin:1.5rem 1.25rem 0;border:1px solid var(--line);border-radius:.75rem;overflow:hidden}
.block>summary{padding:.75rem 1rem;font-weight:600;cursor:pointer;background:var(--well)}
.block:last-child{margin-bottom:1.25rem}
.report{margin:0;padding:1rem;white-space:pre-wrap;overflow-wrap:anywhere;font:.8125rem/1.5 MONO}
.scroll{overflow-x:auto}
h2.day{margin:0;padding:1rem 1.25rem .375rem;font-size:.75rem;font-weight:650;letter-spacing:.1em;
text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--line)}
.filters{margin:0 1.25rem 1rem;border:1px solid var(--line);border-radius:.875rem;background:var(--well)}
.filters>summary{display:flex;align-items:center;gap:.5rem;min-height:2.75rem;padding:.5rem 1rem;font-weight:600;
cursor:pointer;border-radius:.875rem}
.filters>summary::after{content:"";margin-left:auto;width:.5rem;height:.5rem;border:solid currentColor;
border-width:0 2px 2px 0;transform:rotate(45deg) translateY(-2px);transition:transform .16s}
.filters[open]>summary::after{transform:rotate(225deg) translateY(-2px)}
.filters form{display:grid;grid-template-columns:repeat(auto-fill,minmax(11rem,1fr));gap:.75rem 1rem;
padding:.25rem 1rem 1rem}
.field{margin:0}
.field.wide,.go{grid-column:1/-1}
.go{display:flex;flex-wrap:wrap;gap:.625rem;margin:0}
.go button,.go a.button{width:auto;min-width:7.5rem;padding:.625rem 1.25rem}
.toolbar{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:.5rem 1rem;
padding:.5rem 1.25rem .75rem}
.showing{margin:0;font-size:.875rem;color:var(--muted)}
.showing strong{color:var(--ink)}
.sizes{display:flex;align-items:center;gap:.25rem;margin:0;font-size:.8125rem}
.sizes .quiet{margin-right:.375rem}
.chip{display:inline-grid;place-items:center;min-width:2.25rem;min-height:2rem;padding:0 .5rem;border-radius:999px;
font-weight:600;text-decoration:none;border:1px solid transparent}
a.chip:hover{border-color:var(--line);background:var(--well)}
span.chip{color:var(--accent-ink);background:var(--accent)}
.pager,.recnav{display:flex;flex-wrap:wrap;align-items:center;gap:.375rem .5rem;padding:.625rem 1.25rem;
font-size:.875rem}
.pager{border-top:1px solid var(--line);border-bottom:1px solid var(--line);background:var(--well)}
.pager .at{flex:1;text-align:center;min-width:6rem}
.recnav{padding-top:1rem}
.recnav .back{margin-right:auto}
.recnav .at{padding:0 .25rem}
.sheet>p.small{margin:0 1.25rem 1rem}
.lede .badge{margin:0 .375rem 0 0}
.step{display:inline-flex;align-items:center;gap:.375rem;min-height:2.5rem;padding:0 .75rem;border-radius:.625rem;
font-weight:600;text-decoration:none;border:1px solid var(--line);background:var(--sheet)}
a.step:hover{border-color:var(--accent);box-shadow:0 0 0 3px var(--glow)}
.step.off{color:var(--muted);background:none;border-style:dashed;opacity:.85}
.step.first::before{content:"«";content:"«"/""}.step.prev::before{content:"‹";content:"‹"/""}
.step.next::after{content:"›";content:"›"/""}.step.last::after{content:"»";content:"»"/""}
.step.back::before{content:"←";content:"←"/""}
.step::before,.step::after{font-size:1.125rem;line-height:1}
.intro{margin:0 1.25rem}
.finding .body{padding:.25rem 1rem 1rem}
.finding .body p{margin:.5rem 0}
.finding .body ul{margin:.375rem 0;padding-left:1.25rem}
.finding .body li{margin:.25rem 0}
.finding .body li.sub{margin-left:1.25rem;list-style:circle}
.finding .body li.more-line{list-style:none;color:var(--muted)}
.finding code,.intro code{font:.8125rem MONO;padding:.0625rem .3125rem;
border-radius:.3125rem;background:var(--well);overflow-wrap:anywhere}
pre.code{margin:.5rem 0;padding:.75rem .875rem;border-radius:.625rem;background:var(--well);box-shadow:var(--in);
overflow-x:auto;font:.8125rem/1.5 MONO}
button.link{width:auto;display:inline;padding:.25rem 0;border:0;background:none;color:var(--accent);font-weight:600;
text-decoration:underline;cursor:pointer;min-height:1.5rem}
table{width:100%;border-collapse:collapse;font-size:.875rem}
th,td{text-align:left;vertical-align:top;padding:.5rem .75rem;border-top:1px solid var(--line)}
th{font-size:.75rem;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);border-top:0}
td:first-child{white-space:nowrap;color:var(--muted)}
@media (max-width:40rem){.row>summary{grid-template-columns:1fr;gap:.375rem}.tags{justify-content:flex-start}
td:first-child{white-space:normal}.pager .first,.pager .last{padding:0 .625rem}
.pager .first .t,.pager .last .t{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}
.pager .at{order:-1;flex-basis:100%}.pager .next{margin-left:auto}
.recnav .prev,.recnav .next{flex:1 1 40%;justify-content:center}}
""".replace("MONO", "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace")

# A quiet refresh of the list (owner: "should be updated every time"), never while a row is open or the reader is
# reading below the top - so nothing jumps under them.
_REFRESH_JS = """
setTimeout(function again() {
  if (document.querySelector("details.row[open]") || window.scrollY > 40 || document.hidden ||
      (document.activeElement && document.activeElement.closest("form"))) {
    setTimeout(again, 15000); return; }
  location.reload();
}, REFRESH_MS);
""".replace("REFRESH_MS", str(REFRESH_S * 1000))


def _shell(title: str, where: str, main: str, *, refresh: bool = False, script: str = "") -> str:
    from .approval_page import _SHELL, _STYLE

    # Every records page names the way to all of them in its header (owner, 2026-10-15: "all the records should be
    # in one place ... that link is missing").
    return (_SHELL.replace('<div class="page">', '<div class="page wide">').replace("{{TITLE}}", _e(title))
            .replace('<span class="where">{{WHERE}}</span>',
                     '<span class="where">{{WHERE}}</span><a class="nav" href="/r">All incidents</a>')
            .replace("{{WHERE}}", _e(where))
            .replace("{{FOOT}}", "Read from WARDEN's signed record. Times in UTC, local time in brackets.")
            .replace("{{STYLE}}", _STYLE + _RECORDS_STYLE).replace("{{JS}}", "")
            .replace("{{SCRIPT}}", (_REFRESH_JS if refresh else "") + script).replace("{{SLACK}}", "0")
            .replace("{{MAIN}}", main))  # the content last: no placeholder is looked for inside it
