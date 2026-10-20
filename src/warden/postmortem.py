"""A postmortem draft from an incident's signed record (item 16b), for the records page.

A draft, and it says so in its first line: WARDEN writes it from its own record - the alarm, the steps and their
times, the diagnosis as the rules checked it, the fix, the checks after it and how the run ended - and a person
reviews it, corrects it and completes it. Nothing in it is new: every sentence restates a row of the record, so a
reader can check each one against the steps below it on the same page.

The report rules hold here too:
- the root cause is the one cause WARDEN's diagnosis named, said to be WARDEN's and not yet confirmed - or "not
  established" with the reason; never a list of guesses;
- plain words, times in UTC with the display zone beside them;
- an alarm that cleared while its environment was declared down is said to be the planned shutdown it was, with
  nothing for anyone to do;
- next steps per team, from the outcome and from what the record names (the resource's kind, a deploy, a security
  finding).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .bounds import APPLIED  # written only after the platform applied the fix, unlike its intent
from .environments import both_times

END_ROW = "workflow.end"  # the row a fix run ends with
DRAFT = ("DRAFT - written by WARDEN from its signed record of this incident. A person reviews, corrects and completes "
         "it; until then it is not a postmortem.")
# The steps a timeline keeps, in a person's words; every other row stays in "Every step on the record".
TIMELINE = {
    "intake.decision": "The alarm came in", "incident.diagnose": "WARDEN named a likely cause",
    "incident.verify": "WARDEN's rules checked the diagnosis", "remediation.plan": "A fix plan was made",
    "approval.accepted": "The fix was approved", APPLIED: "WARDEN applied the fix",
    "remediation.rollback": "WARDEN undid the fix", END_ROW: "The fix run ended",
    "incident.after_hold": "Looked at again after the planned shutdown", "incident.no_plan": "No fix plan was made",
}
OUTCOME = {
    "recovered": "the fix worked and held through its re-checks", "verified": "the fix worked",
    "relapsed": "the fix worked, then the problem came back", "rolled_back": "the fix did not work and was undone",
    "not_recovered": "the fix did not work", "rollback_failed": "the fix did not work, and undoing it failed",
    "apply_failed": "applying the fix failed part-way", "refused_at_apply": "the fix was not applied",
    "drifted": "the system changed after the plan was made, so the fix was not applied",
    "denied": "an approver denied the fix", "expired": "nobody approved the fix in time; nothing changed",
    "side_effects": "the fix worked, but other alarms started after it",
}
_SECURITY = {"guardduty": "GuardDuty", "securityhub": "Security Hub"}
_DATA = ("rds", "aurora", "db_", "database", "dynamodb", "elasticache", "docdb", "redis")
_FIXED = ("recovered", "verified")


@dataclass
class Draft:
    title: str
    sections: list[tuple[str, list[str]]] = field(default_factory=list)


def _alert(r: Any) -> dict[str, Any]:
    rows = [e["body"].get("alert") or {} for e in r.rows if e["kind"] == "incident.alert"]
    return rows[-1] if rows else {}


def _end(r: Any) -> str:
    ends = [str(e["body"].get("status") or "") for e in r.rows if e["kind"] == END_ROW]
    return ends[-1] if ends else ""


def _planned(r: Any) -> bool:
    return any(e["kind"] == "incident.after_hold" and e["body"].get("firing") is False for e in r.rows)


def _who(r: Any, approver: str) -> str:
    """An approver by their name - never the list's id for them."""
    name = r.shown(approver) if r.shown else ""
    return name if name and name != approver else "an approver"


def _timeline(r: Any) -> list[str]:
    out = []
    for e in r.rows:
        said = TIMELINE.get(e["kind"])
        if said is None:
            continue
        b = e["body"]
        if e["kind"] == END_ROW and b.get("status"):
            said += f": {OUTCOME.get(str(b['status']), str(b['status']).replace('_', ' '))}"
        elif e["kind"] == "approval.accepted":
            said += f" by {_who(r, str(b.get('approver')))}"
        out.append(f"{both_times(e['at'], seconds=False)} - {said}")
    return out


def _root_cause(r: Any) -> list[str]:
    if _planned(r):
        return [("None: the alarm went off during a declared planned shutdown and had cleared when it was looked at "
                 "again.")]
    if r.hypothesis and not r.hypothesis.startswith("No diagnosis") and r.verdict != "rejected":
        return [f"WARDEN's diagnosis, not yet confirmed by a person: {r.hypothesis}",
                "Confirm or correct it from the evidence on this page before this draft is final."]
    if r.verdict == "rejected":  # its words are not shown as the reason either (CodeRabbit, PR 79)
        why = "WARDEN's rules rejected its diagnosis"
    elif r.hypothesis.startswith("No diagnosis: "):
        why = r.hypothesis.removeprefix("No diagnosis: ")
    else:
        why = "WARDEN made no diagnosis"
    return [f"Not established: {why}. A person finds the cause."]


def _done(r: Any) -> list[str]:
    if not r.plan:
        return [f"WARDEN changed nothing. {('No fix plan: ' + r.no_plan) if r.no_plan else 'No fix was proposed.'}"]
    out = [f"Fix plan: {r.plan.get('entry')} on {r.plan.get('target')} (risk {r.plan.get('tier')})."]
    out += [f"{d['what']} by {d['who']} at {both_times(d['at'], seconds=False)}"
            + (f" - their note: {d['note']}" if d.get("note") else "") for d in r.decisions]
    end = _end(r)
    out.append(f"Outcome: {OUTCOME.get(end, end.replace('_', ' '))}." if end else "Outcome: the fix run has not ended.")
    return out


def _verified(r: Any) -> list[str]:
    checks = [e["body"] for e in r.rows if e["kind"] == "remediation.check"]
    healthy = sum(1 for c in checks if c.get("healthy") is True)
    end = _end(r)
    if not checks:
        return ["Nothing: no health check was made after a change." if r.plan else "Nothing was changed, so nothing "
                "needed verifying."]
    out = [f"{len(checks)} health check(s) after the fix, {healthy} healthy."]
    if end == "recovered":
        out.append("WARDEN's own check: healthy readings in a row, then re-checks 15 and 60 minutes later, all "
                   "healthy.")
    elif end not in _FIXED:
        out.append("The checks did not show recovery: the fix is not verified.")
    return out


def _teams(r: Any, alert: dict[str, Any]) -> list[str]:
    if _planned(r):
        return ["Nobody: this was a planned shutdown. Check that the declaration's times were right."]
    end, labels = _end(r), {str(k) for k in (alert.get("labels") or {})}
    via = str((alert.get("labels") or {}).get("via") or "")
    out = []
    if via in _SECURITY:
        out.append(f"Security team: review the finding in {_SECURITY[via]}, decide whether the resource is compromised "
                   "and contain it; WARDEN changes nothing for a security finding.")
    if end in _FIXED:
        out.append("On-call: confirm the alarm stays quiet for the next day.")
    elif r.plan and not end:  # waiting for approval, or being applied and checked (CodeRabbit, PR 79)
        out.append("On-call: the fix run has not ended - wait for its result before changing anything by hand.")
    elif r.plan or r.verdict:
        out.append("On-call: the problem was not fixed by WARDEN - fix it by hand, or decide it needs no fix.")
    team = "DBA / data" if any(k.startswith(_DATA) for k in labels) else "The service's team (Platform / DevOps)"
    out.append(f"{team}: confirm the root cause above and stop it happening again"
               + (f" on {r.service}." if r.service else "."))
    if r.action == "rollback_deploy" or (r.plan.get("entry") == "rollback_deploy"):
        out.append("Developers: the cause points at a deploy - review the change before it ships again.")
    out.append("Whoever reviews this draft: link this record to similar ones (`warden link`), so the next one finds "
               "what worked.")
    return out


def draft(r: Any) -> Draft:
    """The draft from a record built with its steps (records.record, not `light`)."""
    alert = _alert(r)
    when = both_times(r.first, seconds=False) if isinstance(r.first, datetime) else "-"
    where = " / ".join(x for x in (r.environment, r.service) if x) or "-"
    happened = [f"{r.alarm or r.id} went off on {where} (severity {r.severity or 'not given'}), first seen {when}.",
                f"Status now: {r.status}."]
    if _planned(r):
        happened.append("It was a planned shutdown: the environment was declared down and the alarm had cleared.")
    return Draft(title=f"Postmortem draft - {r.alarm or r.id}", sections=[
        ("What happened", happened), ("Timeline", _timeline(r) or ["No steps on the record."]),
        ("Root cause", _root_cause(r)), ("What was done", _done(r)), ("What verified it", _verified(r)),
        ("Next steps, per team", _teams(r, alert))])


def markdown(d: Draft) -> str:
    """The draft as text a person can copy into their own postmortem document."""
    lines = [f"# {d.title}", "", f"_{DRAFT}_"]
    for heading, items in d.sections:
        lines += ["", f"## {heading}", *(f"- {i}" for i in items)]
    return "\n".join(lines)
