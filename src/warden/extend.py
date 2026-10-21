"""An approver extends a waiting fix plan's approval time from the discussion thread.

A plan already waits for its approval as long as its environment says (`approval_wait_hours`: three days unless set,
at most a week, environments.py); the discussion can run longer than a plan made at night. An enrolled approver who
may approve this plan - its risk level, its environment - mentions @WARDEN in the incident's discussion thread with
"extend" (and how many hours: 24 unless said, read strictly - discuss.hours_asked); WARDEN records it in the signed
audit and the plan waits that much longer. Bounded twice: at most EXTEND_MAX_HOURS at a time, and never past
CEILING_HOURS from when the plan was made - the longest wait an environment may set, so one Temporal timer still holds
it.

Nothing else changes, and nothing here can make WARDEN act: the plan still needs an approver's passkey, its cooling-off
still holds, and the target is read again before anything is applied (the precheck) - a plan whose target moved while
it waited is refused, whatever the wait. The workflow reads the extension from this record when its own time runs out
(RemediationWorkflow, activities.approval_extension), never from a message: a row the record does not hold extends
nothing.

Who asks is checked first, so someone who may not extend learns nothing about the plan. A plan whose approvals
already reach its quorum - people's, or Eldane's on its own - waits for nobody and is not extended. An extension
counts from the run's own deadline (WAIT, recorded when its wait began), so it always moves it; and the whole decision
is taken again inside the write's lock.

One message extends at most once: each row names the Slack message that asked (`asked`: its channel
and ts) beside the plan it extended (workflow id and plan hash), written by a check-and-set inside the audit's write
lock (AuditLog.append_unless). A retried activity - the row written, then the reply or the activity's completion lost -
finds its row and gets that first result again; it never adds the hours twice.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from . import environments

EXTENDED = "approval.extended"
# Until when the plan's run really waits, from when its wait began (RemediationWorkflow, patch u38-wait): later than the
# plan's own approval_until by the gate and the critic's time. Extensions count from it, so each one moves the run's
# real deadline.
WAIT = "approval.wait"
EXTEND_MAX_HOURS = 24
CEILING_HOURS = environments.MAX_APPROVAL_WAIT_HOURS
_PLAN = "remediation.plan"
_ACCEPTED = "approval.accepted"
_ENDS = ("workflow.end",)
_TRIES = 3  # check-and-set rounds when another approver's extension lands between the read and the write


def ceiling(made: datetime) -> datetime:
    """The latest a plan made at `made` can ever wait until."""
    return made + timedelta(hours=CEILING_HOURS)


def _when(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def _of(e: dict[str, Any], workflow_id: str, plan_hash: str) -> bool:
    return e["body"].get("workflow_id") == workflow_id and e["body"].get("plan_hash") == plan_hash


def extended_until(log: Any, incident: str, workflow_id: str, plan_hash: str, made: datetime) -> datetime | None:
    """The latest time this exact plan was extended to on the record, bounded by its ceiling; None when it never was.
    A row for another plan - another run's, or a plan made again after its target moved - extends nothing."""
    found = [t for e in log.entries(incident, kinds=(EXTENDED,))
             if _of(e, workflow_id, plan_hash) and (t := _when(e["body"].get("until"))) is not None]
    return min(max(found), ceiling(made)) if found else None


def _base(rows: list[dict[str, Any]], last: dict[str, Any], made: datetime) -> datetime:
    """Until when the plan waits before any extension: its run's own deadline when the run recorded it (WAIT), else
    the plan's approval_until, else - a plan recorded before its row said its wait - its environment's wait."""
    b = last["body"]
    real = [t for e in rows if e["kind"] == WAIT and e["seq"] > last["seq"]
            and _of(e, str(b.get("workflow_id") or ""), str(b.get("plan_hash") or ""))
            and (t := _when(e["body"].get("until"))) is not None]
    if real:
        return max(real)
    said = _when(b.get("approval_until"))
    if said is not None:
        return said
    hours = environments.default_environment_policies().for_env(str(b.get("environment") or "")).approval_wait_hours
    return made + timedelta(hours=hours)


def waiting(log: Any, incident: str) -> dict[str, Any] | None:
    """The incident's newest fix plan, if no end is on the record after it: its workflow, hash, tier, environment,
    when it was made and until when it waits now. None: no plan waits."""
    rows = log.entries(incident, kinds=(_PLAN, WAIT, *_ENDS))
    plans = [e for e in rows if e["kind"] == _PLAN]
    if not plans:
        return None
    last = plans[-1]
    b = last["body"]
    wid = str(b.get("workflow_id") or "")
    if not wid or any(e["kind"] in _ENDS and e["seq"] > last["seq"] and e["body"].get("workflow_id") == wid
                      for e in rows):
        return None
    made = _when(b.get("made")) or last["at"]  # the plan's own created_at: the run's ceiling counts from it
    base = _base(rows, last, made)
    later = extended_until(log, incident, wid, str(b.get("plan_hash") or ""), made)
    return {"workflow_id": wid, "plan_hash": str(b.get("plan_hash") or ""), "tier": str(b.get("tier") or ""),
            "environment": str(b.get("environment") or ""), "made": made,
            "until": max(base, later) if later else base, "seq": last["seq"]}


def _accepted(log: Any, incident: str, plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [e["body"] for e in log.entries(incident, kinds=(_ACCEPTED,))
            if e["seq"] > plan["seq"] and _of(e, plan["workflow_id"], plan["plan_hash"])]


def ai_approved(log: Any, policy: Any, incident: str, plan: dict[str, Any]) -> bool:
    """Eldane, the AI critic, approved this plan on its own (#42): its approval alone met the tier's quorum, as the run
    went by it (RemediationWorkflow._critic: enough with no other approval), so the plan no longer waits for a person
    and its wait is not extended - a person's "no" still stops it until it is applied. An Eldane
    approval that was not enough on its own leaves the plan waiting for a person: that wait may be extended."""
    is_ai = getattr(policy, "is_ai", None)
    need = getattr(policy, "required", {}).get(plan["tier"], 1)
    return bool(is_ai) and any(is_ai(str(b.get("approver"))) and int(b.get("required") or need) <= 1
                               for b in _accepted(log, incident, plan))


def people_approved(log: Any, policy: Any, incident: str, plan: dict[str, Any]) -> bool:
    """The plan's approvals already reach its tier's quorum (different approvers, approvals.enough): it waits for
    nobody now - it is being checked and applied - so there is no wait to extend."""
    rows = _accepted(log, incident, plan)
    need = max((int(b.get("required") or 1) for b in rows),
               default=getattr(policy, "required", {}).get(plan["tier"], 1))
    return bool(rows) and len({str(b.get("approver")) for b in rows}) >= need


def _person(policy: Any, user: str) -> bool:
    """A person on the approver list by this Slack id: never an AI entry, never an empty id."""
    return bool(user) and any(getattr(a, "slack", "") == user and not getattr(a, "ai", False)
                              for a in getattr(policy, "approvers", {}).values())


def approver_of(policy: Any, user: str, tier: str, environment: str) -> str:
    """The approver this Slack member is on the list as, when their entry may approve a plan of this tier in this
    environment; "" otherwise."""
    for name, a in sorted(getattr(policy, "approvers", {}).items()):
        if (user and a.slack == user and tier in a.tiers and not getattr(a, "ai", False)
                and (not a.environments or environment in a.environments)):
            return name
    return ""


def answered(log: Any, incident: str, asked: str) -> dict[str, Any] | None:
    """What the message `asked` already extended, as it was first answered; None when it extended nothing yet."""
    for e in log.entries(incident, kinds=(EXTENDED,)):
        if asked and e["body"].get("asked") == asked:
            return _result(e["body"])
    return None


def _result(body: dict[str, Any]) -> dict[str, Any]:
    until, start = _when(body.get("until")), _when(body.get("from"))
    hours = _hours(until - start) if until and start else body.get("hours", "")
    return {"workflow_id": body.get("workflow_id", ""), "from": body.get("from", ""), "until": body.get("until", ""),
            "hours": hours, "capped": body.get("until") == body.get("ceiling")}


def _refusal(log: Any, policy: Any, incident: str, user: str, hours: int | None, now: datetime, *,
             said_no: bool = False) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """(why not, None) when this person may not extend this incident's wait now, else ({}, the waiting plan). Who
    asks is checked first: someone who may not extend learns nothing about the plan."""
    if not _person(policy, user):
        return {"why": "not an approver"}, None
    plan = waiting(log, incident)
    if plan is None or plan["until"] <= now:
        return {"why": "no plan waiting"}, None
    if not approver_of(policy, user, plan["tier"], plan["environment"]):
        return {"why": "not this plan's approver"}, None
    if ai_approved(log, policy, incident, plan):
        return {"why": "approved by Eldane", "workflow_id": plan["workflow_id"]}, None
    if people_approved(log, policy, incident, plan):
        return {"why": "already approved", "workflow_id": plan["workflow_id"]}, None
    if said_no:  # a "no" beside "extend" (discuss.said_no): unclear, asked again - never extended
        return {"why": "said no"}, None
    if hours is None:
        return {"why": "hours unclear"}, None
    if not 1 <= hours <= EXTEND_MAX_HOURS:
        return {"why": "hours out of range"}, None
    return {}, plan


def _decide(log: Any, policy: Any, incident: str, user: str, hours: int | None, now: datetime, *,
            said_no: bool = False) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """(the answer, the row to write): the row is None when nothing is extended, and the answer says why."""
    why, plan = _refusal(log, policy, incident, user, hours, now, said_no=said_no)
    if plan is None or hours is None:
        return why, None
    top = ceiling(plan["made"])
    until = min(plan["until"] + timedelta(hours=hours), top)
    if until <= plan["until"]:  # it would not move the run's deadline: it already waits as long as a plan can
        return {"why": "at the limit", "workflow_id": plan["workflow_id"], "until": plan["until"].isoformat()}, None
    body = {"workflow_id": plan["workflow_id"], "plan_hash": plan["plan_hash"],
            "approver": approver_of(policy, user, plan["tier"], plan["environment"]), "hours": hours,
            "from": plan["until"].isoformat(), "until": until.isoformat(), "ceiling": top.isoformat()}
    return _result(body), body


def request(log: Any, policy: Any, *, incident: str, user: str, hours: int | None, now: datetime,
            asked: str, said_no: bool = False) -> dict[str, Any]:
    """An approver's "extend" for the incident's waiting plan: recorded and how far, or why not (`why`). Refused for
    anyone who may not approve that plan, for no plan waiting (or one already approved), for a message that says no
    beside "extend" (`said_no`), for hours not said plainly (None) or out of 1..EXTEND_MAX_HOURS, and at the ceiling.
    Writes the extension row only when it extends, and once per message `asked` (its Slack channel and ts): asked
    again - an activity retried - it answers what it first did and writes nothing. The whole decision is taken again inside the write's lock (_stale)."""
    if not asked:
        return {"why": "no message"}
    wid = ""
    for _ in range(_TRIES):
        if (done := answered(log, incident, asked)) is not None:
            return done
        got, body = _decide(log, policy, incident, user, hours, now, said_no=said_no)
        if body is None:
            return got
        wid, body["asked"] = body["workflow_id"], asked
        _, why = log.append_unless(incident, EXTENDED, body,
                                   lambda b=body: _stale(log, policy, incident, user, hours, now, b))
        if not why:
            return got
    return {"why": "busy", "workflow_id": wid}


def _stale(log: Any, policy: Any, incident: str, user: str, hours: int | None, now: datetime,
           body: dict[str, Any]) -> str:
    """Read inside the write's lock: "moved" unless the same decision, taken again now, gives exactly `body` - an
    extension landed in between (another approver's, or this same message's from an attempt running beside this one),
    the plan was approved, by Eldane or by people, it ended, or the list changed. request() then reads again, and finds
    that message's row if it was this one. "" when it still holds (every check, not only the time)."""
    _, again = _decide(log, policy, incident, user, hours, now)
    return "" if again is not None and {**again, "asked": body.get("asked")} == body else "moved"


def _hours(span: timedelta) -> int | float:
    """A span in hours as a person reads it: 12, or 3.5 when the ceiling cut it."""
    h = round(span.total_seconds() / 3600, 1)
    return int(h) if h.is_integer() else h
