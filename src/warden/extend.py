"""An approver extends a waiting fix plan's approval time from the discussion thread (owner update 3, U3-8: "the
discussion thread can extend it").

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

One message extends at most once (CodeRabbit, PR 150): each row names the Slack message that asked (`asked`: its channel
and ts) beside the plan it extended (workflow id and plan hash), written by a check-and-set inside the audit's write
lock (AuditLog.append_unless). A retried activity - the row written, then the reply or the activity's completion lost -
finds its row and gets that first result again; it never adds the hours twice.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from . import environments

EXTENDED = "approval.extended"
EXTEND_MAX_HOURS = 24
CEILING_HOURS = environments.MAX_APPROVAL_WAIT_HOURS
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


def extended_until(log: Any, incident: str, workflow_id: str, plan_hash: str, made: datetime) -> datetime | None:
    """The latest time this exact plan was extended to on the record, bounded by its ceiling; None when it never was.
    A row for another plan - another run's, or a plan made again after its target moved - extends nothing."""
    found = [t for e in log.entries(incident, kinds=(EXTENDED,))
             if e["body"].get("workflow_id") == workflow_id and e["body"].get("plan_hash") == plan_hash
             and (t := _when(e["body"].get("until"))) is not None]
    return min(max(found), ceiling(made)) if found else None


def waiting(log: Any, incident: str) -> dict[str, Any] | None:
    """The incident's newest fix plan, if no end is on the record after it: its workflow, hash, tier, environment,
    when it was made and until when it waits now. None: no plan waits."""
    rows = log.entries(incident, kinds=("remediation.plan", *_ENDS))
    plans = [e for e in rows if e["kind"] == "remediation.plan"]
    if not plans:
        return None
    last = plans[-1]
    b = last["body"]
    wid = str(b.get("workflow_id") or "")
    if not wid or any(e["kind"] in _ENDS and e["seq"] > last["seq"] and e["body"].get("workflow_id") == wid
                      for e in rows):
        return None
    made = last["at"]
    env = str(b.get("environment") or "")
    base = _when(b.get("approval_until"))
    if base is None:  # a plan recorded before its row said its wait: its environment's
        base = made + timedelta(hours=environments.default_environment_policies().for_env(env)
                                .approval_wait_hours)
    later = extended_until(log, incident, wid, str(b.get("plan_hash") or ""), made)
    return {"workflow_id": wid, "plan_hash": str(b.get("plan_hash") or ""), "tier": str(b.get("tier") or ""),
            "environment": env, "made": made, "until": max(base, later) if later else base, "seq": last["seq"]}


def ai_approved(log: Any, policy: Any, incident: str, plan: dict[str, Any]) -> bool:
    """Eldane, the AI critic, approved this plan (#42): it no longer waits for a person, and its wait is not extended -
    a person's "no" still stops it until it is applied (lane C, U3-8)."""
    is_ai = getattr(policy, "is_ai", None)
    return bool(is_ai) and any(
        e["seq"] > plan["seq"] and e["body"].get("workflow_id") == plan["workflow_id"]
        and e["body"].get("plan_hash") == plan["plan_hash"] and is_ai(str(e["body"].get("approver")))
        for e in log.entries(incident, kinds=("approval.accepted",)))


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


def _decide(log: Any, policy: Any, incident: str, user: str, hours: int,
            now: datetime) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """(the answer, the row to write): the row is None when nothing is extended, and the answer says why."""
    plan = waiting(log, incident)
    if plan is None or plan["until"] <= now:
        return {"why": "no plan waiting"}, None
    if ai_approved(log, policy, incident, plan):
        return {"why": "approved by Eldane", "workflow_id": plan["workflow_id"]}, None
    if not 1 <= hours <= EXTEND_MAX_HOURS:
        return {"why": "hours out of range"}, None
    if not any(getattr(a, "slack", "") == user for a in getattr(policy, "approvers", {}).values()):
        return {"why": "not an approver"}, None
    name = approver_of(policy, user, plan["tier"], plan["environment"])
    if not name:
        return {"why": "not this plan's approver"}, None
    top = ceiling(plan["made"])
    until = min(plan["until"] + timedelta(hours=hours), top)
    if until <= plan["until"]:
        return {"why": "at the limit", "workflow_id": plan["workflow_id"], "until": plan["until"].isoformat()}, None
    body = {"workflow_id": plan["workflow_id"], "plan_hash": plan["plan_hash"], "approver": name, "hours": hours,
            "from": plan["until"].isoformat(), "until": until.isoformat(), "ceiling": top.isoformat()}
    return _result(body), body


def request(log: Any, policy: Any, *, incident: str, user: str, hours: int, now: datetime,
            asked: str) -> dict[str, Any]:
    """An approver's "extend" for the incident's waiting plan: recorded and how far, or why not (`why`). Refused for
    anyone who may not approve that plan, for no plan waiting, and at the ceiling; `hours` is at most
    EXTEND_MAX_HOURS. Writes the extension row only when it extends, and once per message `asked` (its Slack channel
    and ts): asked again - an activity retried - it answers what it first did and writes nothing."""
    if not asked:
        return {"why": "no message"}
    wid = ""
    for _ in range(_TRIES):
        if (done := answered(log, incident, asked)) is not None:
            return done
        got, body = _decide(log, policy, incident, user, hours, now)
        if body is None:
            return got
        wid, body["asked"] = body["workflow_id"], asked
        _, why = log.append_unless(incident, EXTENDED, body, lambda b=body: _stale(log, incident, b))
        if not why:
            return got
    return {"why": "busy", "workflow_id": wid}


def _stale(log: Any, incident: str, body: dict[str, Any]) -> str:
    """Read inside the write's lock: "moved" when the plan or its time is no longer what `body` was worked out from -
    an extension landed in between, another approver's or this same message's from an attempt running beside this
    one; request() then reads again, and finds that message's row if it was this one. "" when it still holds."""
    plan = waiting(log, incident)
    if (plan is None or plan["workflow_id"] != body["workflow_id"] or plan["plan_hash"] != body["plan_hash"]
            or plan["until"].isoformat() != body["from"]):
        return "moved"
    return ""


def _hours(span: timedelta) -> int | float:
    """A span in hours as a person reads it: 12, or 3.5 when the ceiling cut it."""
    h = round(span.total_seconds() / 3600, 1)
    return int(h) if h.is_integer() else h
