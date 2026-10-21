"""An approver extends a waiting fix plan's approval time from the discussion thread (owner update 3, U3-8: "the
discussion thread can extend it").

A plan already waits for its approval as long as its environment says (`approval_wait_hours`: three days unless set,
at most a week, environments.py); the discussion can run longer than a plan made at night. An enrolled approver who
may approve this plan - its risk level, its environment - mentions @WARDEN in the incident's discussion thread with
"extend" (and how many hours, 24 unless said); WARDEN records it in the signed audit and the plan waits that much
longer. Bounded twice: at most EXTEND_MAX_HOURS at a time, and never past CEILING_HOURS from when the plan was made -
the longest wait an environment may set, so one Temporal timer still holds it.

Nothing else changes, and nothing here can make WARDEN act: the plan still needs an approver's passkey, its cooling-off
still holds, and the target is read again before anything is applied (the precheck) - a plan whose target moved while
it waited is refused, whatever the wait. The workflow reads the extension from this record when its own time runs out
(RemediationWorkflow, activities.approval_extension), never from a message: a row the record does not hold extends
nothing.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from . import environments

EXTENDED = "approval.extended"
EXTEND_MAX_HOURS = 24
CEILING_HOURS = environments.MAX_APPROVAL_WAIT_HOURS
_ENDS = ("workflow.end",)


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
            "environment": env, "made": made, "until": max(base, later) if later else base}


def approver_of(policy: Any, user: str, tier: str, environment: str) -> str:
    """The approver this Slack member is on the list as, when their entry may approve a plan of this tier in this
    environment; "" otherwise."""
    for name, a in sorted(getattr(policy, "approvers", {}).items()):
        if (user and a.slack == user and tier in a.tiers
                and (not a.environments or environment in a.environments)):
            return name
    return ""


def request(log: Any, policy: Any, *, incident: str, user: str, hours: int, now: datetime) -> dict[str, Any]:
    """An approver's "extend" for the incident's waiting plan: recorded and how far, or why not (`why`). Refused for
    anyone who may not approve that plan, for no plan waiting, and at the ceiling; `hours` is at most
    EXTEND_MAX_HOURS. Writes the extension row only when it extends."""
    plan = waiting(log, incident)
    if plan is None or plan["until"] <= now:
        return {"why": "no plan waiting"}
    if not 1 <= hours <= EXTEND_MAX_HOURS:
        return {"why": "hours out of range"}
    if not any(getattr(a, "slack", "") == user for a in getattr(policy, "approvers", {}).values()):
        return {"why": "not an approver"}
    name = approver_of(policy, user, plan["tier"], plan["environment"])
    if not name:
        return {"why": "not this plan's approver"}
    top = ceiling(plan["made"])
    until = min(plan["until"] + timedelta(hours=hours), top)
    if until <= plan["until"]:
        return {"why": "at the limit", "workflow_id": plan["workflow_id"], "until": plan["until"].isoformat()}
    log.append(incident, EXTENDED, {"workflow_id": plan["workflow_id"], "plan_hash": plan["plan_hash"],
                                    "approver": name, "hours": hours, "from": plan["until"].isoformat(),
                                    "until": until.isoformat(), "ceiling": top.isoformat()})
    return {"workflow_id": plan["workflow_id"], "from": plan["until"].isoformat(), "until": until.isoformat(),
            "hours": _hours(until - plan["until"]), "capped": until == top}


def _hours(span: timedelta) -> int | float:
    """A span in hours as a person reads it: 12, or 3.5 when the ceiling cut it."""
    h = round(span.total_seconds() / 3600, 1)
    return int(h) if h.is_integer() else h
