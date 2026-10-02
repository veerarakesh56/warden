"""The one door alarms come in by (registers C1, C2, C20, C21).

An alarm is not an incident. `decide` turns one alarm event into one of:

  ignore              the state is not ALARM: an OK or INSUFFICIENT_DATA transition is counted, never acted on (C20)
  signal_remediation  the alarm is on a service whose remediation is in its verify window: WARDEN's own fix is not
                      working, so it is told - no new incident that would act on it again (C1, the feedback loop)
  signal_incident     the same alarm (fingerprint) has an incident open: it is told, no second one starts (C2)
  escalate_only       the alarm flapped N times in M minutes (C21), or too many incidents are open (C2): a person
                      gets it, on the rules alone, and no model is asked to propose a change
  start               a new incident, whose id is the fingerprint plus the transition time (C20): the same transition
                      twice is one incident, and the next real one after an OK is a new one

`submit` gathers what `decide` needs from the audit and from Temporal, records the decision and carries it out.
The fingerprint includes the source, so a caller of the MCP server cannot occupy the id space of real alarms.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, field_validator

from .audit import AuditLog
from .models import Alert

FLAP_FLIPS = int(os.environ.get("WARDEN_FLAP_FLIPS", "4"))
FLAP_WINDOW = timedelta(minutes=int(os.environ.get("WARDEN_FLAP_MINUTES", "30")))
MAX_OPEN = int(os.environ.get("WARDEN_MAX_OPEN_INCIDENTS", "10"))
LOOKBACK = timedelta(days=1)  # how far back open incidents and remediations are looked for

Action = Literal["ignore", "signal_remediation", "signal_incident", "escalate_only", "start"]


class AlarmEvent(BaseModel):
    source: Literal["alarm", "mcp", "cli"] = "alarm"
    rule: str  # the alarm or alert rule's name
    state: Literal["ALARM", "OK", "INSUFFICIENT_DATA"]
    transitioned_at: datetime
    alert: Alert

    @field_validator("transitioned_at")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("transitioned_at needs a time zone")
        return v.astimezone(UTC)


class Decision(BaseModel):
    action: Action
    workflow_id: str = ""
    fingerprint: str
    reason: str


def fingerprint(ev: AlarmEvent) -> str:
    a = ev.alert
    material = [ev.source, ev.rule, a.environment, a.service, sorted(a.labels.items())]
    return hashlib.sha256(json.dumps(material).encode()).hexdigest()[:16]


def decide(ev: AlarmEvent, *, recent: list[dict[str, Any]], open_incidents: dict[str, str],
           verifying: dict[tuple[str, str], str], open_count: int) -> Decision:
    """`recent`: this fingerprint's earlier transitions inside FLAP_WINDOW. `open_incidents`: fingerprint -> running
    incident id. `verifying`: (environment, service) -> remediation id in its verify window."""
    fp = fingerprint(ev)
    if ev.state != "ALARM":
        return Decision(action="ignore", fingerprint=fp, reason=f"state {ev.state}: only ALARM starts an incident")
    target = (ev.alert.environment, ev.alert.service)
    if target in verifying:
        return Decision(action="signal_remediation", workflow_id=verifying[target], fingerprint=fp,
                        reason=f"{ev.alert.service} is in the verify window of {verifying[target]}")
    if fp in open_incidents:
        return Decision(action="signal_incident", workflow_id=open_incidents[fp], fingerprint=fp,
                        reason=f"incident {open_incidents[fp]} is open for this alarm")
    wid = f"inc-{fp}-{ev.transitioned_at:%Y%m%dT%H%M%SZ}"
    flips = len(recent) + 1
    if flips >= FLAP_FLIPS:
        return Decision(action="escalate_only", workflow_id=wid, fingerprint=fp,
                        reason=f"the alarm is flapping: {flips} changes in {FLAP_WINDOW.seconds // 60} min")
    if open_count >= MAX_OPEN:
        return Decision(action="escalate_only", workflow_id=wid, fingerprint=fp,
                        reason=f"{open_count} incidents are open, the cap is {MAX_OPEN}: an alarm storm")
    return Decision(action="start", workflow_id=wid, fingerprint=fp, reason="a new alarm")


async def submit(client: Any, ev: AlarmEvent, log: AuditLog, *, task_queue: str | None = None) -> Decision:
    """Gather the state, decide, record the decision, carry it out."""
    from temporalio.client import WorkflowExecutionStatus
    from temporalio.common import WorkflowIDReusePolicy
    from temporalio.exceptions import WorkflowAlreadyStartedError

    from . import runtime
    from .workflows import IncidentWorkflow, RemediationWorkflow

    queue = task_queue or runtime.TASK_QUEUE
    now = datetime.now(UTC)
    fp = fingerprint(ev)
    recent = [e["body"] for e in log.entries(f"intake-{fp}", kinds=("intake.event",), since=now - FLAP_WINDOW)]
    log.append(f"intake-{fp}", "intake.event", {"fingerprint": fp, "state": ev.state, "rule": ev.rule,
                                               "at": ev.transitioned_at.isoformat()})

    async def running(wid: str) -> bool:
        try:
            return (await client.get_workflow_handle(wid).describe()).status == WorkflowExecutionStatus.RUNNING
        except Exception:  # noqa: BLE001 - an id Temporal does not know is not running
            return False

    async def stage_of(wid: str) -> str:
        try:
            return str(await client.get_workflow_handle(wid).query(RemediationWorkflow.stage))
        except Exception:  # noqa: BLE001 - a remediation that cannot be asked is not verifying
            return ""

    open_incidents: dict[str, str] = {}
    open_count = 0
    seen: set[str] = set()
    for e in reversed(log.entries(kinds=("intake.decision",), since=now - LOOKBACK)):
        b = e["body"]
        if b.get("action") in ("start", "escalate_only") and b["workflow_id"] not in seen:
            seen.add(b["workflow_id"])
            if await running(b["workflow_id"]):
                open_count += 1
                open_incidents.setdefault(b["fingerprint"], b["workflow_id"])
    verifying: dict[tuple[str, str], str] = {}
    for e in reversed(log.entries(kinds=("remediation.plan",), since=now - LOOKBACK)):
        b = e["body"]
        key = (b.get("environment", ""), b.get("service", ""))
        if key in verifying or b["workflow_id"] in seen:
            continue
        seen.add(b["workflow_id"])
        if await stage_of(b["workflow_id"]) == "verifying":
            verifying[key] = b["workflow_id"]

    d = decide(ev, recent=recent, open_incidents=open_incidents, verifying=verifying, open_count=open_count)
    log.append(d.workflow_id or f"intake-{fp}", "intake.decision", d.model_dump())
    at = ev.transitioned_at.isoformat()
    if d.action == "signal_remediation":
        await client.get_workflow_handle(d.workflow_id).signal(RemediationWorkflow.alarm, at)
    elif d.action == "signal_incident":
        await client.get_workflow_handle(d.workflow_id).signal(IncidentWorkflow.repeat, at)
    elif d.action in ("start", "escalate_only"):
        alert = ev.alert.model_copy(update={"alert_id": d.workflow_id.removeprefix("inc-")})
        try:
            await client.start_workflow(IncidentWorkflow.run, args=[alert, d.reason if d.action == "escalate_only" else ""],
                                        id=d.workflow_id, task_queue=queue,
                                        id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE_FAILED_ONLY)
        except WorkflowAlreadyStartedError:
            pass  # the same transition delivered twice: one incident (C20)
    return d
