"""The one door alarms come in by (registers C1, C2, C20, C21).

An alarm is not an incident. `decide` turns one alarm event into one of:

  ignore              the state is not ALARM: an OK or INSUFFICIENT_DATA transition is counted, never acted on (C20)
  signal_remediation  the alarm is on a service whose remediation is in its verify window: WARDEN's own fix is not
                      working, so it is told - no new incident that would act on it again (C1, the feedback loop)
  signal_incident     the same alarm (fingerprint) has an incident open: it is told, no second one starts (C2)
  escalate_only       the alarm flapped N times in M minutes (C21), or too many incidents are open (C2): a person
                      gets it, on the rules alone, and no model is asked to propose a change
  expected            a person declared this environment, service or resource down or not in use at this time
                      (expected.py): no incident now. When the cover ends the alarm is looked at again and, still
                      firing, is an incident then - a shutdown that did not come back is not missed
  start               a new incident, whose id is the fingerprint plus the transition time (C20): the same transition
                      twice is one incident, and the next real one after an OK is a new one

`submit` gathers what `decide` needs from the audit and from Temporal, records the decision and carries it out. A
fix that was verified and is still being watched is also told when its resource's alarm fires again: it ends
`relapsed` at once, and the alarm starts its own incident.
The fingerprint includes the source, so a caller of the MCP server cannot occupy the id space of real alarms.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from .audit import AuditLog
from .models import Alert

FLAP_FLIPS = int(os.environ.get("WARDEN_FLAP_FLIPS", "4"))
FLAP_WINDOW = timedelta(minutes=int(os.environ.get("WARDEN_FLAP_MINUTES", "30")))
MAX_OPEN = int(os.environ.get("WARDEN_MAX_OPEN_INCIDENTS", "10"))
LOOKBACK = timedelta(days=1)  # how far back open incidents and remediations are looked for

Action = Literal["ignore", "signal_remediation", "signal_incident", "expected", "escalate_only", "start"]


class AlarmEvent(BaseModel):
    # "security": a GuardDuty or Security Hub finding (security_findings.py) - always escalate-only, below.
    source: Literal["alarm", "mcp", "cli", "security"] = "alarm"
    rule: str  # the alarm or alert rule's name
    state: Literal["ALARM", "OK", "INSUFFICIENT_DATA"]
    transitioned_at: datetime
    alert: Alert
    # A service's own event (lambdas.service_event), not an alarm: nothing later says it cleared.
    stateless: bool = False
    # Why this goes to a person on the rules alone, whatever the model would propose (lambdas.health_event: an AWS-side
    # fault no change of WARDEN's can mend). Empty: decided as any alarm is.
    escalate: str = Field(default="", max_length=300)

    @field_validator("transitioned_at")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("transitioned_at needs a time zone")
        return v.astimezone(UTC)

    @model_validator(mode="after")
    def _security_goes_to_a_person(self) -> AlarmEvent:
        """A security finding never reaches a fix: no catalogue entry contains a compromise (item 15)."""
        if self.source == "security" and not self.escalate.strip():
            raise ValueError("a security finding needs its reason to go to a person: it is escalate-only")
        return self


# Alarms from different rules or tools on the same resource, within this long of an open incident's start, are that
# incident (fs-22, 2026-10-15: one broken config became three incidents - two Datadog monitors and a CloudWatch alarm).
GROUP_WINDOW = timedelta(minutes=int(os.environ.get("WARDEN_GROUP_WINDOW_MIN", "15")))


class Decision(BaseModel):
    action: Action
    workflow_id: str = ""
    fingerprint: str
    reason: str
    # An alarm that joined an open incident on the same resource (GROUP_WINDOW), not the same alarm repeating.
    grouped: bool = False
    # What a started incident names, for grouping a later alarm into it: its environment and its resources.
    environment: str = ""
    resources: list[str] = Field(default_factory=list)
    # WARDEN's own fixes in this alarm's environment, on other resources, being verified or watched when it started:
    # told of it (RemediationWorkflow.side_effect). The incident is started as any other - connected or not is for
    # its diagnosis to say (owner, 2026-10-15).
    after_fix: list[str] = Field(default_factory=list)


def fingerprint(ev: AlarmEvent) -> str:
    a = ev.alert
    material = [ev.source, ev.rule, a.environment, a.service, sorted(a.labels.items())]
    return hashlib.sha256(json.dumps(material).encode()).hexdigest()[:16]


def open_fix(ev: AlarmEvent, fixes: dict[tuple[str, str], str]) -> str | None:
    """The open remediation, if any, of a resource this alarm names. By what the alarm's labels name, not only its
    `service`: an alarm on a schedule's invocations has the ALARM's name for a service and the RULE's in its labels,
    and the fix was filed under the rule - so the alarm never reached its own fix (live, 2026-10-12). The labels that
    only qualify a resource (a namespace, a cluster, the alarm's own name) name none."""
    from .resolver import named_resources

    if ev.source == "security":  # a security finding says nothing of whether a fix of WARDEN's worked (item 15)
        return None
    names = named_resources(ev.alert)
    return next((wid for (env, service), wid in fixes.items() if env == ev.alert.environment and service in names),
                None)


def decide(ev: AlarmEvent, *, recent: list[dict[str, Any]], open_incidents: dict[str, str],
           verifying: dict[tuple[str, str], str], open_count: int,
           expected: tuple[str, datetime | None] | None = None,
           related: dict[str, tuple[str, set[str]]] | None = None) -> Decision:
    """`recent`: this fingerprint's earlier transitions inside FLAP_WINDOW. `open_incidents`: fingerprint -> running
    incident id. `verifying`: (environment, service) -> remediation id in its verify window. `expected`: the
    declaration that covers this alarm now and when its cover ends (expected.covering). `related`: incident id ->
    (environment, resources) of each running incident started inside GROUP_WINDOW."""
    fp = fingerprint(ev)
    if ev.state != "ALARM":
        return Decision(action="ignore", fingerprint=fp, reason=f"state {ev.state}: only ALARM starts an incident")
    fix = open_fix(ev, verifying)
    if fix:
        return Decision(action="signal_remediation", workflow_id=fix, fingerprint=fp,
                        reason=f"{ev.alert.service} is in the verify window of {fix}")
    if fp in open_incidents:
        return Decision(action="signal_incident", workflow_id=open_incidents[fp], fingerprint=fp,
                        reason=f"incident {open_incidents[fp]} is open for this alarm")
    if ev.source == "alarm" and related:
        from .resolver import named_resources

        names = named_resources(ev.alert)
        for wid, (env, resources) in related.items():
            same = sorted(names & resources)
            if env == ev.alert.environment and same:
                return Decision(action="signal_incident", workflow_id=wid, fingerprint=fp, grouped=True,
                                reason=f"names {same[0]}, as open incident {wid} does: the same fault")
    if expected and ev.source == "alarm":  # a person who asks for a diagnosis (MCP, CLI) gets one
        name, until = expected[0], expected[1] and expected[1].astimezone(UTC)
        if ev.stateless:  # no state to look at again when the cover ends: the service says so again if it is so
            return Decision(action="expected", fingerprint=fp,
                            reason=f"expected down ({name!r}): a service's event, not an alarm - not looked at again")
        # One held incident per alarm and cover: its id is the cover's end, so a repeat inside it starts no second.
        return Decision(action="expected", workflow_id=f"inc-{fp}-{until:%Y%m%dT%H%M%SZ}" if until else "",
                        fingerprint=fp, reason=f"expected down ({name!r})" + (
                            f" until {until:%Y-%m-%d %H:%M} UTC: looked at again then" if until
                            else ": nothing ends that declaration, so nothing is looked at again"))
    wid = f"inc-{fp}-{ev.transitioned_at:%Y%m%dT%H%M%SZ}"
    if ev.escalate:
        return Decision(action="escalate_only", workflow_id=wid, fingerprint=fp, reason=ev.escalate)
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

    from . import expected, runtime
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
    related: dict[str, tuple[str, set[str]]] = {}
    open_count = 0
    seen: set[str] = set()
    for e in reversed(log.entries(kinds=("intake.decision",), since=now - LOOKBACK)):
        b = e["body"]
        if b.get("action") in ("start", "escalate_only") and b["workflow_id"] not in seen:
            seen.add(b["workflow_id"])
            if await running(b["workflow_id"]):
                open_count += 1
                open_incidents.setdefault(b["fingerprint"], b["workflow_id"])
                if b.get("resources") and e["at"] >= now - GROUP_WINDOW:
                    related[b["workflow_id"]] = (str(b.get("environment") or ""), set(b["resources"]))
    # A fix being verified takes the alarm instead of a new incident (C1). One that was verified and is being watched
    # is told too - it relapsed - and the alarm still starts its incident: a relapse is diagnosed afresh.
    verifying: dict[tuple[str, str], str] = {}
    watching: dict[tuple[str, str], str] = {}
    for e in reversed(log.entries(kinds=("remediation.plan",), since=now - LOOKBACK)):
        b = e["body"]
        key = (b.get("environment", ""), b.get("service", ""))
        if key in verifying or key in watching or b["workflow_id"] in seen:
            continue
        seen.add(b["workflow_id"])
        stage = await stage_of(b["workflow_id"])
        if stage == "verifying":
            verifying[key] = b["workflow_id"]
        elif stage == "watching":
            watching[key] = b["workflow_id"]

    d = decide(ev, recent=recent, open_incidents=open_incidents, verifying=verifying, open_count=open_count,
               expected=expected.covering(ev.alert, now), related=related)
    if d.action in ("start", "escalate_only"):
        from .resolver import named_resources

        names = named_resources(ev.alert)
        # A security finding is an incident of its own (item 15): no later alarm groups into it by the resources it
        # names, and no fix of WARDEN's is told of it as a side effect.
        security = ev.source == "security"
        others = [] if security else sorted({w for (env, service), w in {**verifying, **watching}.items()
                                             if env == ev.alert.environment and service not in names})
        d = d.model_copy(update={"environment": ev.alert.environment, "resources": [] if security else sorted(names),
                                 "after_fix": others})
    log.append(d.workflow_id or f"intake-{fp}", "intake.decision", d.model_dump())
    if d.grouped:
        # On the incident's own record: which other alarm said the same, and where it came from (records.py).
        log.append(d.workflow_id.removeprefix("inc-"), "intake.grouped", {
            "rule": ev.rule[:200], "name": ev.alert.name[:200], "via": ev.alert.labels.get("via", ""),
            "at": ev.transitioned_at.isoformat()})
    at = ev.transitioned_at.isoformat()
    relapsed = open_fix(ev, watching) if d.action in ("start", "escalate_only") else None
    if relapsed:
        log.append(relapsed, "intake.relapse", {"workflow_id": relapsed, "fingerprint": fp, "at": at})
        await client.get_workflow_handle(relapsed).signal(RemediationWorkflow.alarm, at)
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
        # Each of WARDEN's fixes in the environment that was being checked is told, after the incident started: a
        # fix that ended meanwhile cannot be told, and that holds no alarm back.
        said = f"incident {d.workflow_id.removeprefix('inc-')} started at {at}"  # never the alarm's own words (M2)
        for fix in d.after_fix:
            log.append(fix, "intake.side_effect", {"workflow_id": fix, "incident": d.workflow_id, "rule": ev.rule[:200],
                                                   "at": at})
            with contextlib.suppress(Exception):  # recorded above; the run may have just ended
                await client.get_workflow_handle(fix).signal(RemediationWorkflow.side_effect, said)
    elif d.action == "expected" and d.workflow_id:
        # Started now, to run when the cover ends: Temporal holds it, so no schedule and no second trigger to fail.
        until = datetime.strptime(d.workflow_id.rsplit("-", 1)[1], "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
        alert = ev.alert.model_copy(update={"alert_id": d.workflow_id.removeprefix("inc-")})
        try:
            await client.start_workflow(IncidentWorkflow.run, args=[alert, "", d.reason], id=d.workflow_id,
                                        task_queue=queue, start_delay=max(until - now, timedelta(0)),
                                        id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE_FAILED_ONLY)
        except WorkflowAlreadyStartedError:
            pass  # this alarm is already held until then
    return d
