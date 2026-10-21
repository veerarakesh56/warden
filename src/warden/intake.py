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
  reopen              WARDEN's fix of this alarm's incident, or of a resource it names, was verified and is still in
                      its soak (item 11, owner 2026-10-16): the fix did not hold. The SAME incident is opened again -
                      its record carries the whole story - the fix is marked as not holding, and that fix is not
                      offered again for the target without a person (history.did_not_hold)
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

Action = Literal["ignore", "signal_remediation", "signal_incident", "expected", "escalate_only", "reopen", "start"]
# The actions that run an incident: what a later alarm of the same fingerprint joins while it runs.
RUNS = ("start", "escalate_only", "reopen")
# A watched fix whose last word was late - a worker restarting at the soak's end - is still in its soak this long.
SOAK_GRACE = timedelta(minutes=5)
MAX_SOAK = timedelta(days=1)  # FixRequest.soak_minutes' bound (activities.MAX_SOAK_MINUTES)


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
    # A reopened incident's reason to go to a person on the rules alone (flapping, a storm, AWS's own fault): carried
    # into its run as an escalate-only one is (CodeRabbit, PR 43).
    escalate: str = ""


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


def held_fix(ev: AlarmEvent, log: AuditLog, now: datetime) -> dict[str, Any] | None:
    """The newest fix that was verified and is still in its soak - its run has a passing result and no end yet, and
    the result is no older than the plan's soak - for this alarm's own incident (the fingerprint its id starts with)
    or a resource the alarm names, in its environment. None: no fix of this is being soaked.

    Driven from the passing results, which are recent: a result older than the longest soak is past any soak. Each
    one's plan row is read from its incident's record with no time limit (CodeRabbit, PR 43): it is written before
    the approval wait, up to a week before the fix is verified."""
    from . import bounds
    from .resolver import named_resources

    fp, names = fingerprint(ev), named_resources(ev.alert)
    since = now - MAX_SOAK - SOAK_GRACE
    ended = {(e["body"].get("workflow_id"), e["body"].get("run_id", "")) for e in log.entries(
        kinds=("workflow.end",), since=since)}
    verified: dict[tuple[str, str], tuple[datetime, str]] = {}
    for e in log.entries(kinds=(bounds.RESULT,), since=since):
        key = (e["body"].get("workflow_id"), e["body"].get("run_id", ""))
        if e["body"].get("ok") is True and key not in verified:
            verified[key] = (e["at"], str(e["correlation_id"]))
    for key, (at, incident) in sorted(verified.items(), key=lambda kv: kv[1][0], reverse=True):
        b = None if key in ended else _plan_row(log, incident, key)
        if b and _in_soak(ev, b, incident, at, now, fp, names):
            return {"incident": incident, "workflow_id": str(b.get("workflow_id")), "run_id": str(b.get("run_id", "")),
                    "entry": str(b.get("entry", "")), "target": str(b.get("target", "")),
                    "verified_at": at.isoformat()}
    return None


def _plan_row(log: AuditLog, incident: str, key: tuple[str, str]) -> dict[str, Any] | None:
    """The plan row of run `key` on its incident's record, however old."""
    return next((p["body"] for p in reversed(log.entries(incident, kinds=("remediation.plan",)))
                 if (p["body"].get("workflow_id"), p["body"].get("run_id", "")) == key), None)


def _in_soak(ev: AlarmEvent, plan: dict[str, Any], incident: str, verified_at: datetime, now: datetime, fp: str,
             names: set[str]) -> bool:
    """Whether this alarm speaks of the fix `plan` - its incident's own, or on a resource it names, in its
    environment - and came inside its soak: after the fix passed its checks (an alarm from before says nothing of
    whether it held, PR 43), and no later than the soak's end."""
    if plan.get("environment") != ev.alert.environment:
        return False
    if not (incident.startswith(f"{fp}-") or plan.get("service") in names):
        return False
    soak = timedelta(minutes=int(plan.get("soak_minutes") or 60)) + SOAK_GRACE
    return ev.transitioned_at >= verified_at and now - verified_at <= soak


def decide(ev: AlarmEvent, *, recent: list[dict[str, Any]], open_incidents: dict[str, str],
           verifying: dict[tuple[str, str], str], open_count: int,
           expected: tuple[str, datetime | None] | None = None,
           related: dict[str, tuple[str, set[str]]] | None = None, held: dict[str, Any] | None = None) -> Decision:
    """`recent`: this fingerprint's earlier transitions inside FLAP_WINDOW. `open_incidents`: fingerprint -> running
    incident id. `verifying`: (environment, service) -> remediation id in its verify window. `expected`: the
    declaration that covers this alarm now and when its cover ends (expected.covering). `related`: incident id ->
    (environment, resources) of each running incident started inside GROUP_WINDOW. `held`: the verified fix in its
    soak that this alarm says did not hold (held_fix)."""
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
    grouped = _grouped(ev, related, fp) if ev.source == "alarm" and related else None
    if grouped is not None:
        return grouped
    if expected and ev.source == "alarm":  # a person who asks for a diagnosis (MCP, CLI) gets one
        return _expected_down(ev, expected, fp)
    wid = f"inc-{fp}-{ev.transitioned_at:%Y%m%dT%H%M%SZ}"
    escalate = _escalation(ev, len(recent) + 1, open_count)
    if held and ev.source == "alarm":
        return Decision(action="reopen", workflow_id=f"inc-{held['incident']}", fingerprint=fp, escalate=escalate,
                        reason=(f"WARDEN's fix `{held['entry']}` of incident {held['incident']} was verified at "
                                f"{held['verified_at'][:16]}Z and its alarm came back inside the soak: the fix did not "
                                "hold, and the incident is reopened"))
    if escalate:
        return Decision(action="escalate_only", workflow_id=wid, fingerprint=fp, reason=escalate)
    return Decision(action="start", workflow_id=wid, fingerprint=fp, reason="a new alarm")


def _grouped(ev: AlarmEvent, related: dict[str, tuple[str, set[str]]], fp: str) -> Decision | None:
    """The running incident this alarm is the same fault as: one in its environment that names a resource it names.
    None: no such incident."""
    from .resolver import named_resources

    names = named_resources(ev.alert)
    for wid, (env, resources) in related.items():
        same = sorted(names & resources)
        if env == ev.alert.environment and same:
            return Decision(action="signal_incident", workflow_id=wid, fingerprint=fp, grouped=True,
                            reason=f"names {same[0]}, as open incident {wid} does: the same fault")
    return None


def _expected_down(ev: AlarmEvent, expected: tuple[str, datetime | None], fp: str) -> Decision:
    """An alarm covered by an expected-down declaration: held, to be looked at again when the cover ends."""
    name, until = expected[0], expected[1] and expected[1].astimezone(UTC)
    if ev.stateless:  # no state to look at again when the cover ends: the service says so again if it is so
        return Decision(action="expected", fingerprint=fp,
                        reason=f"expected down ({name!r}): a service's event, not an alarm - not looked at again")
    # One held incident per alarm and cover: its id is the cover's end, so a repeat inside it starts no second.
    return Decision(action="expected", workflow_id=f"inc-{fp}-{until:%Y%m%dT%H%M%SZ}" if until else "",
                    fingerprint=fp, reason=f"expected down ({name!r})" + (
                        f" until {until:%Y-%m-%d %H:%M} UTC: looked at again then" if until
                        else ": nothing ends that declaration, so nothing is looked at again"))


def _escalation(ev: AlarmEvent, flips: int, open_count: int) -> str:
    """Why this alarm goes to a person on the rules alone - AWS's own fault, flapping (C21), a storm (C2) - or ""."""
    if ev.escalate:
        return ev.escalate
    if flips >= FLAP_FLIPS:
        return f"the alarm is flapping: {flips} changes in {FLAP_WINDOW.seconds // 60} min"
    if open_count >= MAX_OPEN:
        return f"{open_count} incidents are open, the cap is {MAX_OPEN}: an alarm storm"
    return ""


def reopen_pending(ev: AlarmEvent, log: AuditLog, now: datetime) -> dict[str, Any] | None:
    """The reopen this same transition already decided and recorded, when its incident never started - a start that
    failed, retried by EventBridge after the fix's run had ended (CodeRabbit, PR 43): the intent outlives the soak."""
    fp, at = fingerprint(ev), ev.transitioned_at.isoformat()
    started = {(e["correlation_id"], e["body"].get("at")) for e in log.entries(kinds=(REOPEN_STARTED,),
                                                                              since=now - LOOKBACK)}
    for e in reversed(log.entries(kinds=(REOPENED,), since=now - LOOKBACK)):
        b = e["body"]
        if b.get("fingerprint") == fp and b.get("at") == at and (e["correlation_id"], at) not in started:
            return b.get("held") or None
    return None


REOPENED, REOPEN_STARTED = "incident.reopened", "intake.reopen_started"


def _did_not_hold(log: AuditLog, incident: str, held: dict[str, Any], at: str, rule: str) -> None:
    """The fix `held` did not hold, on `incident`'s record for this transition `at` - once, however often the
    transition is delivered."""
    from .history import DID_NOT_HOLD

    if not any(e["body"].get("workflow_id") == held["workflow_id"] and e["body"].get("at") == at
               for e in log.entries(incident, kinds=(DID_NOT_HOLD,))):
        log.append(incident, DID_NOT_HOLD, {**held, "at": at, "rule": rule})


async def _relapse(client: Any, log: AuditLog, fix: str, fp: str, at: str) -> None:
    """A watched fix whose alarm came back is told: it ends `relapsed` (C18a)."""
    from .workflows import RemediationWorkflow

    log.append(fix, "intake.relapse", {"workflow_id": fix, "fingerprint": fp, "at": at})
    with contextlib.suppress(Exception):  # recorded above; a run that ended meanwhile cannot be told
        await client.get_workflow_handle(fix).signal(RemediationWorkflow.alarm, at)


async def submit(client: Any, ev: AlarmEvent, log: AuditLog, *, task_queue: str | None = None) -> Decision:
    """Gather the state, decide, record the decision, carry it out."""
    from . import expected, runtime

    queue = task_queue or runtime.TASK_QUEUE
    now = datetime.now(UTC)
    fp = fingerprint(ev)
    recent = [e["body"] for e in log.entries(f"intake-{fp}", kinds=("intake.event",), since=now - FLAP_WINDOW)]
    log.append(f"intake-{fp}", "intake.event", {"fingerprint": fp, "state": ev.state, "rule": ev.rule,
                                               "at": ev.transitioned_at.isoformat()})
    open_incidents, related, open_count, seen = await _open_runs(client, log, now)
    verifying, watching = await _fixes_in_check(client, log, now, seen)
    pending = reopen_pending(ev, log, now) if ev.source == "alarm" else None
    held = pending or held_fix(ev, log, now)
    d = decide(ev, recent=recent, open_incidents=open_incidents, verifying=verifying, open_count=open_count,
               expected=expected.covering(ev.alert, now), related=related, held=held)
    if d.action in RUNS:
        d = _scoped(d, ev, verifying, watching)
    log.append(d.workflow_id or f"intake-{fp}", "intake.decision", d.model_dump())
    if d.grouped:
        _record_grouped(log, d, ev)
    at = ev.transitioned_at.isoformat()
    relapsed = open_fix(ev, watching) if d.action in RUNS else None
    if d.action == "reopen" and held:
        relapsed = relapsed or held["workflow_id"]
        _mark_reopened(log, d, held, pending=pending, at=at, rule=ev.rule[:200], fp=fp)
    if relapsed and d.action != "reopen":
        await _relapse(client, log, relapsed, fp, at)
    await _carry_out(client, log, d, ev, at=at, now=now, queue=queue, relapsed=relapsed, fp=fp)
    return d


async def _running(client: Any, wid: str) -> bool:
    """Whether Temporal says the workflow `wid` is running."""
    from temporalio.client import WorkflowExecutionStatus

    try:
        return (await client.get_workflow_handle(wid).describe()).status == WorkflowExecutionStatus.RUNNING
    except Exception:  # noqa: BLE001 - an id Temporal does not know is not running
        return False


async def _stage_of(client: Any, wid: str) -> str:
    """The stage the remediation `wid` says it is in."""
    from .workflows import RemediationWorkflow

    try:
        return str(await client.get_workflow_handle(wid).query(RemediationWorkflow.stage))
    except Exception:  # noqa: BLE001 - a remediation that cannot be asked is not verifying
        return ""


async def _open_runs(client: Any, log: AuditLog, now: datetime) -> tuple[
        dict[str, str], dict[str, tuple[str, set[str]]], int, set[str]]:
    """From the record of decisions in LOOKBACK, the runs still running: fingerprint -> its incident, the ones started
    inside GROUP_WINDOW with the resources they name, how many, and every run id looked at."""
    open_incidents: dict[str, str] = {}
    related: dict[str, tuple[str, set[str]]] = {}
    open_count = 0
    seen: set[str] = set()
    for e in reversed(log.entries(kinds=("intake.decision",), since=now - LOOKBACK)):
        b = e["body"]
        if b.get("action") not in RUNS or b["workflow_id"] in seen:
            continue
        seen.add(b["workflow_id"])
        if not await _running(client, b["workflow_id"]):
            continue
        open_count += 1
        open_incidents.setdefault(b["fingerprint"], b["workflow_id"])
        if b.get("resources") and e["at"] >= now - GROUP_WINDOW:
            related[b["workflow_id"]] = (str(b.get("environment") or ""), set(b["resources"]))
    return open_incidents, related, open_count, seen


async def _fixes_in_check(client: Any, log: AuditLog, now: datetime,
                          seen: set[str]) -> tuple[dict[tuple[str, str], str], dict[tuple[str, str], str]]:
    """A fix being verified takes the alarm instead of a new incident (C1). One that was verified and is being watched
    is told too - it relapsed - and the alarm still starts its incident: a relapse is diagnosed afresh. Both by
    (environment, service), the latest plan of each."""
    verifying: dict[tuple[str, str], str] = {}
    watching: dict[tuple[str, str], str] = {}
    for e in reversed(log.entries(kinds=("remediation.plan",), since=now - LOOKBACK)):
        b = e["body"]
        key = (b.get("environment", ""), b.get("service", ""))
        if key in verifying or key in watching or b["workflow_id"] in seen:
            continue
        seen.add(b["workflow_id"])
        stage = await _stage_of(client, b["workflow_id"])
        if stage == "verifying":
            verifying[key] = b["workflow_id"]
        elif stage == "watching":
            watching[key] = b["workflow_id"]
    return verifying, watching


def _scoped(d: Decision, ev: AlarmEvent, verifying: dict[tuple[str, str], str],
            watching: dict[tuple[str, str], str]) -> Decision:
    """A decision that runs an incident, with its environment, the resources it names, and WARDEN's fixes in that
    environment being checked that it may be a side effect of."""
    from .resolver import named_resources

    names = named_resources(ev.alert)
    # A security finding is an incident of its own (item 15): no later alarm groups into it by the resources it
    # names, and no fix of WARDEN's is told of it as a side effect.
    security = ev.source == "security"
    others = [] if security else sorted({w for (env, service), w in {**verifying, **watching}.items()
                                         if env == ev.alert.environment and service not in names})
    return d.model_copy(update={"environment": ev.alert.environment, "resources": [] if security else sorted(names),
                                "after_fix": others})


def _record_grouped(log: AuditLog, d: Decision, ev: AlarmEvent) -> None:
    """On the incident's own record: which other alarm said the same, and where it came from (records.py)."""
    log.append(d.workflow_id.removeprefix("inc-"), "intake.grouped", {
        "rule": ev.rule[:200], "name": ev.alert.name[:200], "via": ev.alert.labels.get("via", ""),
        "at": ev.transitioned_at.isoformat()})


def _mark_reopened(log: AuditLog, d: Decision, held: dict[str, Any], *, pending: dict[str, Any] | None, at: str,
                   rule: str, fp: str) -> None:
    """On the incident's own record, first, both: the fix it had did not hold, which plan_fix reads before it offers a
    fix (history.did_not_hold) - and it is open again, the intent a retry of this transition honours if the start
    fails (reopen_pending). The marker first, and once, on a retry too: an intent is never on the record without it
    (CodeRabbit, PR 43). The fix's own run is told once the incident has started."""
    incident = d.workflow_id.removeprefix("inc-")
    _did_not_hold(log, incident, held, at, rule)
    if not pending:
        log.append(incident, REOPENED, {"rule": rule, "at": at, "fingerprint": fp,
                                        "workflow_id": held["workflow_id"], "held": held})


async def _carry_out(client: Any, log: AuditLog, d: Decision, ev: AlarmEvent, *, at: str, now: datetime, queue: str,
                     relapsed: str | None, fp: str) -> None:
    """Do what `d` decided: tell a running fix or incident, start an incident, or hold one until its cover ends."""
    from .workflows import IncidentWorkflow, RemediationWorkflow

    if d.action == "signal_remediation":
        await client.get_workflow_handle(d.workflow_id).signal(RemediationWorkflow.alarm, at)
    elif d.action == "signal_incident":
        await client.get_workflow_handle(d.workflow_id).signal(IncidentWorkflow.repeat, at)
    elif d.action in RUNS:
        await _start_incident(client, log, d, ev, at=at, queue=queue, relapsed=relapsed, fp=fp)
    elif d.action == "expected" and d.workflow_id:
        await _start_held(client, d, ev, now=now, queue=queue)


async def _start_incident(client: Any, log: AuditLog, d: Decision, ev: AlarmEvent, *, at: str, queue: str,
                          relapsed: str | None, fp: str) -> None:
    """Start (or reopen) the incident, then tell the fix that relapsed and each fix it may be a side effect of."""
    from temporalio.common import WorkflowIDReusePolicy
    from temporalio.exceptions import WorkflowAlreadyStartedError

    from .workflows import IncidentWorkflow, RemediationWorkflow

    alert = ev.alert.model_copy(update={"alert_id": d.workflow_id.removeprefix("inc-")})
    try:
        # A reopen runs the incident's own workflow id again, after its first run completed: the same record.
        await client.start_workflow(IncidentWorkflow.run, args=[alert, d.reason if d.action == "escalate_only" else
                                                                d.escalate],
                                    id=d.workflow_id, task_queue=queue,
                                    id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE if d.action == "reopen"
                                    else WorkflowIDReusePolicy.ALLOW_DUPLICATE_FAILED_ONLY)
    except WorkflowAlreadyStartedError:
        if d.action == "reopen":  # its run is still going: it is told, as a repeat is
            await client.get_workflow_handle(d.workflow_id).signal(IncidentWorkflow.repeat, at)
        # else the same transition delivered twice: one incident (C20)
    if d.action == "reopen":
        log.append(d.workflow_id.removeprefix("inc-"), REOPEN_STARTED, {"at": at, "workflow_id": d.workflow_id})
        if relapsed:
            await _relapse(client, log, relapsed, fp, at)
    # Each of WARDEN's fixes in the environment that was being checked is told, after the incident started: a
    # fix that ended meanwhile cannot be told, and that holds no alarm back.
    said = f"incident {d.workflow_id.removeprefix('inc-')} started at {at}"  # never the alarm's own words (M2)
    for fix in d.after_fix:
        log.append(fix, "intake.side_effect", {"workflow_id": fix, "incident": d.workflow_id, "rule": ev.rule[:200],
                                               "at": at})
        with contextlib.suppress(Exception):  # recorded above; the run may have just ended
            await client.get_workflow_handle(fix).signal(RemediationWorkflow.side_effect, said)


async def _start_held(client: Any, d: Decision, ev: AlarmEvent, *, now: datetime, queue: str) -> None:
    """Started now, to run when the cover ends: Temporal holds it, so no schedule and no second trigger to fail."""
    from temporalio.common import WorkflowIDReusePolicy
    from temporalio.exceptions import WorkflowAlreadyStartedError

    from .workflows import IncidentWorkflow

    until = datetime.strptime(d.workflow_id.rsplit("-", 1)[1], "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    alert = ev.alert.model_copy(update={"alert_id": d.workflow_id.removeprefix("inc-")})
    try:
        await client.start_workflow(IncidentWorkflow.run, args=[alert, "", d.reason], id=d.workflow_id,
                                    task_queue=queue, start_delay=max(until - now, timedelta(0)),
                                    id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE_FAILED_ONLY)
    except WorkflowAlreadyStartedError:
        pass  # this alarm is already held until then
