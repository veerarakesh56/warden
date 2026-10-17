"""Temporal workflows. Deterministic orchestration only: no I/O, no clock but workflow.now().

RemediationWorkflow carries one catalogue entry from plan to verified result:

    plan (live read, catalogue check)  ->  bounds / kill switch  ->  signed approvals until the TTL
    ->  re-check live state (drift = new plan)  ->  apply ONCE  ->  own success check, on a timer
    ->  roll back if it did not recover  ->  audit the end (signed checkpoint)

The outcome's checklist [planned, policy, approved, prechecked, applied, verified, audited] is filled
by the workflow as each step really happens. There is no input that can mark a fix successful: only
the workflow's own success check can, and the agent has no way to write to it.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime, timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import (
    ActivityError,
    ApplicationError,
    WorkflowAlreadyStartedError,
    is_cancelled_exception,
)
from temporalio.workflow import ParentClosePolicy

with workflow.unsafe.imports_passed_through():
    from .activities import (
        APPLY_REFUSED,
        DiscussActivities,
        FixOutcome,
        FixRequest,
        IncidentActivities,
        Plan,
        Recorded,
        RemediationActivities,
    )
    from .approvals import Denial, PasskeyAssertion, SignedApproval
    from .catalog import MITIGATES
    from .discuss import (
        ELSEWHERE,
        LIMIT,
        NEW_PLAN,
        NO_ANSWER,
        NO_RECORD,
        NOT_APPROVER,
        NOT_READ,
        NOW,
        REPLAN_SOON,
        REPLANNED,
        Thread,
        Turn,
    )
    from .models import Alert, ContextBundle, RunReport, ingestion_wait, reread_wait

STEPS = ("planned", "policy", "approved", "prechecked", "applied", "verified", "audited")
# Bounded (audit A-B-L10): Temporal's default retries an activity forever, so a step that kept failing - an audit
# store that cannot be written, a platform that cannot be read - held the run, and the target, with no end row.
# About ten minutes of tries, then the run ends on the record (FAILED below) and a person looks.
QUICK = {"start_to_close_timeout": timedelta(seconds=60),
         "retry_policy": RetryPolicy(maximum_attempts=10, maximum_interval=timedelta(seconds=60))}
ONCE = {"start_to_close_timeout": timedelta(minutes=5), "retry_policy": RetryPolicy(maximum_attempts=1)}
NOTIFY = {"start_to_close_timeout": timedelta(seconds=60), "retry_policy": RetryPolicy(maximum_attempts=3)}
# prepare reads, redacts and runs the tripwire (bounded by tripwire.MAX_SCAN_TOKENS, about three minutes):
# a few attempts, then the incident FAILS visibly - never an endless retry (second review, 2026-09-30).
# 15 min: a full-budget scan measured ~7 min on a loaded laptop CPU (third review, 2026-09-30).
PREPARE = {"start_to_close_timeout": timedelta(minutes=15), "retry_policy": RetryPolicy(maximum_attempts=3)}
# Eldane's review: two model calls and perhaps a catch trial, once. A critic zone that is not running holds nobody up
# for long: unstarted within two minutes, the plan goes to a person as before.
CRITIC = {"schedule_to_start_timeout": timedelta(minutes=2), "start_to_close_timeout": timedelta(minutes=6),
          "retry_policy": RetryPolicy(maximum_attempts=1)}
# Register S15, the trust zones: each activity runs where its credentials are. The read zone holds the watched
# environments' readers, the llm zone the model, the notify zone the paging, chat and change-record secrets (and so a
# run's end, which resolves its page and records the change), the act zone the actors;
# the rest - the audit's own steps and the workflows - run on the main queue (the core zone). A workflow on the main
# queue sends each zoned activity to its zone's queue; one on any other queue (a test's) keeps them all with it.
MAIN_QUEUE = "warden"
ZONES = {"read": ("prepare", "reread", "investigate", "plan_fix", "resolve_plan", "precheck", "check_success", "after_hold",
                  "discuss_evidence", "discuss_replan"),
         "llm": ("diagnose", "discuss_answer"),
         "notify": ("notify", "announce", "finish", "no_plan", "discuss_thread", "discuss_reply", "summary_owed"),
         "act": ("apply", "rollback"),
         # Eldane, the AI critic (eldane.py): its own model, its own signing key, no other zone's credentials.
         "critic": ("critic_review",)}
_ZONE_OF = {name: zone for zone, names in ZONES.items() for name in names}


def zone_queue(zone: str) -> str:
    return f"{MAIN_QUEUE}-{zone}"


def _zoned(activity: Any) -> dict[str, str]:
    """The task queue an activity runs on, as activity options. Patched: a run begun before the zones keeps every
    activity on the main queue when it replays."""
    zone = _ZONE_OF.get(activity.__name__)
    if zone and workflow.info().task_queue == MAIN_QUEUE and workflow.patched("s15-zones"):
        return {"task_queue": zone_queue(zone)}
    return {}
# G9-B: rounds of "read these related resources, then decide again" after the first diagnosis.
INVESTIGATE_ROUNDS = 2
CHECK_EVERY = timedelta(seconds=30)
# Register C18a, false recovery: a service that died stops reporting errors, and one good reading is not recovery.
# Recovered = this many healthy checks in a row; then re-checked this long after, the run open until the last.
CONSECUTIVE_HEALTHY = 3
RECHECK_AFTER = (timedelta(minutes=15), timedelta(minutes=60))
# Stages that are ends: a failure there is the end row's own (finish), with nothing left to record.
# Decision D7: when the target, or WARDEN itself, changed under an approved plan, the plan is made again from what
# WARDEN reads now and put to the approvers again - never applied unseen. Live, 2026-10-12: a deploy a minute before
# the owner's approval ended the plan "refused at apply", and the fix had to be started again by hand. At most
# REPLAN_MAX times for one fix: a target that keeps changing goes to a person.
REPLAN_MAX = 2
_REPLAN_ON = ("WARDEN's code or catalogue changed after the plan was made", "the target changed after the plan was made")


def _plan_again(req: FixRequest, problems: list[str]) -> list[str]:
    """The line said when the plan is made again - none when it is not: only for a change of the target or of WARDEN
    itself, nothing else wrong, and under the cap. Patched: histories recorded before it end as they did."""
    if (not problems or not all(p.startswith(_REPLAN_ON) for p in problems) or req.replans >= REPLAN_MAX
            or not workflow.patched("g10-replan")):
        return []
    return [(f"WARDEN makes the plan again from what it reads now and asks for an approval once more "
             f"({req.replans + 1} of {REPLAN_MAX})")]


END_STAGES = frozenset({"refused", "blocked", "expired", "drifted", "refused_at_apply", "apply_failed", "recovered",
                        "mitigated",
                        "rollback_failed", "not_recovered", "rolled_back", "cancelled", "cancelled_after_apply",
                        "failed", "failed_after_apply", "relapsed", "denied", "side_effects"})
# The ends a person is told of as they happen (announce "ended"). Not `expired`: the ladder said it. Not a cancelled or
# crashed run: its end row is written on the way out of a failure, where one more step could lose it.
TOLD = END_STAGES - {"expired", "cancelled", "cancelled_after_apply", "failed", "failed_after_apply"}


@workflow.defn
class RemediationWorkflow:
    def __init__(self) -> None:
        self._inbox: list[SignedApproval | PasskeyAssertion | Denial] = []
        self._plan: Plan | None = None
        self._stage = "planning"
        self._applying = False  # set the moment apply is sent: from then on the target's state is not known
        self._alarm_at = ""  # the target's alarm fired during the verify window (register C1)
        self._side_effects: list[str] = []  # other alarms in the environment that started after the fix (intake)

    @workflow.signal
    def approve(self, approval: SignedApproval) -> None:
        self._inbox.append(approval)

    @workflow.signal
    def approve_passkey(self, assertion: PasskeyAssertion) -> None:
        """A passkey approval from the approval page (register H6): re-verified by check_passkey before it counts."""
        self._inbox.append(assertion)

    @workflow.signal
    def deny(self, denial: Denial) -> None:
        """An approver's "no" from the approval page (requirement R28): the plan ends denied, nothing changed."""
        self._inbox.append(denial)

    @workflow.signal
    def alarm(self, at: str) -> None:
        """The target's alarm fired again (register C1, from intake). Inside the verify window that is the fix not
        working: the run stops verifying and rolls back. Before the change it is the incident itself, and ignored."""
        if self._stage in ("verifying", "watching"):
            self._alarm_at = at

    @workflow.signal
    def side_effect(self, what: str) -> None:
        """Another alarm in this fix's environment started while it was verified or watched (owner, 2026-10-15: "fixes
        might break things or cause even bigger other problems"). It may be this fix's doing, or not: its own incident
        diagnoses it with this fix beside its evidence (activities._own_fixes)."""
        if self._stage in ("verifying", "watching") and len(self._side_effects) < 5:
            self._side_effects.append(what[:300])

    @workflow.query
    def stage(self) -> str:
        return self._stage

    @workflow.query
    def plan(self) -> Plan | None:
        return self._plan

    @workflow.run
    async def run(self, req: FixRequest) -> FixOutcome:
        acts = RemediationActivities
        wid = workflow.info().workflow_id
        done = dict.fromkeys(STEPS, False)

        async def end(status: str, reasons: list[str] | None = None) -> FixOutcome:
            self._stage = status
            outcome = FixOutcome(status=status, reasons=reasons or [], checklist=done,
                                 plan_hash=self._plan.plan_hash if self._plan else "")
            await workflow.execute_activity_method(acts.finish, **_zoned(acts.finish), args=[req.incident_id, wid, outcome], **QUICK)
            done["audited"] = True
            # The people who approved the plan are told how it ended (owner's first live approvals, 2026-10-12). After
            # the end row, which the message is read from; a message that fails changes nothing.
            if self._plan is not None and status in TOLD and workflow.patched("g10-outcome"):
                with contextlib.suppress(ActivityError):
                    await workflow.execute_activity_method(acts.announce, **_zoned(acts.announce), args=[self._plan, "ended"], **NOTIFY)
            elif workflow.patched("g10-summary-owed"):
                # An end that tells nobody - failed, cancelled, or before a plan was made: the incident's one message,
                # if nothing has carried its summary yet (activities.summary_owed).
                with contextlib.suppress(ActivityError):
                    await workflow.execute_activity_method(acts.summary_owed, **_zoned(acts.summary_owed),
                                                           args=[req.incident_id, status], **NOTIFY)
            return outcome.model_copy(update={"checklist": dict(done)})

        try:
            return await self._steps(req, acts, wid, done, end)
        except (asyncio.CancelledError, ActivityError) as exc:
            # A cancelled run still ends on the record, signed - and once apply was SENT, nobody knows what state it
            # left: the kill switch goes on (eighth review, 2026-10-01: a run cancelled while verifying left no end
            # row, the switch off). A cancel during an activity arrives as an ActivityError, not a CancelledError,
            # and apply may have acted before it returned (ninth review).
            if isinstance(exc, asyncio.CancelledError) or is_cancelled_exception(exc):
                await end("cancelled_after_apply" if self._applying else "cancelled", ["the run was cancelled"])
            elif self._stage not in END_STAGES:
                # A step that failed every try (audit A-B-L10) ends the run on the record too - after apply, as a
                # change in an unknown state: the kill switch goes on. If the end row itself cannot be written, the
                # run fails visibly.
                await end("failed_after_apply" if self._applying else "failed", [f"a step failed: {exc.cause or exc}"])
            raise

    async def _side_effects_end(self, req: FixRequest, acts, plan: Plan, end) -> FixOutcome | None:
        """The fix passed its own checks, and other alarms started after it: not called fixed, and not undone either -
        they may be unrelated; each alarm's own incident says whether it is connected. What they were is read from the
        record intake wrote (activities.side_effects), never from the signal: a signal the record does not bear out
        is dropped, and the run goes on (success is never an input, and neither is failure)."""
        seen = await workflow.execute_activity_method(acts.side_effects, **_zoned(acts.side_effects), args=[plan],
                                                      **QUICK)
        if not seen:
            self._side_effects = []
            return None
        return await end("side_effects", [f"{req.service} passed its own checks, but after the fix: " + "; ".join(seen)])

    async def _diagnose_again(self, req: FixRequest, acts, why: str) -> list[str]:
        """The incident's alarm as a new incident from now (as an approver's "new plan" makes one): the line said, or
        none when the record holds no alarm or the step fails - the relapse is said either way."""
        try:
            got = await workflow.execute_activity_method(acts.again_alert, **_zoned(acts.again_alert),
                                                         args=[req.incident_id, why], **QUICK)
        except ActivityError:
            return []
        if not got:
            return []
        with contextlib.suppress(WorkflowAlreadyStartedError):
            await workflow.start_child_workflow(IncidentWorkflow.run, Alert.model_validate(got["alert"]),
                                                id=f"inc-{got['new']}", task_queue=workflow.info().task_queue,
                                                parent_close_policy=ParentClosePolicy.ABANDON)
        return [(f"WARDEN diagnoses the incident again from what it reads now, as `{got['new']}`, with this fix "
                 "beside its evidence: any fix it finds is a new plan for an approver")]

    async def _steps(self, req: FixRequest, acts, wid: str, done: dict, end) -> FixOutcome:
        plan = self._plan = await workflow.execute_activity_method(acts.resolve_plan, **_zoned(acts.resolve_plan), args=[req, wid], **QUICK)
        if plan.problems:
            return await end("refused", plan.problems)
        done["planned"] = True

        blocked = await workflow.execute_activity_method(acts.gate, **_zoned(acts.gate), args=[plan, req.service], **QUICK)
        # Only an explicit empty list is "not blocked": an unreadable or forged answer decodes to None,
        # which `if blocked:` read as a pass (third review, 2026-09-30).
        if blocked != []:
            return await end("blocked", blocked or ["the gate's answer could not be read"])
        done["policy"] = True

        accepted: list[SignedApproval] = []
        auto = False
        # Eldane, the AI critic (owner, 2026-10-16), after the gate: it can only add a "no". It reviews the plan in its
        # own zone; where the plan's class has earned autonomy (autonomy.py) its signed approval comes back and is
        # checked like any other approval. Anything else, or no answer in time, and a person decides as before.
        if workflow.patched("eldane-critic"):
            offered = None
            with contextlib.suppress(ActivityError):
                offered = await workflow.execute_activity_method(acts.critic_review, **_zoned(acts.critic_review),
                                                                 args=[plan], **CRITIC)
            if isinstance(offered, SignedApproval):
                result = await workflow.execute_activity_method(acts.check_approval, **_zoned(acts.check_approval),
                                                                args=[plan, offered, []], **QUICK)
                if not result.problems:
                    accepted.append(offered)
                    auto = result.enough

        # Registers H6/R28: the approvers are told as the wait starts - with the approval links when the runtime has an
        # approval domain - not only at the halfway reminder. Sent before the stage reads "awaiting_approval", so
        # whoever sees the plan waiting can already have its links.
        if not auto and workflow.patched("h6-links"):
            with contextlib.suppress(ActivityError):
                await workflow.execute_activity_method(acts.announce, **_zoned(acts.announce), args=[plan, "opening"], **NOTIFY)
        self._stage = "awaiting_approval"
        deadline = workflow.now() + timedelta(minutes=req.approval_ttl_minutes)
        refused: list[str] = []
        seen = 0
        # Register H10: halfway through the wait a person is reminded, and at the end told that nothing was done -
        # an approval request that only expires is one nobody may ever have seen. A failed message changes nothing.
        ladder = workflow.patched("h10-ladder")
        halfway, reminded = workflow.now() + timedelta(minutes=req.approval_ttl_minutes) / 2, False
        while not auto:
            until = halfway if ladder and not reminded and not accepted else deadline
            try:
                await workflow.wait_condition(lambda n=seen: len(self._inbox) > n,
                                              timeout=max(until - workflow.now(), timedelta(0)))
            except TimeoutError:
                if until == halfway and workflow.now() < deadline:
                    reminded = True
                    with contextlib.suppress(ActivityError):
                        await workflow.execute_activity_method(acts.announce, **_zoned(acts.announce), args=[plan, "waiting"], **NOTIFY)
                    continue
                if ladder:
                    with contextlib.suppress(ActivityError):
                        await workflow.execute_activity_method(acts.announce, **_zoned(acts.announce), args=[plan, "expired"], **NOTIFY)
                return await end("expired", refused or ["no valid approval arrived in time"])
            approval, seen = self._inbox[seen], seen + 1
            if isinstance(approval, Denial):
                if approval.workflow_id == wid and approval.plan_hash == plan.plan_hash:
                    return await end("denied", [f"denied by {approval.approver}" +
                                                (f": {approval.reason}" if approval.reason else "")])
                refused.append("a denial for another plan was ignored")
                continue
            if isinstance(approval, PasskeyAssertion):
                result = await workflow.execute_activity_method(acts.check_passkey, **_zoned(acts.check_passkey), args=[plan, approval, accepted],
                                                                **QUICK)
                approval = result.accepted
            else:
                result = await workflow.execute_activity_method(acts.check_approval, **_zoned(acts.check_approval),
                                                                args=[plan, approval, accepted], **QUICK)
            if result.problems or approval is None:
                refused += result.problems
                continue
            accepted.append(approval)
            if result.enough:
                break
        done["approved"] = True
        # Said to everyone the plan was put to: who approved it, read from this run's accepted approvals.
        if workflow.patched("g10-approved-said"):
            with contextlib.suppress(ActivityError):
                await workflow.execute_activity_method(acts.announce, **_zoned(acts.announce), args=[plan, "approved"], **NOTIFY)

        self._stage = "prechecking"
        drift = await workflow.execute_activity_method(acts.precheck, **_zoned(acts.precheck), args=[plan], **QUICK)
        if drift != []:  # as for the gate: only an explicit empty list is clean
            again = _plan_again(req, drift)
            outcome = await end("drifted", (drift or ["the precheck's answer could not be read"]) + again)
            if again:
                workflow.continue_as_new(req.model_copy(update={"replans": req.replans + 1}))
            return outcome
        done["prechecked"] = True

        self._stage = "applying"
        self._applying = True
        try:
            await workflow.execute_activity_method(acts.apply, **_zoned(acts.apply), args=[plan, req.service], **ONCE)
        except ActivityError as exc:
            if is_cancelled_exception(exc):
                raise  # a cancel, not a failed apply: run() ends it, after apply (ninth review)
            if isinstance(exc.cause, ApplicationError) and exc.cause.type == APPLY_REFUSED:
                # Refused before anything was touched: nothing to roll back, nothing half-made.
                again = _plan_again(req, str(exc.cause).removeprefix("apply refused: ").split("; "))
                outcome = await end("refused_at_apply", [str(exc.cause), *again])
                if again:
                    workflow.continue_as_new(req.model_copy(update={"replans": req.replans + 1}))
                return outcome
            # The change may be half-made; the state is unknown, so no automatic rollback - a person.
            return await end("apply_failed", [f"apply failed: {exc.cause or exc}"])
        done["applied"] = True

        self._stage = "verifying"
        until = workflow.now() + timedelta(minutes=req.recover_within_minutes)
        need = CONSECUTIVE_HEALTHY if workflow.patched("c18a-consecutive") else 1
        streak = 0
        while workflow.now() < until and streak < need and not self._alarm_at:
            await workflow.sleep(CHECK_EVERY)
            if self._alarm_at:
                break  # the alarm fired again: not recovered, whatever a check said before it (register C1)
            healthy = await workflow.execute_activity_method(acts.check_success, **_zoned(acts.check_success), args=[plan, req.service], **QUICK)
            streak = streak + 1 if healthy else 0
        recovered = streak >= need and not self._alarm_at
        # The verdict is WARDEN's audit of THIS run's own checks, returned with the run it belongs to: a
        # result replayed from an earlier run of this workflow id carries that run's id and is refused.
        recorded = await workflow.execute_activity_method(acts.record_result, **_zoned(acts.record_result),
                                                          args=[plan, req.service, recovered, need], **QUICK)
        recovered = (isinstance(recorded, Recorded) and recorded.ok is True
                     and recorded.run_id == workflow.info().run_id)
        if recovered:
            done["verified"] = True
            side = workflow.patched("g10-side-effects")
            if side and self._side_effects and (ended := await self._side_effects_end(req, acts, plan, end)):
                return ended
            if workflow.patched("g9-mitigated") and plan.entry in MITIGATES:
                # A pause holds the harm and fixes nothing (review H2): the page stays open, a person resumes it.
                return await end("mitigated", [f"{req.service} is mitigated, not fixed: {MITIGATES[plan.entry]}"])
            if workflow.patched("c18a-rechecks"):
                # Durable re-checks (register C18a): a fix that holds for minutes and fails within the hour is not a
                # recovery. A relapse is recorded as a failed result (the breaker counts it) and goes to a person:
                # WARDEN never reverses its own fix on its own (register C8).
                self._stage = "watching"
                since = workflow.now()
                if workflow.patched("g10-outcome"):
                    with contextlib.suppress(ActivityError):
                        await workflow.execute_activity_method(acts.announce, **_zoned(acts.announce), args=[plan, "verified"], **NOTIFY)
                now_too = workflow.patched("g10-relapse-now")
                for after in RECHECK_AFTER:
                    wait = max(since + after - workflow.now(), timedelta(0))
                    if now_too and wait > timedelta(0):
                        # The alarm firing again ends the watch at once (intake signals it): the people are told of the
                        # relapse then, and the resource is free for the plan its new incident may open (live,
                        # 2026-10-12: the watch slept to its re-check, and the new plan was silently not opened).
                        with contextlib.suppress(TimeoutError):
                            await workflow.wait_condition(lambda: bool(self._alarm_at) or (side and bool(self._side_effects)),
                                                          timeout=wait)
                    else:
                        await workflow.sleep(wait)
                    if side and self._side_effects and not self._alarm_at and (
                            ended := await self._side_effects_end(req, acts, plan, end)):
                        return ended
                    healthy = not self._alarm_at and await workflow.execute_activity_method(
                        acts.check_success, **_zoned(acts.check_success), args=[plan, req.service], **QUICK)
                    if not healthy:
                        await workflow.execute_activity_method(acts.record_result, **_zoned(acts.record_result),
                                                               args=[plan, req.service, False, 1], **QUICK)
                        cause = (f"its alarm fired again at {self._alarm_at}" if self._alarm_at
                                 else "a health check failed")
                        minutes = int(after.total_seconds() // 60)
                        why = f"{req.service} recovered, then {cause} by the {minutes}-minute re-check"
                        if now_too and self._alarm_at:
                            why = f"{req.service} recovered, then {cause}"
                        again = []
                        if not self._alarm_at and workflow.patched("g10-rediagnose"):
                            # No alarm fired, so none starts an incident: WARDEN thinks again itself - the cause, the
                            # fix, the plan - from what it reads now, with this fix beside the evidence (owner,
                            # 2026-10-15). Any fix it finds is a new plan for an approver.
                            again = await self._diagnose_again(req, acts, why)
                        return await end("relapsed", [why, *again])
            return await end("recovered")

        self._stage = "rolling_back"
        try:
            undone = await workflow.execute_activity_method(acts.rollback, **_zoned(acts.rollback), args=[plan], **ONCE)
        except ActivityError as exc:
            if is_cancelled_exception(exc):
                raise
            # The run still ends on the record, signed: a failed rollback crashed the workflow with no end row
            # (sixth review, 2026-10-01). The activity tripped the kill switch; a person takes it from here.
            return await end("rollback_failed", [f"{req.service} did not recover, and {exc.cause or exc}"])
        why = (f"{req.service}'s alarm fired again during the verify window, at {self._alarm_at} (register C1)"
               if self._alarm_at else f"{req.service} did not recover within {req.recover_within_minutes} min")
        if self._side_effects:
            # A count, never the signal's own words (security review M2): the record says which alarms they were.
            n = len(self._side_effects)
            why += f"; also, {n} other alarm{'s' if n > 1 else ''} started after the fix (see the record)"
        # A change with nothing to undo (a restart, a closed session) is not "rolled back": the target is as the
        # fix left it, unhealthy - a person (sixth review, 2026-10-01).
        if str(undone).startswith(("nothing to roll back", "not rolled back")):
            return await end("not_recovered", [why, str(undone)])
        return await end("rolled_back", [why])


@workflow.defn
class DiscussWorkflow:
    """One mention of WARDEN in the discussion channel, answered in its thread (discuss.py): the thread read, the
    incident's evidence read again, the model's answer, the reply - each step in its zone. It changes nothing, and
    starts nothing that does."""

    @workflow.run
    async def run(self, turn: Turn) -> str:
        acts = DiscussActivities
        turn = Turn.model_validate(turn)
        thread = Thread.model_validate(await workflow.execute_activity_method(
            acts.discuss_thread, **_zoned(acts.discuss_thread), args=[turn], **NOTIFY))
        if thread.elsewhere:  # another environment's incident: refused before anything of it was read
            text = ELSEWHERE.format(environment=turn.environment)
        elif not thread.incident:
            text = ("Which incident? Mention its id - the one in the footer of any of its messages - with your "
                    "question, and WARDEN answers here.")
        elif thread.over:
            text = LIMIT
        if thread.incident and not thread.over and workflow.patched("discuss-facts"):
            # The record's facts first, at once - the incident and the ones like it - then the model's answer.
            with contextlib.suppress(ActivityError):
                facts = await workflow.execute_activity_method(
                    acts.discuss_facts, **_zoned(acts.discuss_facts), args=[thread.incident], **QUICK)
                if facts:
                    await workflow.execute_activity_method(acts.discuss_reply, **_zoned(acts.discuss_reply),
                                                           args=[turn, facts, thread.incident], **NOTIFY)
        if not thread.incident or thread.over:
            pass
        elif NEW_PLAN.search(turn.text) and workflow.patched("g10-discuss-replan"):
            text = NOT_READ
            with contextlib.suppress(ActivityError):
                got = await workflow.execute_activity_method(
                    acts.discuss_replan, **_zoned(acts.discuss_replan), args=[turn, thread.incident], **QUICK)
                why = got.get("why", "")
                text = (NOT_APPROVER if why == "not an approver"
                        else REPLAN_SOON.format(incident=thread.incident) if why == "asked again within the hour"
                        else NO_RECORD.format(incident=thread.incident) if why else NOT_READ)
                if not why:
                    # A diagnosis, nothing more: any fix it finds is its own plan, waiting for a passkey.
                    with contextlib.suppress(WorkflowAlreadyStartedError):
                        await workflow.start_child_workflow(
                            IncidentWorkflow.run, Alert.model_validate(got["alert"]), id=f"inc-{got['new']}",
                            task_queue=workflow.info().task_queue, parent_close_policy=ParentClosePolicy.ABANDON)
                    text = REPLANNED.format(incident=thread.incident, new=f"`{got['new']}`")
        else:
            fresh = NOW.search(turn.text) is not None
            text, evidence = NOT_READ, None
            try:  # a step that fails still ends in a reply: the person is never left waiting in the thread
                evidence = await workflow.execute_activity_method(
                    acts.discuss_evidence, **_zoned(acts.discuss_evidence), args=[thread.incident, fresh], **PREPARE)
                if evidence is None:
                    text = NO_RECORD.format(incident=thread.incident)
                else:
                    text = NO_ANSWER
                    text = await workflow.execute_activity_method(
                        acts.discuss_answer, **_zoned(acts.discuss_answer), args=[turn, thread, evidence, fresh],
                        start_to_close_timeout=timedelta(minutes=5), retry_policy=RetryPolicy(maximum_attempts=1))
            except ActivityError:
                pass
        await workflow.execute_activity_method(acts.discuss_reply, **_zoned(acts.discuss_reply),
                                               args=[turn, text, thread.incident], **NOTIFY)
        return text


@workflow.defn
class ClockWorkflow:
    """The Temporal server's time as a workflow sees it, for the worker's start-up skew check (register O6)."""

    @workflow.run
    async def run(self) -> datetime:
        return workflow.now()


MODEL_UNAVAILABLE = "ModelUnavailable"


# Checks an answer can pass by being better grounded: a citation that does not quote its item, a target not in the
# evidence, citations that do not bear on the action, a number not in the evidence, too little cited. Everything else
# (safety, environment, tier, injection, freeze, bounds) is final.
REPAIRABLE = frozenset({"P13-UNGROUNDED", "P14-TARGET-NOT-IN-EVIDENCE", "P15-CITATIONS-DO-NOT-SUPPORT-ACTION",
                        "P27-NUMBER-NOT-IN-EVIDENCE", "P9-THIN-EVIDENCE"})
REPAIR_NOTE_CHARS = 800


def repair_note(verdict: Any) -> str:
    """What the model is told when its answer was held only by REPAIRABLE checks; "" otherwise."""
    ids = set(getattr(verdict, "policy_ids", None) or [])
    if not ids or not ids <= REPAIRABLE:
        return ""
    said = "; ".join(str(r) for r in getattr(verdict, "reasons", None) or [])[:REPAIR_NOTE_CHARS]
    return ("\n\nWARDEN'S CHECKS HELD YOUR PREVIOUS ANSWER (" + ", ".join(sorted(ids)) + "): " + said +
            "\nAnswer again from the same evidence: cite only items that exist, quote them exactly, and name only "
            "targets the evidence names. If the evidence cannot support a fix, say so and propose escalate_to_human.")


@workflow.defn
class IncidentWorkflow:
    """One alert, diagnosed: prepare (read + redact, the redaction map never leaves it) -> diagnose
    (the one model call, on redacted input only) -> verify (no model). Started with the workflow id
    `inc-<alert_id>`, so the same alert twice is one incident, not two.

    It ends at the verdict, exactly where the graph ended. Turning an approved proposal into a
    RemediationWorkflow needs a per-platform resolver from proposal to catalogue parameters, read
    from live state; that arrives with the real platforms (Phase 4). Until then a proposal is advice.
    """

    def __init__(self) -> None:
        self._repeats: list[str] = []

    @workflow.signal
    def repeat(self, at: str) -> None:
        """The same alarm fired again while this incident is open (register C2): counted here, not a second incident."""
        self._repeats.append(at)

    @workflow.query
    def repeats(self) -> list[str]:
        return list(self._repeats)

    @workflow.run
    async def run(self, alert: Alert, escalate_only: str = "", held: str = "") -> RunReport:
        """`escalate_only`: intake's reason to hand this alarm to a person on the rules alone (flapping, a storm),
        without asking the model to propose a change (registers C21, C2). `held`: why intake held this alarm until
        now (expected down, register G10-39) - it is an incident only if it is still firing."""
        acts = IncidentActivities
        if held:  # an input no earlier history carries: they replay unchanged
            try:
                firing = await workflow.execute_activity_method(acts.after_hold, **_zoned(acts.after_hold),
                                                                args=[alert, held], **QUICK)
            except ActivityError:
                firing = None  # the alarm could not be read: unknown is not cleared
            if firing is False:
                return RunReport(alert=alert, redaction_map_size=0, context=ContextBundle(),
                                 halted_reason=f"the alarm had cleared when its hold ended ({held}): no incident")
            # An incident from the moment it was no longer expected: the evidence is read around now, not around
            # the shutdown.
            alert = Alert.model_validate(alert).model_copy(update={"started_at": workflow.now().isoformat()})
        # Register R23: read only once the alert's last minutes have reached the log store. A durable timer, so a
        # worker restart does not restart the wait; patched, so histories recorded before it replay unchanged.
        if workflow.patched("r23-ingest-lag"):
            # The argument arrives as the converter decoded it (a dict here); read its time through the model.
            wait = ingestion_wait(Alert.model_validate(alert).started_at, workflow.now())
            if wait > timedelta(0):
                await workflow.sleep(wait)
        pack = await workflow.execute_activity_method(acts.prepare, **_zoned(acts.prepare), args=[alert], **PREPARE)
        # A source that answered with nothing right after the alert may only be early (research 2026-10-15, item 3):
        # read once more when the alert is old enough for its slowest source, on a durable timer. One re-read at most;
        # what it filled, and the alert's age then, go on the record. Patched: earlier histories replay unchanged.
        if pack.context.empty_reads and workflow.patched("reread-once"):
            wait = reread_wait(pack.alert.started_at, workflow.now())
            if wait is not None:
                await workflow.sleep(wait)
                pack = await workflow.execute_activity_method(acts.reread, **_zoned(acts.reread), args=[pack],
                                                              **PREPARE)
        # ONE attempt (audit A-C-7): the model client retries inside one budget and one call ceiling; a
        # Temporal retry built a fresh client, and so a fresh budget - $1.20 spent against a $0.50 cap
        # (fourth review, 2026-09-30).
        diagnosed = await workflow.execute_activity_method(
            acts.diagnose, **_zoned(acts.diagnose), args=[pack, escalate_only], start_to_close_timeout=timedelta(minutes=10),
            retry_policy=RetryPolicy(maximum_attempts=1))
        # G9-B: the model may ask to read up to 3 related resources it saw named in trusted evidence, then decide
        # again - at most INVESTIGATE_ROUNDS times; the llm zone's budget (6 calls, US$0.25 per incident, counted
        # from the audit across rounds) stops it sooner. Patched: histories recorded before it replay unchanged.
        first = pack.alert  # what the alarm itself named: the only targets a fix plan may take (review F6)
        if workflow.patched("g9-investigate"):
            rounds = 0
            while diagnosed.need_evidence and not diagnosed.model_unavailable and rounds < INVESTIGATE_ROUNDS:
                rounds += 1
                try:
                    wider = await workflow.execute_activity_method(
                        acts.investigate, **_zoned(acts.investigate), args=[pack, diagnosed.need_evidence], **PREPARE)
                    if wider.alert.labels == pack.alert.labels:
                        break  # nothing accepted: no second answer on the same evidence (review F4)
                    again = await workflow.execute_activity_method(
                        acts.diagnose, **_zoned(acts.diagnose), args=[wider, escalate_only],
                        start_to_close_timeout=timedelta(minutes=10), retry_policy=RetryPolicy(maximum_attempts=1))
                except ActivityError:
                    break  # a failed read or call: the answer so far stands, and is verified and told (review F8)
                if again.model_unavailable:
                    break  # e.g. the budget is spent: the earlier answer, on its own evidence, stands (review F8)
                pack, diagnosed = wider, again
        verified = await workflow.execute_activity_method(acts.verify, **_zoned(acts.verify), args=[pack, diagnosed], **QUICK)
        # One repair round (research 2026-10-15: a model fixes an error when told exactly where it is, and rules-based
        # feedback is the strongest kind): an answer held ONLY by checks a better answer can pass is asked once more,
        # with the checks' own words. Safety policies are never fed back - the model must not learn to argue past
        # them. Within the llm zone's budget (6 calls, US$0.25 per incident); patched, so histories replay unchanged.
        note = repair_note(verified.verdict)
        if note and not diagnosed.model_unavailable and workflow.patched("verify-repair"):
            try:
                again = await workflow.execute_activity_method(
                    acts.diagnose, **_zoned(acts.diagnose),
                    args=[pack.model_copy(update={"prompt": pack.prompt + note}), escalate_only],
                    start_to_close_timeout=timedelta(minutes=10), retry_policy=RetryPolicy(maximum_attempts=1))
                if not again.model_unavailable:
                    checked = await workflow.execute_activity_method(acts.verify, **_zoned(acts.verify),
                                                                     args=[pack, again], **QUICK)
                    diagnosed, verified = again, checked
            except ActivityError:
                pass  # the first answer, verified, stands
        # A second, independent opinion before any fix reaches a person (owner, 2026-10-15: "better and more double
        # checks ... the model sometimes makes mistakes"): the model asked once more on the same evidence; if the two
        # answers name another action or another target, the fix is escalated, never offered. It can only take an
        # approval away. Within the llm zone's budget; patched, so histories recorded before it replay unchanged.
        if (str(getattr(verified.verdict.status, "value", verified.verdict.status)) == "approved_for_human"
                and not diagnosed.model_unavailable and workflow.patched("second-opinion")):
            try:
                second = await workflow.execute_activity_method(
                    acts.diagnose, **_zoned(acts.diagnose), args=[pack, escalate_only],
                    start_to_close_timeout=timedelta(minutes=10), retry_policy=RetryPolicy(maximum_attempts=1))
            except ActivityError:
                second = diagnosed.model_copy(update={"model_unavailable": "the second diagnosis could not be made"})
            verified = await workflow.execute_activity_method(
                acts.second_opinion, **_zoned(acts.second_opinion), args=[pack, diagnosed, second, verified], **QUICK)
        # One Slack message per incident (owner, 2026-10-14: "why all that alerts total details and approval thing
        # coming in 3 parts ... i want all in one part only"): the report is recorded first, and said once - in the
        # plan's request for approval when a plan opens, else on its own with why there is none.
        one = workflow.patched("g10-one-message")
        if not one and workflow.patched("s17-notify"):
            # Register S17: a person is told, with the incident id and the audit head to check the message against -
            # before an escalate-only run ends. A notification that fails does not fail the incident: the audit holds
            # the verdict.
            try:
                await workflow.execute_activity_method(acts.notify, **_zoned(acts.notify), args=[pack, diagnosed, verified], **NOTIFY)
            except ActivityError:
                pass
        # G9-D1: a proposal the verifier passed for a person opens its fix plan - a RemediationWorkflow that waits for
        # a signed human approval, as one requested through MCP does. Its own workflow, abandoned by this one: the plan
        # outlives the incident's run. Patched: histories recorded before it replay unchanged.
        # Review-e M5: also a proposal escalated by P6 ALONE - its reach is wide, which is exactly what the signed approval
        # of its plan decides; shift_traffic's floor is multi_service, so no zonal shift could ever be planned.
        plannable = verified.verdict.status.value == "approved_for_human" or (
            workflow.patched("g9-plan-p6") and verified.verdict.status.value == "escalated"
            and set(verified.verdict.policy_ids) == {"P6-BLAST-RADIUS"})
        # Held by P31 alone: plan_fix offers the undo of the change the proposal left unaddressed (activities.py).
        if (not plannable and verified.verdict.status.value == "escalated"
                and set(verified.verdict.policy_ids) == {"P31-UNADDRESSED-CHANGE"}):
            plannable = workflow.patched("g10-offer-undo")
        if workflow.patched("g9-plan-fix") and not diagnosed.model_unavailable and plannable:
            try:
                req = await workflow.execute_activity_method(acts.plan_fix, **_zoned(acts.plan_fix),
                                                             args=[first, diagnosed, verified], **QUICK)
            except ActivityError:
                req = {}
            held = ""
            if one:
                with contextlib.suppress(ActivityError):
                    await workflow.execute_activity_method(acts.notify, **_zoned(acts.notify),
                                                           args=[pack, diagnosed, verified, "plan" if req else "none"],
                                                           **NOTIFY)
            if req:
                wid = req.pop("workflow_id")
                try:
                    await workflow.start_child_workflow(
                        RemediationWorkflow.run, FixRequest.model_validate(req), id=wid,
                        task_queue=workflow.info().task_queue, parent_close_policy=ParentClosePolicy.ABANDON)
                except WorkflowAlreadyStartedError:  # one open plan per resource (C3)
                    # Where a reader can see it: the records page (2026-10-15: `warden status` needs a Temporal key
                    # that only the runtime holds, so the command it named could not be run by anyone reading this).
                    held = (f"an earlier plan for the same resource (`{wid}`) is still open - waiting for its "
                            "approval, or being watched after its fix; the records page (All incidents) shows it")
            # The report said "held for approval": with no plan to approve, a person is told so, and why.
            if ((not req and not one) or held) and workflow.patched("g10-no-plan"):
                with contextlib.suppress(ActivityError):
                    await workflow.execute_activity_method(acts.no_plan, **_zoned(acts.no_plan),
                                                           args=[first.alert_id, held], **NOTIFY)
        elif one:  # nothing to plan: the report is the incident's one message
            with contextlib.suppress(ActivityError):
                await workflow.execute_activity_method(acts.notify, **_zoned(acts.notify),
                                                       args=[pack, diagnosed, verified, "none"], **NOTIFY)
        if diagnosed.model_unavailable:
            # Rules only (register M19): the escalation is verified and audited above, and the run ends FAILED, so the
            # incident may be diagnosed again once the model is back (ALLOW_DUPLICATE_FAILED_ONLY, sixth review).
            raise ApplicationError(f"escalated without a model: {diagnosed.model_unavailable}",
                                   type=MODEL_UNAVAILABLE, non_retryable=True)
        return RunReport(alert=pack.alert, redaction_map_size=pack.masked, context=pack.context,
                         root_cause=diagnosed.root_cause, proposal=diagnosed.proposal, verdict=verified.verdict,
                         cost=diagnosed.cost, audit=pack.steps + diagnosed.steps + verified.steps,
                         halted_reason=verified.halted_reason)
