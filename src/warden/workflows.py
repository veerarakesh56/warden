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

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError, is_cancelled_exception

with workflow.unsafe.imports_passed_through():
    from .activities import (
        APPLY_REFUSED,
        FixOutcome,
        FixRequest,
        IncidentActivities,
        Plan,
        Recorded,
        RemediationActivities,
    )
    from .approvals import PasskeyAssertion, SignedApproval
    from .models import Alert, RunReport, ingestion_wait

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
CHECK_EVERY = timedelta(seconds=30)
# Register C18a, false recovery: a service that died stops reporting errors, and one good reading is not recovery.
# Recovered = this many healthy checks in a row; then re-checked this long after, the run open until the last.
CONSECUTIVE_HEALTHY = 3
RECHECK_AFTER = (timedelta(minutes=15), timedelta(minutes=60))
# Stages that are ends: a failure there is the end row's own (finish), with nothing left to record.
END_STAGES = frozenset({"refused", "blocked", "expired", "drifted", "refused_at_apply", "apply_failed", "recovered",
                        "rollback_failed", "not_recovered", "rolled_back", "cancelled", "cancelled_after_apply",
                        "failed", "failed_after_apply", "relapsed"})


@workflow.defn
class RemediationWorkflow:
    def __init__(self) -> None:
        self._inbox: list[SignedApproval | PasskeyAssertion] = []
        self._plan: Plan | None = None
        self._stage = "planning"
        self._applying = False  # set the moment apply is sent: from then on the target's state is not known
        self._alarm_at = ""  # the target's alarm fired during the verify window (register C1)

    @workflow.signal
    def approve(self, approval: SignedApproval) -> None:
        self._inbox.append(approval)

    @workflow.signal
    def approve_passkey(self, assertion: PasskeyAssertion) -> None:
        """A passkey approval from the approval page (register H6): re-verified by check_passkey before it counts."""
        self._inbox.append(assertion)

    @workflow.signal
    def alarm(self, at: str) -> None:
        """The target's alarm fired again (register C1, from intake). Inside the verify window that is the fix not
        working: the run stops verifying and rolls back. Before the change it is the incident itself, and ignored."""
        if self._stage in ("verifying", "watching"):
            self._alarm_at = at

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
            await workflow.execute_activity_method(acts.finish, args=[req.incident_id, wid, outcome], **QUICK)
            done["audited"] = True
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

    async def _steps(self, req: FixRequest, acts, wid: str, done: dict, end) -> FixOutcome:
        plan = self._plan = await workflow.execute_activity_method(acts.resolve_plan, args=[req, wid], **QUICK)
        if plan.problems:
            return await end("refused", plan.problems)
        done["planned"] = True

        blocked = await workflow.execute_activity_method(acts.gate, args=[plan, req.service], **QUICK)
        # Only an explicit empty list is "not blocked": an unreadable or forged answer decodes to None,
        # which `if blocked:` read as a pass (third review, 2026-09-30).
        if blocked != []:
            return await end("blocked", blocked or ["the gate's answer could not be read"])
        done["policy"] = True

        self._stage = "awaiting_approval"
        deadline = workflow.now() + timedelta(minutes=req.approval_ttl_minutes)
        accepted: list[SignedApproval] = []
        refused: list[str] = []
        seen = 0
        # Register H10: halfway through the wait a person is reminded, and at the end told that nothing was done -
        # an approval request that only expires is one nobody may ever have seen. A failed message changes nothing.
        ladder = workflow.patched("h10-ladder")
        halfway, reminded = workflow.now() + timedelta(minutes=req.approval_ttl_minutes) / 2, False
        while True:
            until = halfway if ladder and not reminded and not accepted else deadline
            try:
                await workflow.wait_condition(lambda n=seen: len(self._inbox) > n,
                                              timeout=max(until - workflow.now(), timedelta(0)))
            except TimeoutError:
                if until == halfway and workflow.now() < deadline:
                    reminded = True
                    with contextlib.suppress(ActivityError):
                        await workflow.execute_activity_method(acts.announce, args=[plan, "waiting"], **NOTIFY)
                    continue
                if ladder:
                    with contextlib.suppress(ActivityError):
                        await workflow.execute_activity_method(acts.announce, args=[plan, "expired"], **NOTIFY)
                return await end("expired", refused or ["no valid approval arrived in time"])
            approval, seen = self._inbox[seen], seen + 1
            if isinstance(approval, PasskeyAssertion):
                result = await workflow.execute_activity_method(acts.check_passkey, args=[plan, approval, accepted],
                                                                **QUICK)
                approval = result.accepted
            else:
                result = await workflow.execute_activity_method(acts.check_approval,
                                                                args=[plan, approval, accepted], **QUICK)
            if result.problems or approval is None:
                refused += result.problems
                continue
            accepted.append(approval)
            if result.enough:
                break
        done["approved"] = True

        self._stage = "prechecking"
        drift = await workflow.execute_activity_method(acts.precheck, args=[plan], **QUICK)
        if drift != []:  # as for the gate: only an explicit empty list is clean
            return await end("drifted", drift or ["the precheck's answer could not be read"])
        done["prechecked"] = True

        self._stage = "applying"
        self._applying = True
        try:
            await workflow.execute_activity_method(acts.apply, args=[plan, req.service], **ONCE)
        except ActivityError as exc:
            if is_cancelled_exception(exc):
                raise  # a cancel, not a failed apply: run() ends it, after apply (ninth review)
            if isinstance(exc.cause, ApplicationError) and exc.cause.type == APPLY_REFUSED:
                # Refused before anything was touched: nothing to roll back, nothing half-made.
                return await end("refused_at_apply", [str(exc.cause)])
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
            healthy = await workflow.execute_activity_method(acts.check_success, args=[plan, req.service], **QUICK)
            streak = streak + 1 if healthy else 0
        recovered = streak >= need and not self._alarm_at
        # The verdict is WARDEN's audit of THIS run's own checks, returned with the run it belongs to: a
        # result replayed from an earlier run of this workflow id carries that run's id and is refused.
        recorded = await workflow.execute_activity_method(acts.record_result,
                                                          args=[plan, req.service, recovered, need], **QUICK)
        recovered = (isinstance(recorded, Recorded) and recorded.ok is True
                     and recorded.run_id == workflow.info().run_id)
        if recovered:
            done["verified"] = True
            if workflow.patched("c18a-rechecks"):
                # Durable re-checks (register C18a): a fix that holds for minutes and fails within the hour is not a
                # recovery. A relapse is recorded as a failed result (the breaker counts it) and goes to a person:
                # WARDEN never reverses its own fix on its own (register C8).
                self._stage = "watching"
                since = workflow.now()
                for after in RECHECK_AFTER:
                    await workflow.sleep(max(since + after - workflow.now(), timedelta(0)))
                    healthy = not self._alarm_at and await workflow.execute_activity_method(
                        acts.check_success, args=[plan, req.service], **QUICK)
                    if not healthy:
                        await workflow.execute_activity_method(acts.record_result,
                                                               args=[plan, req.service, False, 1], **QUICK)
                        cause = (f"its alarm fired again at {self._alarm_at}" if self._alarm_at
                                 else "a health check failed")
                        minutes = int(after.total_seconds() // 60)
                        why = f"{req.service} recovered, then {cause} by the {minutes}-minute re-check"
                        return await end("relapsed", [why])
            return await end("recovered")

        self._stage = "rolling_back"
        try:
            undone = await workflow.execute_activity_method(acts.rollback, args=[plan], **ONCE)
        except ActivityError as exc:
            if is_cancelled_exception(exc):
                raise
            # The run still ends on the record, signed: a failed rollback crashed the workflow with no end row
            # (sixth review, 2026-10-01). The activity tripped the kill switch; a person takes it from here.
            return await end("rollback_failed", [f"{req.service} did not recover, and {exc.cause or exc}"])
        why = (f"{req.service}'s alarm fired again during the verify window, at {self._alarm_at} (register C1)"
               if self._alarm_at else f"{req.service} did not recover within {req.recover_within_minutes} min")
        # A change with nothing to undo (a restart, a closed session) is not "rolled back": the target is as the
        # fix left it, unhealthy - a person (sixth review, 2026-10-01).
        if str(undone).startswith("nothing to roll back"):
            return await end("not_recovered", [why, str(undone)])
        return await end("rolled_back", [why])


@workflow.defn
class ClockWorkflow:
    """The Temporal server's time as a workflow sees it, for the worker's start-up skew check (register O6)."""

    @workflow.run
    async def run(self) -> datetime:
        return workflow.now()


MODEL_UNAVAILABLE = "ModelUnavailable"


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
    async def run(self, alert: Alert, escalate_only: str = "") -> RunReport:
        """`escalate_only`: intake's reason to hand this alarm to a person on the rules alone (flapping, a storm),
        without asking the model to propose a change (registers C21, C2)."""
        acts = IncidentActivities
        # Register R23: read only once the alert's last minutes have reached the log store. A durable timer, so a
        # worker restart does not restart the wait; patched, so histories recorded before it replay unchanged.
        if workflow.patched("r23-ingest-lag"):
            # The argument arrives as the converter decoded it (a dict here); read its time through the model.
            wait = ingestion_wait(Alert.model_validate(alert).started_at, workflow.now())
            if wait > timedelta(0):
                await workflow.sleep(wait)
        pack = await workflow.execute_activity_method(acts.prepare, args=[alert], **PREPARE)
        # ONE attempt (audit A-C-7): the model client retries inside one budget and one call ceiling; a
        # Temporal retry built a fresh client, and so a fresh budget - $1.20 spent against a $0.50 cap
        # (fourth review, 2026-09-30).
        diagnosed = await workflow.execute_activity_method(
            acts.diagnose, args=[pack, escalate_only], start_to_close_timeout=timedelta(minutes=10),
            retry_policy=RetryPolicy(maximum_attempts=1))
        verified = await workflow.execute_activity_method(acts.verify, args=[pack, diagnosed], **QUICK)
        if workflow.patched("s17-notify"):
            # Register S17: a person is told, with the incident id and the audit head to check the message against -
            # before an escalate-only run ends. A notification that fails does not fail the incident: the audit holds
            # the verdict.
            try:
                await workflow.execute_activity_method(acts.notify, args=[pack, diagnosed, verified], **NOTIFY)
            except ActivityError:
                pass
        if diagnosed.model_unavailable:
            # Rules only (register M19): the escalation is verified and audited above, and the run ends FAILED, so the
            # incident may be diagnosed again once the model is back (ALLOW_DUPLICATE_FAILED_ONLY, sixth review).
            raise ApplicationError(f"escalated without a model: {diagnosed.model_unavailable}",
                                   type=MODEL_UNAVAILABLE, non_retryable=True)
        return RunReport(alert=pack.alert, redaction_map_size=pack.masked, context=pack.context,
                         root_cause=diagnosed.root_cause, proposal=diagnosed.proposal, verdict=verified.verdict,
                         cost=diagnosed.cost, audit=pack.steps + diagnosed.steps + verified.steps,
                         halted_reason=verified.halted_reason)
