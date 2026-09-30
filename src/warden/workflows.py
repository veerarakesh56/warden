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

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError

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
    from .approvals import SignedApproval
    from .models import Alert, RunReport

STEPS = ("planned", "policy", "approved", "prechecked", "applied", "verified", "audited")
QUICK = {"start_to_close_timeout": timedelta(seconds=60)}
ONCE = {"start_to_close_timeout": timedelta(minutes=5), "retry_policy": RetryPolicy(maximum_attempts=1)}
# prepare reads, redacts and runs the tripwire (bounded by tripwire.MAX_SCAN_TOKENS, about a minute):
# a few attempts, then the incident FAILS visibly - never an endless retry (second review, 2026-09-30).
# 15 min: a full-budget scan measured ~7 min on a loaded laptop CPU (third review, 2026-09-30).
PREPARE = {"start_to_close_timeout": timedelta(minutes=15), "retry_policy": RetryPolicy(maximum_attempts=3)}
CHECK_EVERY = timedelta(seconds=30)


@workflow.defn
class RemediationWorkflow:
    def __init__(self) -> None:
        self._inbox: list[SignedApproval] = []
        self._plan: Plan | None = None
        self._stage = "planning"

    @workflow.signal
    def approve(self, approval: SignedApproval) -> None:
        self._inbox.append(approval)

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
        while True:
            remaining = deadline - workflow.now()
            try:
                await workflow.wait_condition(lambda n=seen: len(self._inbox) > n, timeout=max(remaining, timedelta(0)))
            except TimeoutError:
                return await end("expired", refused or ["no valid approval arrived in time"])
            approval, seen = self._inbox[seen], seen + 1
            result = await workflow.execute_activity_method(acts.check_approval, args=[plan, approval, accepted],
                                                            **QUICK)
            if result.problems:
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
        try:
            await workflow.execute_activity_method(acts.apply, args=[plan, req.service], **ONCE)
        except ActivityError as exc:
            if isinstance(exc.cause, ApplicationError) and exc.cause.type == APPLY_REFUSED:
                # Refused before anything was touched: nothing to roll back, nothing half-made.
                return await end("refused_at_apply", [str(exc.cause)])
            # The change may be half-made; the state is unknown, so no automatic rollback - a person.
            return await end("apply_failed", [f"apply failed: {exc.cause or exc}"])
        done["applied"] = True

        self._stage = "verifying"
        until = workflow.now() + timedelta(minutes=req.recover_within_minutes)
        recovered = False
        while workflow.now() < until and not recovered:
            await workflow.sleep(CHECK_EVERY)
            recovered = await workflow.execute_activity_method(acts.check_success, args=[plan, req.service],
                                                               **QUICK)
        # The verdict is WARDEN's audit of THIS run's own checks, returned with the run it belongs to: a
        # result replayed from an earlier run of this workflow id carries that run's id and is refused.
        recorded = await workflow.execute_activity_method(acts.record_result, args=[plan, req.service, recovered],
                                                          **QUICK)
        recovered = (isinstance(recorded, Recorded) and recorded.ok is True
                     and recorded.run_id == workflow.info().run_id)
        if recovered:
            done["verified"] = True
            return await end("recovered")

        self._stage = "rolling_back"
        await workflow.execute_activity_method(acts.rollback, args=[plan], **ONCE)
        return await end("rolled_back", [f"{req.service} did not recover within {req.recover_within_minutes} min"])


@workflow.defn
class IncidentWorkflow:
    """One alert, diagnosed: prepare (read + redact, the redaction map never leaves it) -> diagnose
    (the one model call, on redacted input only) -> verify (no model). Started with the workflow id
    `inc-<alert_id>`, so the same alert twice is one incident, not two.

    It ends at the verdict, exactly where the graph ended. Turning an approved proposal into a
    RemediationWorkflow needs a per-platform resolver from proposal to catalogue parameters, read
    from live state; that arrives with the real platforms (Phase 4). Until then a proposal is advice.
    """

    @workflow.run
    async def run(self, alert: Alert) -> RunReport:
        acts = IncidentActivities
        pack = await workflow.execute_activity_method(acts.prepare, args=[alert], **PREPARE)
        # ONE attempt (audit A-C-7): the model client retries inside one budget and one call ceiling; a
        # Temporal retry built a fresh client, and so a fresh budget - $1.20 spent against a $0.50 cap
        # (fourth review, 2026-09-30).
        diagnosed = await workflow.execute_activity_method(
            acts.diagnose, args=[pack], start_to_close_timeout=timedelta(minutes=10),
            retry_policy=RetryPolicy(maximum_attempts=1))
        verified = await workflow.execute_activity_method(acts.verify, args=[pack, diagnosed], **QUICK)
        return RunReport(alert=pack.alert, redaction_map_size=pack.masked, context=pack.context,
                         root_cause=diagnosed.root_cause, proposal=diagnosed.proposal, verdict=verified.verdict,
                         cost=diagnosed.cost, audit=pack.steps + diagnosed.steps + verified.steps,
                         halted_reason=verified.halted_reason)
