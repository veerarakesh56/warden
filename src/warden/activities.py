"""The activities of the remediation workflow: every step that touches the world or the audit log.

The workflow (workflows.py) is deterministic orchestration only. Everything with a side effect or a
clock is here, and every step writes an audit row.

A `Platform` is how an activity reads and changes one kind of system (Lambda, ECS, Kubernetes, a
database). Phase 2 ships only a fake for tests; the real AWS ones come with the JIT roles in
Phase 4, so no activity here holds a credential yet.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import BaseModel, Field
from temporalio import activity
from temporalio.exceptions import ApplicationError

from . import approvals, bounds, catalog
from .audit import AuditLog
from .models import Alert, ContextBundle, CostRecord, RemediationProposal, RootCause, Verdict


class FixRequest(BaseModel):
    incident_id: str
    # A catalogue entry name, never free text: an agent-supplied entry was printed raw by `warden
    # status` (independent review 2026-09-28). The catalogue itself decides whether it exists.
    entry: str = Field(pattern=r"^[a-z][a-z0-9_]{1,60}$")
    params: dict[str, Any]
    service: str
    approval_ttl_minutes: int = 30
    recover_within_minutes: int = 5


class Plan(BaseModel):
    workflow_id: str
    incident_id: str
    entry: str
    tier: str = ""
    params: dict[str, Any]
    snapshot: dict[str, Any] = Field(default_factory=dict)
    plan_hash: str = ""
    created_at: datetime
    problems: list[str] = Field(default_factory=list)


APPLY_REFUSED = "ApplyRefused"


def _run_id() -> str:
    """The Temporal run this activity belongs to. Every remediation row records it, and apply counts only
    rows of its own run: `rem-<service>` is reused, and a replay of an earlier run's approval and
    results applied a later run nobody approved (third review, 2026-09-30). Empty outside an activity."""
    try:
        return activity.info().workflow_run_id or ""
    except RuntimeError:  # called directly (tests, tools), not by a worker
        return ""


class ApprovalResult(BaseModel):
    problems: list[str]
    enough: bool = False


class Recorded(BaseModel):
    """The verdict of a remediation, as WARDEN's own audit shows it, and the run it belongs to."""
    run_id: str
    ok: bool


class FixOutcome(BaseModel):
    status: str
    reasons: list[str] = Field(default_factory=list)
    checklist: dict[str, bool]
    plan_hash: str = ""


class Platform(Protocol):
    def live(self, entry: str, params: dict[str, Any]) -> dict[str, Any]:
        """What WARDEN reads before acting: allowed values for each `ref` parameter (sets), the
        current values relative limits need, and `state` - a JSON snapshot of the target."""

    def apply(self, entry: str, params: dict[str, Any]) -> str: ...

    def healthy(self, service: str) -> bool: ...

    def rollback(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any]) -> str: ...


def plan_hash(entry: str, params: dict[str, Any], snapshot: dict[str, Any]) -> str:
    material = json.dumps([entry, params, snapshot], sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(material.encode()).hexdigest()


class RemediationActivities:
    def __init__(self, *, audit: AuditLog, policy: approvals.ApproverPolicy, platform: Platform,
                 limits: bounds.Limits = bounds.DEFAULT_LIMITS) -> None:
        self.audit, self.policy, self.platform, self.limits = audit, policy, platform, limits

    @activity.defn
    def resolve_plan(self, req: FixRequest, workflow_id: str) -> Plan:
        entry = catalog.CATALOG.get(req.entry)
        live = self.platform.live(req.entry, req.params)
        problems = catalog.validate(req.entry, req.params, live)
        snapshot = live.get("state", {})
        plan = Plan(workflow_id=workflow_id, incident_id=req.incident_id, entry=req.entry,
                    tier=entry.tier if entry else "", params=req.params, snapshot=snapshot,
                    plan_hash=plan_hash(req.entry, req.params, snapshot), created_at=datetime.now(UTC),
                    problems=problems)
        self.audit.append(req.incident_id, "remediation.plan",
                          {"workflow_id": workflow_id, "run_id": _run_id(), "entry": req.entry, "tier": plan.tier,
                           "params": req.params, "plan_hash": plan.plan_hash, "problems": problems})
        return plan

    @activity.defn
    def gate(self, plan: Plan, service: str) -> list[str]:
        reasons = bounds.blocked(self.audit, service=service, action_class=plan.entry, now=datetime.now(UTC),
                                 limits=self.limits)
        self.audit.append(plan.incident_id, "remediation.gate", {"workflow_id": plan.workflow_id, "run_id": _run_id(),
                                                                  "blocked": reasons})
        return reasons

    @activity.defn
    def check_approval(self, plan: Plan, approval: approvals.SignedApproval,
                       accepted: list[approvals.SignedApproval]) -> ApprovalResult:
        used = {e["body"]["nonce"] for e in self.audit.entries(kinds=("approval.accepted",))}
        problems = approvals.check(approval, policy=self.policy, workflow_id=plan.workflow_id,
                                   plan_hash=plan.plan_hash, tier=plan.tier, plan_created_at=plan.created_at,
                                   used_nonces=used)
        if any(a.approver == approval.approver for a in accepted):
            problems.append(f"{approval.approver} has already approved this plan")
        kind = "approval.refused" if problems else "approval.accepted"
        self.audit.append(plan.incident_id, kind, {"workflow_id": plan.workflow_id, "run_id": _run_id(),
                                                   "approver": approval.approver,
                                                   "nonce": approval.nonce, "plan_hash": plan.plan_hash,
                                                   "problems": problems})
        valid = accepted + ([approval] if not problems else [])
        return ApprovalResult(problems=problems, enough=approvals.enough(valid, plan.tier, self.policy))

    @activity.defn
    def precheck(self, plan: Plan) -> list[str]:
        """Read live state again right before acting: a plan approved against a state that no longer
        exists is not the plan that was approved."""
        live = self.platform.live(plan.entry, plan.params)
        problems = catalog.validate(plan.entry, plan.params, live)
        if plan_hash(plan.entry, plan.params, live.get("state", {})) != plan.plan_hash:
            problems.append("the target changed after the plan was made; it needs a new plan")
        self.audit.append(plan.incident_id, "remediation.precheck",
                          {"workflow_id": plan.workflow_id, "run_id": _run_id(), "plan_hash": plan.plan_hash,
                           "problems": problems})
        return problems

    def _not_approved(self, plan: Plan, service: str) -> list[str]:
        """Why `plan` may not be applied, from WARDEN's OWN audit log - never from what the workflow
        says, and only rows of THIS run (a replayed or forged activity result can carry a workflow past
        any of its steps: second and third reviews, 2026-09-30):
        - the plan resolve_plan made for this workflow and run, same entry and parameters, no problems;
        - as many distinct approvers of that plan hash, in this run, as its tier needs;
        - a clean precheck of that plan hash, in this run, AFTER the approvals (drift);
        - bounds and the kill switch, checked again now - the gate ran before the approval wait."""
        run = _run_id()

        def rows(kind: str) -> list[dict[str, Any]]:
            return [e for e in self.audit.entries(plan.incident_id, kinds=(kind,))
                    if e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("run_id", "") == run
                    and e["body"].get("plan_hash") == plan.plan_hash]

        made = [e["body"] for e in rows("remediation.plan")]
        if (not made or made[-1].get("problems") or made[-1].get("entry") != plan.entry
                or made[-1].get("params") != plan.params):
            return ["no such plan was made for this workflow run"]
        approved = rows("approval.accepted")
        need = self.policy.required.get(made[-1].get("tier", ""), 1)
        if len({e["body"].get("approver") for e in approved}) < need:
            return [f"{len({e['body'].get('approver') for e in approved})} of {need} approval(s) recorded for this plan"]
        last_approval = max(e["seq"] for e in approved)
        checks = [e for e in rows("remediation.precheck") if e["seq"] > last_approval]
        if not checks or checks[-1]["body"].get("problems"):
            return ["no clean precheck of this plan after its approval"]
        return bounds.blocked(self.audit, service=service, action_class=plan.entry, now=datetime.now(UTC),
                              limits=self.limits)

    @activity.defn
    def apply(self, plan: Plan, service: str) -> str:
        run = _run_id()
        refused = self._not_approved(plan, service)
        if refused:
            self.audit.append(plan.incident_id, "remediation.refused", {"workflow_id": plan.workflow_id,
                                                                       "run_id": run, "plan_hash": plan.plan_hash,
                                                                       "why": refused})
            # Its own type: the workflow reports "nothing was changed", not "may be half-made" (fourth review).
            raise ApplicationError("apply refused: " + "; ".join(refused), type=APPLY_REFUSED, non_retryable=True)
        done = [e for e in self.audit.entries(plan.incident_id, kinds=(bounds.APPLIED,))
                if e["body"].get("plan_hash") == plan.plan_hash and e["body"].get("workflow_id") == plan.workflow_id
                and e["body"].get("run_id", "") == run]
        if done:  # idempotent WITHIN this run: a retried activity never applies twice. Scoped to the run
            return "already applied"  # (fourth review): a later approved run of the same plan applied nothing
        self.audit.append(plan.incident_id, "remediation.intent", {"workflow_id": plan.workflow_id,
                                                                   "run_id": run, "plan_hash": plan.plan_hash})
        detail = self.platform.apply(plan.entry, plan.params)
        bounds.record_applied(self.audit, plan.incident_id, service=service, action_class=plan.entry,
                              plan_hash=plan.plan_hash, detail=detail, workflow_id=plan.workflow_id, run_id=run)
        return detail

    @activity.defn
    def check_success(self, plan: Plan, service: str) -> bool:
        healthy = bool(self.platform.healthy(service))
        # Every real check is on the record with its run: the verdict is taken from these rows, never from
        # what an activity result or the workflow claims (fourth review, 2026-09-30: run 1's "healthy"
        # replayed into run 2 marked a fix verified with no health check made).
        self.audit.append(plan.incident_id, "remediation.check",
                          {"workflow_id": plan.workflow_id, "run_id": _run_id(), "plan_hash": plan.plan_hash,
                           "healthy": healthy})
        return healthy

    @activity.defn
    def record_result(self, plan: Plan, service: str, ok: bool) -> Recorded:
        run = _run_id()
        checks = [e["body"] for e in self.audit.entries(plan.incident_id, kinds=("remediation.check",))
                  if e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("run_id", "") == run
                  and e["body"].get("plan_hash") == plan.plan_hash]
        # Verified only if THIS run applied the plan: a replayed apply result let a run with nothing applied
        # end "recovered" and write a success row (fifth review, 2026-10-01).
        applied = any(e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("run_id", "") == run
                      and e["body"].get("plan_hash") == plan.plan_hash
                      for e in self.audit.entries(plan.incident_id, kinds=(bounds.APPLIED,)))
        verified = applied and bool(checks) and checks[-1].get("healthy") is True
        if verified != ok:
            self.audit.append(plan.incident_id, "remediation.result_mismatch",
                              {"workflow_id": plan.workflow_id, "run_id": run, "claimed": ok, "recorded": verified})
        bounds.record_result(self.audit, plan.incident_id, service=service, ok=verified, now=datetime.now(UTC),
                             limits=self.limits, workflow_id=plan.workflow_id, run_id=run,
                             plan_hash=plan.plan_hash)
        return Recorded(run_id=run, ok=verified)

    @activity.defn
    def rollback(self, plan: Plan) -> str:
        detail = self.platform.rollback(plan.entry, plan.params, plan.snapshot)
        self.audit.append(plan.incident_id, "remediation.rollback", {"workflow_id": plan.workflow_id, "detail": detail})
        return detail

    @activity.defn
    def finish(self, incident_id: str, workflow_id: str, outcome: FixOutcome) -> None:
        # The signed end row states what THIS run's audit rows show, not what the workflow claims (fourth
        # review: a refused apply was recorded with approved and prechecked True).
        run = _run_id()

        def ours(kind: str) -> list[dict[str, Any]]:
            return [e["body"] for e in self.audit.entries(incident_id, kinds=(kind,))
                    if e["body"].get("workflow_id") == workflow_id and e["body"].get("run_id", "") == run
                    and (not outcome.plan_hash or e["body"].get("plan_hash") == outcome.plan_hash)]

        recorded = dict(outcome.checklist)
        # Approved means the tier's quorum of different approvers, as the workflow requires - one signature
        # of two was recorded as approved (fifth review, 2026-10-01).
        plans = ours("remediation.plan")
        tier = plans[-1].get("tier", "") if plans else ""
        approvers = {b.get("approver") for b in ours("approval.accepted")}
        recorded["approved"] = bool(plans) and len(approvers) >= self.policy.required.get(tier, 1)
        recorded["prechecked"] = any(not b.get("problems") for b in ours("remediation.precheck"))
        recorded["applied"] = bool(ours(bounds.APPLIED))
        results = ours(bounds.RESULT)
        recorded["verified"] = bool(results) and results[-1].get("ok") is True
        body = {"workflow_id": workflow_id, "run_id": run, **outcome.model_dump(), "checklist": recorded}
        if recorded != outcome.checklist:
            body["claimed_checklist"] = outcome.checklist
        self.audit.append(incident_id, "workflow.end", body)
        self.audit.checkpoint()


# --------------------------------------------------------------------------- incident


class EvidencePack(BaseModel):
    """What leaves the read side: everything already redacted. The redaction map is not here - it
    stays inside `prepare`, so it never enters Temporal's history."""
    alert: Alert
    context: ContextBundle
    redacted_logs: list[str] = Field(default_factory=list)
    redacted_deploys: list[dict[str, str]] = Field(default_factory=list)
    prompt: str
    masked: int
    steps: list[dict[str, Any]] = Field(default_factory=list)


class Diagnosed(BaseModel):
    root_cause: RootCause
    proposal: RemediationProposal
    cost: CostRecord
    steps: list[dict[str, Any]] = Field(default_factory=list)


class Verified(BaseModel):
    verdict: Verdict
    halted_reason: str | None = None
    steps: list[dict[str, Any]] = Field(default_factory=list)


class IncidentActivities:
    """The diagnosis pipeline (graph.py's nodes, unchanged), split where the trust zones split:
    `prepare` reads and redacts, `diagnose` is the only model call, `verify` has no model."""

    def __init__(self, *, audit: AuditLog, backend: Any = None,
                 llm_factory: Callable[[], Any] | None = None) -> None:
        self.audit, self.backend = audit, backend
        self.llm_factory = llm_factory

    def _record(self, alert_id: str, steps: list[dict[str, Any]]) -> None:
        for step in steps:
            self.audit.append(alert_id, f"incident.{step.get('node', 'step')}", step)

    @activity.defn
    def prepare(self, alert: Alert) -> EvidencePack:
        from . import graph

        state: dict[str, Any] = {"alert": alert, "backend": self.backend}
        steps: list[dict[str, Any]] = []
        for node in (graph.node_ingest, graph.node_gather, graph.node_redact, graph.node_tripwire):
            steps += graph.apply_node(state, node(state))
        prompt = graph._evidence_blob(state)  # built HERE, with the map, which then goes out of scope
        self._record(alert.alert_id, steps)
        return EvidencePack(alert=state["alert"], context=state["context"], prompt=prompt,
                            redacted_logs=state.get("redacted_logs", []),
                            redacted_deploys=state.get("redacted_deploys", []),
                            masked=len(state.get("redaction_map", {})), steps=steps)

    @activity.defn
    def diagnose(self, pack: EvidencePack) -> Diagnosed:
        from . import graph
        from .llm import LLMClient

        llm = (self.llm_factory or LLMClient)()
        state = {"alert": pack.alert, "context": pack.context, "redacted_logs": pack.redacted_logs,
                 "redacted_deploys": pack.redacted_deploys, "prompt": pack.prompt, "llm": llm}
        steps = graph.apply_node(state, graph.node_diagnose(state))
        self._record(pack.alert.alert_id, steps)
        return Diagnosed(root_cause=state["root_cause"], proposal=state["proposal"], cost=llm.cost, steps=steps)

    @activity.defn
    def verify(self, pack: EvidencePack, diagnosed: Diagnosed) -> Verified:
        from . import graph

        state = {"alert": pack.alert, "context": pack.context, "root_cause": diagnosed.root_cause,
                 "proposal": diagnosed.proposal}
        steps = graph.apply_node(state, graph.node_verify(state))
        route = {"halt": graph.node_halt, "escalate": graph.node_escalate,
                 "await_approval": graph.node_await_approval, "record_safe": graph.node_record_safe}
        steps += graph.apply_node(state, route[graph.route_after_verify(state)](state))
        self._record(pack.alert.alert_id, steps)
        self.audit.checkpoint()
        return Verified(verdict=state["verdict"], halted_reason=state.get("halted_reason"), steps=steps)
