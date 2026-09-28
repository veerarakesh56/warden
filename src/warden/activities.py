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
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import BaseModel, Field
from temporalio import activity

from . import approvals, bounds, catalog
from .audit import AuditLog


class FixRequest(BaseModel):
    incident_id: str
    entry: str
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


class ApprovalResult(BaseModel):
    problems: list[str]
    enough: bool = False


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
                          {"workflow_id": workflow_id, "entry": req.entry, "tier": plan.tier,
                           "params": req.params, "plan_hash": plan.plan_hash, "problems": problems})
        return plan

    @activity.defn
    def gate(self, plan: Plan, service: str) -> list[str]:
        reasons = bounds.blocked(self.audit, service=service, action_class=plan.entry, now=datetime.now(UTC),
                                 limits=self.limits)
        self.audit.append(plan.incident_id, "remediation.gate", {"workflow_id": plan.workflow_id, "blocked": reasons})
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
        self.audit.append(plan.incident_id, kind, {"workflow_id": plan.workflow_id, "approver": approval.approver,
                                                   "nonce": approval.nonce, "problems": problems})
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
                          {"workflow_id": plan.workflow_id, "problems": problems})
        return problems

    @activity.defn
    def apply(self, plan: Plan, service: str) -> str:
        done = [e for e in self.audit.entries(plan.incident_id, kinds=(bounds.APPLIED,))
                if e["body"].get("plan_hash") == plan.plan_hash]
        if done:  # idempotent: a retried activity never applies twice
            return "already applied"
        self.audit.append(plan.incident_id, "remediation.intent", {"workflow_id": plan.workflow_id,
                                                                   "plan_hash": plan.plan_hash})
        detail = self.platform.apply(plan.entry, plan.params)
        bounds.record_applied(self.audit, plan.incident_id, service=service, action_class=plan.entry,
                              plan_hash=plan.plan_hash, detail=detail)
        return detail

    @activity.defn
    def check_success(self, service: str) -> bool:
        return self.platform.healthy(service)

    @activity.defn
    def record_result(self, plan: Plan, service: str, ok: bool) -> None:
        bounds.record_result(self.audit, plan.incident_id, service=service, ok=ok, now=datetime.now(UTC),
                             limits=self.limits)

    @activity.defn
    def rollback(self, plan: Plan) -> str:
        detail = self.platform.rollback(plan.entry, plan.params, plan.snapshot)
        self.audit.append(plan.incident_id, "remediation.rollback", {"workflow_id": plan.workflow_id, "detail": detail})
        return detail

    @activity.defn
    def finish(self, incident_id: str, workflow_id: str, outcome: FixOutcome) -> None:
        self.audit.append(incident_id, "workflow.end", {"workflow_id": workflow_id, **outcome.model_dump()})
        self.audit.checkpoint()
