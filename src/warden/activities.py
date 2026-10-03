"""The activities of the remediation workflow: every step that touches the world or the audit log.

The workflow (workflows.py) is deterministic orchestration only. Everything with a side effect or a
clock is here, and every step writes an audit row.

A `Platform` is how an activity reads and changes one kind of system (Lambda, ECS, Kubernetes, a
database). Phase 2 ships only a fake for tests; the real AWS ones come with the JIT roles in
Phase 4, so no activity here holds a credential yet.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from pydantic import BaseModel, Field, field_validator
from temporalio import activity
from temporalio.exceptions import ApplicationError

from . import approvals, audit, bounds, catalog, environments, freeze
from .audit import AuditLog
from .models import Alert, ContextBundle, CostRecord, RemediationProposal, RootCause, Verdict
from .observability import _safe_error

MAX_APPROVAL_TTL_MINUTES = 240
MAX_RECOVER_WITHIN_MINUTES = 120


class FixRequest(BaseModel):
    incident_id: str
    # A catalogue entry name, never free text: an agent-supplied entry was printed raw by `warden
    # status` (independent review 2026-09-28). The catalogue itself decides whether it exists.
    entry: str = Field(pattern=r"^[a-z][a-z0-9_]{1,60}$")
    params: dict[str, Any]
    # The environment the incident is in. A label anyone sending an alert can write: the target's own
    # environment must match it (P18, register S6), and it is part of the plan hash and the workflow id.
    environment: str
    service: str
    # Bounded (register O3): every verify check is a timer and an activity in the workflow's history, and Temporal
    # caps a history at 50k events / 50 MB. The longest verify window allowed here stays near 2k events.
    approval_ttl_minutes: int = Field(30, ge=1, le=MAX_APPROVAL_TTL_MINUTES)
    recover_within_minutes: int = Field(5, ge=1, le=MAX_RECOVER_WITHIN_MINUTES)

    @field_validator("environment")
    @classmethod
    def _known_environment(cls, v: str) -> str:
        try:
            environments.names(v)
        except environments.EnvironmentPolicyError as exc:
            raise ValueError(str(exc)) from None
        return v


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
    # `<environment>/<catalog.target_key>`: what the bounds and the mutex key on.
    target: str = ""
    environment: str = ""
    # What the plan was made under, in its hash (register O5): the environment, the catalogue, WARDEN's code and
    # the incident's record at that moment.
    basis: dict[str, str] = Field(default_factory=dict)


APPLY_REFUSED = "ApplyRefused"
ROLLBACK_FAILED = "RollbackFailed"


def _run_id() -> str:
    """The Temporal run this activity belongs to. Every remediation row records it, and apply counts only
    rows of its own run: a workflow id (`rem-<env>-<target hash>`) is reused, and a replay of an earlier run's approval and
    results applied a later run nobody approved (third review, 2026-09-30). Empty outside an activity."""
    try:
        return activity.info().workflow_run_id or ""
    except RuntimeError:  # called directly (tests, tools), not by a worker
        return ""


class ApprovalResult(BaseModel):
    problems: list[str]
    enough: bool = False
    # A passkey approval, once verified, recorded in the same shape as a signed one for the quorum.
    accepted: approvals.SignedApproval | None = None


class Recorded(BaseModel):
    """The verdict of a remediation, as WARDEN's own audit shows it, and the run it belongs to."""
    run_id: str
    ok: bool


# Ends that leave the target in a state nobody knows: the kill switch goes on (bounds.trip).
PERSON_TAKES_OVER = frozenset({"rollback_failed", "apply_failed", "cancelled_after_apply", "failed_after_apply"})


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


def plan_hash(entry: str, params: dict[str, Any], snapshot: dict[str, Any], basis: dict[str, str] | None = None) -> str:
    material = json.dumps([entry, params, snapshot, *([basis] if basis else [])], sort_keys=True,
                          separators=(",", ":"), default=str)
    return hashlib.sha256(material.encode()).hexdigest()


def code_version() -> str:
    """WARDEN's own code and policy data, as one hash: a plan is applied only by the code it was made and approved
    under - a worker deployed mid-approval refuses it (register O5)."""
    return audit.code_version()


def _environment_problems(env: str, entry: catalog.Entry, params: dict[str, Any], live: dict[str, Any]) -> list[str]:
    """P18 ENV-MISMATCH (register S6): the incident's environment is a label an alert sender writes. The target's
    OWN environment - its tag or label, as the platform read it - must be that environment, and a name carrying
    another environment's prefix (`warden-prod-orders` for a dev incident) is refused too. Unknown is a mismatch."""
    problems = []
    runtime = environments.default_environment_policies().runtime_environment
    named = {environments.env_of_name(str(params.get(p, ""))) for p in entry.target_params}
    if runtime and runtime in {env, live.get("environment"), *named}:
        # P22 SELF-TARGET (register N7): WARDEN never changes its own components, whatever the approval.
        problems.append(f"P22 SELF-TARGET: the target is in WARDEN's own runtime environment {runtime!r}; a person "
                        "changes it, never WARDEN")
    own = live.get("environment")
    if own != env:
        problems.append(f"P18 ENV-MISMATCH: the target's own environment is {own!r}, not the incident's {env!r}")
    for p in entry.target_params:
        named = environments.env_of_name(str(params.get(p, "")))
        if named and named != env:
            problems.append(f"P18 ENV-MISMATCH: {p} {params.get(p)!r} is named for {named!r}, not {env!r}")
    return problems


def _basis_now(plan: Plan) -> dict[str, str]:
    return {**plan.basis, "catalog": catalog.fingerprint(), "code": code_version()}


class AuditThreads:
    """Which Slack thread each incident has (register H3), kept in the audit so every worker continues the same one:
    a `chatops.thread` row per incident, the latest wins."""

    def __init__(self, audit: AuditLog) -> None:
        self.audit = audit

    def get(self, incident: str, default: str | None = None) -> str | None:
        rows = self.audit.entries(incident, kinds=("chatops.thread",))
        return rows[-1]["body"]["ts"] if rows else default

    def __setitem__(self, incident: str, ts: str) -> None:
        self.audit.append(incident, "chatops.thread", {"ts": ts})


class RemediationActivities:
    def __init__(self, *, audit: AuditLog, policy: approvals.ApproverPolicy, platform: Platform,
                 limits: bounds.Limits = bounds.DEFAULT_LIMITS, changes: Any = None) -> None:
        self.audit, self.policy, self.platform, self.limits = audit, policy, platform, limits
        self.changes = changes  # register O9: where an applied change is recorded (changes.GitHubIssues), if anywhere

    @activity.defn
    def resolve_plan(self, req: FixRequest, workflow_id: str) -> Plan:
        entry = catalog.CATALOG.get(req.entry)
        live = self.platform.live(req.entry, req.params)
        problems = catalog.validate(req.entry, req.params, live)
        target = req.params.get(entry.target_param) if entry else None
        if entry and target != req.service:
            # The health check keys on `service`: it must be what the fix changes (sixth review, 2026-10-01: a
            # scale of `payments` filed under `orders` was judged by `orders`).
            problems.append(f"the fix changes {entry.target_param} {target!r}, not the service {req.service!r} "
                            "its health would be judged by")
        if entry:
            problems += _environment_problems(req.environment, entry, req.params, live)
        snapshot = live.get("state", {})
        basis = {"environment": req.environment, "catalog": catalog.fingerprint(), "code": code_version(),
                 "evidence": self.audit.head(req.incident_id)}
        key = f"{req.environment}/{catalog.target_key(req.entry, req.params)}" if entry else ""
        plan = Plan(workflow_id=workflow_id, incident_id=req.incident_id, entry=req.entry,
                    tier=entry.tier if entry else "", params=req.params, snapshot=snapshot,
                    plan_hash=plan_hash(req.entry, req.params, snapshot, basis), created_at=datetime.now(UTC),
                    problems=problems, target=key, environment=req.environment, basis=basis)
        self.audit.append(req.incident_id, "remediation.plan",
                          {"workflow_id": workflow_id, "run_id": _run_id(), "entry": req.entry, "tier": plan.tier,
                           "environment": req.environment, "service": req.service,  # intake matches alarms on these (C1)
                           "params": req.params, "target": key, "basis": basis, "plan_hash": plan.plan_hash,
                           "problems": problems})
        return plan

    @activity.defn
    def gate(self, plan: Plan, service: str) -> list[str]:
        # The bounds key on the target the plan changes, not on `service` (audit A-B-M4); _not_approved re-checks
        # the target against the plan row before apply.
        reasons = self._blocked(plan)
        # Register H1: approval fatigue. Past this many requests for approval in an hour, a person approving is
        # stamping, not reading - the next plan waits.
        asked = {e["body"].get("workflow_id") for e in self.audit.entries(kinds=("remediation.plan",),
                                                                          since=datetime.now(UTC) - timedelta(hours=1))}
        asked.discard(plan.workflow_id)
        if len(asked) >= MAX_PLANS_PER_HOUR:
            reasons.append(f"H1: {len(asked)} other plans asked for approval in the last hour; the cap is "
                           f"{MAX_PLANS_PER_HOUR} (WARDEN_MAX_PLANS_PER_HOUR)")
        self.audit.append(plan.incident_id, "remediation.gate", {"workflow_id": plan.workflow_id, "run_id": _run_id(),
                                                                  "blocked": reasons})
        return reasons

    @activity.defn
    def announce(self, plan: Plan, what: str) -> list[str]:
        """Tell a person where a plan stands (register H10): `waiting` for an approval, or `expired` with nothing
        changed. Through the outbound gate, with the incident and its audit head (register S17)."""
        from .chatops import notify as send
        from .reporting import Report

        self.audit.checkpoint()
        head = self.audit.head(plan.incident_id)
        said = {"waiting": (f"WARDEN's plan `{plan.entry}` on `{plan.target}` ({plan.tier}) is waiting for an approval: "
                            f"`warden status {plan.workflow_id}`. Unapproved, it expires and nothing is changed."),
                "expired": (f"WARDEN's plan `{plan.entry}` on `{plan.target}` expired without an approval. No action "
                            "was taken; the incident is still open.")}[what]
        footer = (f"\n\n---\nWARDEN · incident `{plan.incident_id}` · audit head `{audit.short(head)}` · check it with "
                  f"`warden audit show {plan.incident_id}`. Approvals are signed out of band, never given in chat.")
        sent = send(Report(markdown=said + footer, data={"alert": {"id": plan.incident_id}}, promotion=()),
                    threads=AuditThreads(self.audit))
        delivered = [n.sink for n in sent if n.delivered]
        self.audit.append(plan.incident_id, "remediation.announce", {"workflow_id": plan.workflow_id,
                                                                     "run_id": _run_id(), "what": what,
                                                                     "head": head, "delivered": delivered})
        return delivered

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
        # Register H1: how long the approver had the plan before signing. Under HASTY_S is recorded as hasty - read
        # by the person who audits approvals, and by the catch trials (G7).
        latency = (approval.issued_at - plan.created_at).total_seconds()
        self.audit.append(plan.incident_id, kind, {"workflow_id": plan.workflow_id, "run_id": _run_id(),
                                                   "latency_s": round(latency, 1), "hasty": latency < HASTY_S,
                                                   "approver": approval.approver,
                                                   "nonce": approval.nonce, "plan_hash": plan.plan_hash,
                                                   # Requirement R50: how many different people this tier needs.
                                                   "required": self.policy.required.get(plan.tier, 1),
                                                   "problems": problems})
        valid = accepted + ([approval] if not problems else [])
        return ApprovalResult(problems=problems, enough=approvals.enough(valid, plan.tier, self.policy))

    @activity.defn
    def check_passkey(self, plan: Plan, assertion: approvals.PasskeyAssertion,
                      accepted: list[approvals.SignedApproval]) -> ApprovalResult:
        """A passkey approval (decision D14, register H6), re-verified here whatever the page that sent it checked:
        the approver may approve this tier, the assertion answers THIS plan's challenge, with their enrolled passkey,
        user-verified, once, unexpired, its counter past every one the audit has seen, and device-bound for T3."""
        from . import passkeys

        now = datetime.now(UTC)
        problems: list[str] = []
        approver = self.policy.approvers.get(assertion.approver)
        if approver is None:
            problems.append(f"{assertion.approver!r} is not an approver")
        elif plan.tier not in approver.tiers:
            problems.append(f"{assertion.approver} may not approve {plan.tier}")
        if (assertion.workflow_id, assertion.plan_hash, assertion.tier) != (plan.workflow_id, plan.plan_hash, plan.tier):
            problems.append("the passkey approval is for a different plan")
        cooling = timedelta(minutes=self.policy.cooling_off_minutes.get(plan.tier, 0))
        if now < plan.created_at + cooling:
            problems.append(f"{plan.tier} needs the plan to exist for {cooling} before it is approved")
        if any(a.approver == assertion.approver for a in accepted):
            problems.append(f"{assertion.approver} has already approved this plan")
        enrolled = next((c for c in (approver.passkeys if approver else [])
                         if c.credential_id == assertion.response.get("id")), None)
        if approver is not None and enrolled is None:
            problems.append(f"the passkey used is not one {assertion.approver} enrolled")
        rp_id = os.environ.get("WARDEN_APPROVAL_RP_ID", "")
        if not rp_id:
            problems.append("no approval domain is configured (WARDEN_APPROVAL_RP_ID)")
        seen = self.audit.entries(kinds=("approval.accepted",))
        verified = None
        if enrolled is not None and rp_id:  # every reason is reported, not only the first
            counts = [e["body"].get("sign_count", 0) for e in seen if e["body"].get("credential_id") == enrolled.credential_id]
            verified, found = passkeys.verify_approval(
                assertion.response, credential=passkeys.Credential(
                    assertion.approver, enrolled.credential_id, enrolled.public_key,
                    max([enrolled.sign_count, *counts]), enrolled.device_bound),
                pending=passkeys.Pending(plan.workflow_id, plan.plan_hash, plan.tier, assertion.nonce,
                                         assertion.expires_at, assertion.challenge),
                rp_id=rp_id, origin=f"https://{rp_id}", now=now, used_nonces={e["body"]["nonce"] for e in seen})
            problems += found
        latency = (now - plan.created_at).total_seconds()
        self.audit.append(plan.incident_id, "approval.refused" if problems else "approval.accepted", {
            "workflow_id": plan.workflow_id, "run_id": _run_id(), "method": "passkey", "latency_s": round(latency, 1),
            "hasty": latency < HASTY_S, "approver": assertion.approver, "nonce": assertion.nonce,
            "plan_hash": plan.plan_hash, "required": self.policy.required.get(plan.tier, 1),
            "credential_id": enrolled.credential_id if enrolled else "",
            "sign_count": verified.new_sign_count if verified else None, "problems": problems})
        if problems:
            return ApprovalResult(problems=problems)
        record = approvals.SignedApproval(approver=assertion.approver, workflow_id=plan.workflow_id,
                                          plan_hash=plan.plan_hash, tier=plan.tier, issued_at=now,
                                          expires_at=assertion.expires_at, nonce=assertion.nonce,
                                          signature=f"passkey:{enrolled.credential_id}")
        return ApprovalResult(problems=[], accepted=record,
                              enough=approvals.enough([*accepted, record], plan.tier, self.policy))

    @activity.defn
    def precheck(self, plan: Plan) -> list[str]:
        """Read live state again right before acting: a plan approved against a state that no longer
        exists is not the plan that was approved."""
        live = self.platform.live(plan.entry, plan.params)
        problems = catalog.validate(plan.entry, plan.params, live)
        if _basis_now(plan) != plan.basis:
            problems.append("WARDEN's code or catalogue changed after the plan was made; it needs a new plan")
        elif plan_hash(plan.entry, plan.params, live.get("state", {}), plan.basis) != plan.plan_hash:
            problems.append("the target changed after the plan was made; it needs a new plan")
        if entry := catalog.CATALOG.get(plan.entry):
            problems += _environment_problems(plan.environment, entry, plan.params, live)
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
                or made[-1].get("params") != plan.params or made[-1].get("target") != plan.target
                or made[-1].get("basis") != plan.basis):
            return ["no such plan was made for this workflow run"]
        if _basis_now(plan) != plan.basis:  # a worker deployed after the precheck (register O5)
            return ["WARDEN's code or catalogue changed after the plan was made"]
        approved = rows("approval.accepted")
        need = self.policy.required.get(made[-1].get("tier", ""), 1)
        if len({e["body"].get("approver") for e in approved}) < need:
            return [f"{len({e['body'].get('approver') for e in approved})} of {need} approval(s) recorded for this plan"]
        last_approval = max(e["seq"] for e in approved)
        checks = [e for e in rows("remediation.precheck") if e["seq"] > last_approval]
        if not checks or checks[-1]["body"].get("problems"):
            return ["no clean precheck of this plan after its approval"]
        return self._blocked(plan)

    def _blocked(self, plan: Plan) -> list[str]:
        """The kill switch, the bounds and the change freezes (register C6, P19), at the gate and again right
        before apply: a freeze that starts while a plan waits for its approval still holds."""
        now = datetime.now(UTC)
        return (bounds.blocked(self.audit, service=plan.target, action_class=plan.entry, now=now, limits=self.limits)
                + freeze.active(plan.environment, now))

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
        try:
            # The approved snapshot goes to a platform that can hold the write to it (sixth review: a count that
            # moved after the precheck was stepped from).
            if "snapshot" in inspect.signature(self.platform.apply).parameters:
                detail = self.platform.apply(plan.entry, plan.params, snapshot=plan.snapshot)
            else:
                detail = self.platform.apply(plan.entry, plan.params)
        except Exception as exc:
            if not getattr(exc, "nothing_changed", False):
                raise  # the change may be half-made: the workflow says so, and a person decides
            why = f"the platform refused before changing anything: {_safe_error(exc)}"
            self.audit.append(plan.incident_id, "remediation.refused", {"workflow_id": plan.workflow_id,
                                                                       "run_id": run, "plan_hash": plan.plan_hash,
                                                                       "why": [why]})
            raise ApplicationError(f"apply refused: {why}", type=APPLY_REFUSED, non_retryable=True) from None
        bounds.record_applied(self.audit, plan.incident_id, service=plan.target, action_class=plan.entry,
                              plan_hash=plan.plan_hash, detail=detail, workflow_id=plan.workflow_id, run_id=run)
        return detail

    @activity.defn
    def check_success(self, plan: Plan, service: str) -> bool:
        # Asked of the platform that made the change, when it can route by entry: a database of the same name
        # must not judge a Deployment (sixth review).
        routed = getattr(self.platform, "healthy_for", None)
        healthy = bool(routed(plan.entry, service) if routed else self.platform.healthy(service))
        # Every real check is on the record with its run: the verdict is taken from these rows, never from
        # what an activity result or the workflow claims (fourth review, 2026-09-30: run 1's "healthy"
        # replayed into run 2 marked a fix verified with no health check made).
        self.audit.append(plan.incident_id, "remediation.check",
                          {"workflow_id": plan.workflow_id, "run_id": _run_id(), "plan_hash": plan.plan_hash,
                           "healthy": healthy})
        return healthy

    @activity.defn
    def record_result(self, plan: Plan, service: str, ok: bool, consecutive: int = 1) -> Recorded:
        run = _run_id()
        checks = [e["body"] for e in self.audit.entries(plan.incident_id, kinds=("remediation.check",))
                  if e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("run_id", "") == run
                  and e["body"].get("plan_hash") == plan.plan_hash]
        # Verified only if THIS run applied the plan: a replayed apply result let a run with nothing applied
        # end "recovered" and write a success row (fifth review, 2026-10-01).
        applied = any(e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("run_id", "") == run
                      and e["body"].get("plan_hash") == plan.plan_hash
                      for e in self.audit.entries(plan.incident_id, kinds=(bounds.APPLIED,)))
        # The last `consecutive` checks of this run, all healthy (register C18a): one good reading is not recovery.
        need = max(1, int(consecutive))
        verified = applied and len(checks) >= need and all(c.get("healthy") is True for c in checks[-need:])
        if verified != ok:
            self.audit.append(plan.incident_id, "remediation.result_mismatch",
                              {"workflow_id": plan.workflow_id, "run_id": run, "claimed": ok, "recorded": verified})
        bounds.record_result(self.audit, plan.incident_id, service=plan.target, ok=verified, now=datetime.now(UTC),
                             limits=self.limits, workflow_id=plan.workflow_id, run_id=run,
                             plan_hash=plan.plan_hash)
        return Recorded(run_id=run, ok=verified)

    @activity.defn
    def rollback(self, plan: Plan) -> str:
        run = _run_id()
        row = {"workflow_id": plan.workflow_id, "run_id": run, "plan_hash": plan.plan_hash}
        # Only what THIS run applied is undone: after a replayed apply result, a run that changed nothing
        # rolled the target back anyway (sixth review, 2026-10-01).
        if not any(e["body"].get("workflow_id") == plan.workflow_id and e["body"].get("run_id", "") == run
                   and e["body"].get("plan_hash") == plan.plan_hash
                   for e in self.audit.entries(plan.incident_id, kinds=(bounds.APPLIED,))):
            detail = "nothing to roll back: this run applied nothing"
            self.audit.append(plan.incident_id, "remediation.rollback", {**row, "detail": detail})
            return detail
        try:
            detail = self.platform.rollback(plan.entry, plan.params, plan.snapshot)
        except Exception as exc:  # noqa: BLE001 - every failure is the same fact: WARDEN's change may still be there
            reason = f"rollback failed: {_safe_error(exc)}"
            self.audit.append(plan.incident_id, "remediation.rollback_failed", {**row, "why": reason})
            # A change WARDEN made may still be in place: no further fix runs until a person resets the switch.
            bounds.trip(self.audit, plan.incident_id, reason, workflow_id=plan.workflow_id, run_id=_run_id())
            raise ApplicationError(reason, type=ROLLBACK_FAILED, non_retryable=True) from None
        self.audit.append(plan.incident_id, "remediation.rollback", {**row, "detail": detail})
        return detail

    @activity.defn
    def finish(self, incident_id: str, workflow_id: str, outcome: FixOutcome) -> None:
        # The signed end row states what THIS run's audit rows show, not what the workflow claims (fourth
        # review: a refused apply was recorded with approved and prechecked True).
        run = _run_id()
        # Once per run: Temporal retries this activity when a step after the end row fails, and a second end row
        # was written (eighth review, 2026-10-01).
        if run and any(e["body"].get("workflow_id") == workflow_id and e["body"].get("run_id") == run
                       for e in self.audit.entries(incident_id, kinds=("workflow.end",))):
            # Signed even when this try only finds the row: the try that wrote it may have failed before its
            # checkpoint (register R9-O4), and the end of a run must not stay unsigned.
            self.audit.checkpoint()
            return

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
        body = {"workflow_id": workflow_id, "run_id": run, **outcome.model_dump(), "checklist": recorded,
                # Requirement R50: who approved, how many the tier required, and - said, not implied - whether one
                # person alone decided this change.
                "approvers": sorted(a for a in approvers if a), "required": self.policy.required.get(tier, 1),
                "single_approver": recorded["approved"] and len(approvers) == 1}
        if recorded != outcome.checklist:
            body["claimed_checklist"] = outcome.checklist
        # A run that leaves a target in an unknown state stops every automatic fix until a person resets the
        # switch - whatever ended it. Only the rollback activity's own failure tripped it: a rollback past its
        # timeout, or on a worker that died, ended rollback_failed with the switch off (seventh review, 2026-10-01).
        # Before the end row, and once per run: the rollback may have tripped it already.
        if outcome.status in PERSON_TAKES_OVER and not any(
                t["body"].get("workflow_id") == workflow_id and t["body"].get("run_id") == run
                for t in bounds.trips(self.audit)):
            bounds.trip(self.audit, incident_id, f"{workflow_id} ended {outcome.status}: {'; '.join(outcome.reasons)}",
                        workflow_id=workflow_id, run_id=run)
        self.audit.append(incident_id, "workflow.end", body)
        self.audit.checkpoint()
        if recorded["applied"] and self.changes is not None and plans:
            # Register O9: a change to a live system is recorded where the team looks for changes - once per run,
            # after the signed end row it cites. A record that could not be written is itself recorded.
            from .changes import issue_text

            title, text = issue_text(incident_id=incident_id, end=body, plan=plans[-1],
                                     head=self.audit.head(incident_id), at=datetime.now(UTC))
            url, detail = self.changes.open(title, text)
            self.audit.append(incident_id, "change.recorded", {"workflow_id": workflow_id, "run_id": run,
                                                               "url": url, "detail": detail})
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
    model_unavailable: str = ""  # why the model was not used: verify then escalates (register M19)


# A cap across incidents (registers M18, A-P-4): a storm of incidents, each within its own budget, still spent without
# end. Counted from the audit over the last 24 hours, reservations of unfinished calls included.
MAX_PLANS_PER_HOUR = int(os.environ.get("WARDEN_MAX_PLANS_PER_HOUR", "6"))
HASTY_S = 10.0  # an approval signed this soon after the plan was made was not read (register H1)
DAILY_MAX_USD = float(os.environ.get("WARDEN_DAILY_MAX_USD", "10.00"))
DAILY_MAX_TOKENS = int(os.environ.get("WARDEN_DAILY_MAX_TOKENS", "2000000"))


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
    def diagnose(self, pack: EvidencePack, escalate_only: str = "") -> Diagnosed:
        from . import graph
        from .llm import LLMClient

        llm = (self.llm_factory or LLMClient)()
        # One budget per incident, across its runs. A FAILED run may run again (ALLOW_DUPLICATE_FAILED_ONLY) - also
        # one that failed because it spent its budget - and each run built a fresh client: five restarts spent
        # $3.00 against a $0.50 cap (seventh review, 2026-10-01). Every run records what it spent, failed or not,
        # and the next one's client starts from the incident's total, so the USD and call ceilings hold. What
        # carries is what may have been billed: answered and timed-out calls, not requests that reached no model -
        # carrying those let a provider outage use up the ceiling and lock the incident (eighth review).
        before = self._spent(pack.alert.alert_id)
        llm.cost = before.model_copy()
        today = self._spent_since(datetime.now(UTC) - timedelta(hours=24))
        over = (today.usd + max(llm.max_usd - before.usd, 0.0) > DAILY_MAX_USD
                or today.input_tokens + today.output_tokens >= DAILY_MAX_TOKENS)
        if over or escalate_only:
            reason = escalate_only or (f"the daily model cap is reached (${today.usd:.2f} of ${DAILY_MAX_USD:.2f}, "
                                       f"{today.input_tokens + today.output_tokens} of {DAILY_MAX_TOKENS} tokens in 24 h)")
            state = {"alert": pack.alert, "context": pack.context, "llm": llm, "model_unavailable": reason}
            steps = graph.apply_node(state, graph.node_diagnose(state))
            self._record(pack.alert.alert_id, steps)
            return Diagnosed(root_cause=state["root_cause"], proposal=state["proposal"], cost=llm.cost, steps=steps,
                             model_unavailable=reason)
        # Reserved BEFORE the call (register R8-O1): what is left of the incident's budget, under an id that this
        # run's spend row settles. A run cancelled, terminated or killed mid-call wrote its spend late or never, and
        # the next run started as if nothing had been spent. Now an unsettled reservation counts as spent: the next
        # run of a killed one has no budget left, and the incident goes to a person - not to a second paid call.
        attempt = secrets.token_hex(8)
        self.audit.append(pack.alert.alert_id, "incident.llm_reserve", {
            "run_id": _run_id(), "attempt": attempt, "usd": max(llm.max_usd - before.usd, 0.0),
            "calls": max(llm.max_calls - before.calls, 0)})
        try:
            state = {"alert": pack.alert, "context": pack.context, "redacted_logs": pack.redacted_logs,
                     "redacted_deploys": pack.redacted_deploys, "prompt": pack.prompt, "llm": llm}
            steps = graph.apply_node(state, graph.node_diagnose(state))
        finally:
            now, unanswered = llm.cost, int(getattr(llm, "unanswered", 0) or 0)
            self.audit.append(pack.alert.alert_id, "incident.llm_spend", {
                "run_id": _run_id(), "attempt": attempt, "usd": now.usd - before.usd, "calls": now.calls - before.calls - unanswered,
                "unanswered": unanswered, "input_tokens": now.input_tokens - before.input_tokens,
                "output_tokens": now.output_tokens - before.output_tokens})
        self._record(pack.alert.alert_id, steps)
        return Diagnosed(root_cause=state["root_cause"], proposal=state["proposal"], cost=llm.cost, steps=steps,
                         model_unavailable=state.get("model_unavailable", ""))

    def _spent_since(self, since: datetime) -> CostRecord:
        """What every incident spent on the model since `since`, reservations of unfinished calls included."""
        total = CostRecord()
        spent = self.audit.entries(kinds=("incident.llm_spend",), since=since)
        for e in spent:
            b = e["body"]
            total.input_tokens += int(b.get("input_tokens", 0))
            total.output_tokens += int(b.get("output_tokens", 0))
            total.usd += float(b.get("usd", 0.0))
        settled = {e["body"].get("attempt") for e in self.audit.entries(kinds=("incident.llm_spend",))}
        for e in self.audit.entries(kinds=("incident.llm_reserve",), since=since):
            if e["body"].get("attempt") not in settled:
                total.usd += float(e["body"].get("usd", 0.0))
        return total

    def _spent(self, alert_id: str) -> CostRecord:
        """What every earlier run of this incident spent on the model, from the audit - and, for a run whose spend
        was never written (killed mid-call), everything it had reserved."""
        total = CostRecord()
        spent = self.audit.entries(alert_id, kinds=("incident.llm_spend",))
        for e in spent:
            b = e["body"]
            total.input_tokens += int(b.get("input_tokens", 0))
            total.output_tokens += int(b.get("output_tokens", 0))
            total.usd += float(b.get("usd", 0.0))
            total.calls += int(b.get("calls", 0))
        settled = {e["body"].get("attempt") for e in spent}
        for e in self.audit.entries(alert_id, kinds=("incident.llm_reserve",)):
            if e["body"].get("attempt") not in settled:
                total.usd += float(e["body"].get("usd", 0.0))
                total.calls += int(e["body"].get("calls", 0))
        return total

    @activity.defn
    def notify(self, pack: EvidencePack, diagnosed: Diagnosed, verified: Verified) -> list[str]:
        """The incident's report to the configured sinks, through the outbound gate (register S17). Its footer names
        the incident and the head of its audit record - signed first - so a reader can check that a message claiming
        to be WARDEN's is one: `warden audit show <incident>` lists the same hash. Returns the sinks it reached."""
        import dataclasses

        from .chatops import notify as send
        from .reporting import build_report

        alert_id = pack.alert.alert_id
        self.audit.checkpoint()
        head = self.audit.head(alert_id)
        report = build_report(pack.alert, root_cause=diagnosed.root_cause, proposal=diagnosed.proposal,
                              verdict=verified.verdict, context=pack.context, show_identifiers=False)
        footer = (f"\n\n---\nWARDEN · incident `{alert_id}` · audit head `{audit.short(head)}` · check it with "
                  f"`warden audit show {alert_id}`. WARDEN never asks for an approval in chat: approvals are signed "
                  "out of band.")
        sent = send(dataclasses.replace(report, markdown=report.markdown + footer), threads=AuditThreads(self.audit))
        self.audit.append(alert_id, "incident.notify", {"run_id": _run_id(), "head": head,
                                                        "sinks": [n.sink for n in sent],
                                                        "delivered": [n.sink for n in sent if n.delivered]})
        return [n.sink for n in sent if n.delivered]

    @activity.defn
    def verify(self, pack: EvidencePack, diagnosed: Diagnosed) -> Verified:
        from . import graph

        state = {"alert": pack.alert, "context": pack.context, "root_cause": diagnosed.root_cause,
                 "proposal": diagnosed.proposal, "model_unavailable": diagnosed.model_unavailable}
        steps = graph.apply_node(state, graph.node_verify(state))
        route = {"halt": graph.node_halt, "escalate": graph.node_escalate,
                 "await_approval": graph.node_await_approval, "record_safe": graph.node_record_safe}
        steps += graph.apply_node(state, route[graph.route_after_verify(state)](state))
        self._record(pack.alert.alert_id, steps)
        self.audit.checkpoint()
        return Verified(verdict=state["verdict"], halted_reason=state.get("halted_reason"), steps=steps)
