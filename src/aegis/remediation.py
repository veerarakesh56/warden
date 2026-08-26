"""Deciding whether an approved fix may actually be APPLIED — and, in the low environments, applying it.

The verifier decides whether an action is *admissible*. This layer decides whether it may be
*executed*, here, now, by this principal — the four-way gate the owner asked for:

    auto-remediate  x  authorised principal  x  explicit approval  x  a live backend

Only when all four hold does anything touch infrastructure, and even then only through a pluggable
`RemediationBackend`. The one this repo ships is `DryRunBackend`, which changes nothing and records
what it *would* do. That keeps AEGIS's core promise intact — this codebase never mutates a cluster —
while making the execution path real and testable. An operator wanting genuine remediation supplies
their own backend (kubectl/cloud SDK); the gate above it is the same either way.

The environment gradient (from environments.yaml) does the heavy lifting:
  - staging / qa-staging : auto_remediate = true  -> with an authorised approval, AEGIS applies.
  - pre-prod / qa-prod / prod / unknown : auto_remediate = false -> AEGIS never applies; a human does.
"""

from __future__ import annotations

from enum import Enum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel

from .environments import EnvironmentPolicies, default_environment_policies
from .models import ActionKind, Alert, RemediationProposal, Verdict, VerdictStatus


class RemediationOutcome(str, Enum):
    applied = "applied"                     # a live backend actually made the change
    dry_run = "dry_run"                     # all gates passed; the shipped backend only simulates
    awaiting_approval = "awaiting_approval"  # auto-remediable, authorised, but nobody approved yet
    unauthorized = "unauthorized"            # the principal may not act in this environment
    not_auto_remediable = "not_auto_remediable"  # this env never auto-applies; a human must
    blocked = "blocked"                      # the verdict was not approvable in the first place
    failed = "failed"                        # every gate passed, but the backend errored while acting


class RemediationError(RuntimeError):
    """A remediation backend could not carry out (or refused) an action. Caught by the gate and
    turned into a `failed` result — a backend fault must never crash the pipeline."""


class RemediationRequest(BaseModel):
    """Who is asking to apply the fix, and whether an authorised person approved it."""

    principal: str | None = None
    approved: bool = False
    reason: str = ""


class RemediationResult(BaseModel):
    outcome: RemediationOutcome
    action: ActionKind
    target: str
    environment: str
    principal: str | None = None
    detail: str = ""
    applied_change: str | None = None   # what the backend reports it did (dry-run or real)

    @property
    def changed_infrastructure(self) -> bool:
        return self.outcome is RemediationOutcome.applied


@runtime_checkable
class RemediationBackend(Protocol):
    """A thing that can carry out an action. `live` is the honesty flag: False means it only
    simulates (nothing is touched), True means it really acts. The gate treats them differently."""

    live: bool

    def apply(self, action: ActionKind, target: str, environment: str) -> str:
        """Perform (or simulate) the action; return a human-readable description of what happened."""
        ...


class DryRunBackend:
    """The default. Touches nothing; reports what a real backend would have done. AEGIS's core
    guarantee — this codebase does not execute against infrastructure — lives here."""

    live = False

    def apply(self, action: ActionKind, target: str, environment: str) -> str:
        return f"DRY RUN: would {action.value} '{target}' in {environment} (no change made)"


# States a verdict can be in that mean "this proposal is a candidate to apply". Anything else
# (rejected, escalated) short-circuits to `blocked`. auto_safe means the action is inert
# (no_action/escalate) — there is nothing to remediate, so it is blocked here too.
_APPROVABLE = {VerdictStatus.approved_for_human}


def decide_remediation(
    alert: Alert,
    proposal: RemediationProposal,
    verdict: Verdict,
    request: RemediationRequest,
    *,
    policies: EnvironmentPolicies | None = None,
    backend: RemediationBackend | None = None,
) -> RemediationResult:
    """The whole gate, in order. Returns what happened (or why nothing did). Never raises for a
    policy decision — a refusal is a result, not an error."""
    env_policies = policies or default_environment_policies()
    env = env_policies.for_env(alert.environment)
    action = proposal.action
    target = proposal.target

    def result(outcome: RemediationOutcome, detail: str, change: str | None = None) -> RemediationResult:
        return RemediationResult(
            outcome=outcome,
            action=action,
            target=target,
            environment=alert.environment,
            principal=request.principal,
            detail=detail,
            applied_change=change,
        )

    # 1. The verdict must have cleared policy. A rejected/escalated/auto_safe verdict is not applied.
    if verdict.status not in _APPROVABLE:
        return result(
            RemediationOutcome.blocked,
            f"verdict is {verdict.status.value}; only an approved_for_human proposal can be applied",
        )

    # 2. Defence in depth: the environment must still permit the action (the verifier checked this,
    #    but the executor must not trust that the two were run against the same config).
    if not env.permits(action):
        return result(
            RemediationOutcome.blocked,
            f"{action.value} is not permitted in {alert.environment} by the environment policy",
        )

    # 3. The principal must be authorised to act in this environment.
    if not env.authorizes(request.principal):
        who = request.principal or "<no principal>"
        return result(
            RemediationOutcome.unauthorized,
            f"principal '{who}' is not authorised to remediate in {alert.environment}",
        )

    # 4. This environment must be one AEGIS may auto-apply in at all. pre-prod/qa-prod/prod/unknown
    #    are not — the fix is handed to a human, who applies it with the report as the runbook.
    if not env.auto_remediate:
        return result(
            RemediationOutcome.not_auto_remediable,
            f"{alert.environment} does not auto-remediate; a human applies this fix (see report)",
        )

    # 5. Even in an auto-remediable environment, an explicit approval from the authorised principal
    #    is required — AEGIS never applies a change nobody signed off.
    if not request.approved:
        return result(
            RemediationOutcome.awaiting_approval,
            f"{action.value} on '{target}' is ready to apply in {alert.environment}; "
            f"awaiting approval from an authorised principal",
        )

    # 6. All gates passed. Apply through the backend. The shipped DryRunBackend changes nothing.
    #    A live backend that errors (an API 403, a missing deployment, an unsupported action) must
    #    not crash the run — it becomes a `failed` result carrying the reason.
    exec_backend = backend or DryRunBackend()
    try:
        change = exec_backend.apply(action, target, alert.environment)
    except Exception as exc:  # noqa: BLE001 - a backend fault is a result, not a crash
        return result(RemediationOutcome.failed, f"backend error: {exc}")
    outcome = RemediationOutcome.applied if exec_backend.live else RemediationOutcome.dry_run
    return result(outcome, f"applied by '{request.principal}' after approval", change)
