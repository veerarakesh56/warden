"""Typed contracts for every stage of the pipeline.

Everything that crosses a boundary — into the model, out of the model, into the verifier — is a
pydantic model. An LLM returning free text is unverifiable; a model returning a typed object can be
validated, replayed and diffed.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class Alert(BaseModel):
    """What the monitoring stack hands us. Shape mirrors Prometheus Alertmanager."""

    alert_id: str
    name: str
    severity: Severity
    service: str
    # A free string, resolved against the per-environment policy (environments.py). Not a fixed
    # Literal because the set of environments is a deployment concern an operator configures
    # (staging, qa-staging, pre-prod, qa-prod, prod, ...). An environment the policy doesn't know
    # resolves to the restrictive default and fails closed, so widening this cannot loosen safety.
    environment: str
    summary: str
    started_at: str
    labels: dict[str, str] = Field(default_factory=dict)


class ContextBundle(BaseModel):
    """Evidence gathered by tools. Collected BEFORE the model reasons, never by the model itself."""

    logs: list[str] = Field(default_factory=list)
    metrics: dict[str, float] = Field(default_factory=dict)
    recent_deploys: list[dict[str, str]] = Field(default_factory=list)
    tool_errors: list[str] = Field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.logs or self.metrics or self.recent_deploys)


class RootCause(BaseModel):
    """The model's reading of the evidence. A hypothesis — never a verdict."""

    hypothesis: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    ruled_out: list[str] = Field(default_factory=list)


class ActionKind(str, Enum):
    """The closed set of things WARDEN is allowed to propose.

    Closed on purpose. A model that can invent an action kind can invent `delete_database`.
    """

    restart_pods = "restart_pods"
    scale_up = "scale_up"
    scale_down = "scale_down"
    rollback_deploy = "rollback_deploy"
    failover_replica = "failover_replica"
    clear_cache = "clear_cache"
    # Terminate stuck database connections (idle-in-transaction / over-threshold). The one safe,
    # reversible database write WARDEN performs — kills the connection, never the data. Not auto-safe
    # (touches a running DB); it goes through the full gate like every other real action.
    terminate_connections = "terminate_connections"
    no_action = "no_action"
    escalate_to_human = "escalate_to_human"


class RemediationProposal(BaseModel):
    """Structured output from the model. Input to the verifier. Never executed directly."""

    action: ActionKind
    target: str
    reasoning: str
    expected_effect: str
    blast_radius: Literal["single_pod", "single_service", "multi_service", "region"]
    reversible: bool


class VerdictStatus(str, Enum):
    approved_for_human = "approved_for_human"  # passed policy, still needs a person
    auto_safe = "auto_safe"                    # passed policy and is safe to run unattended
    rejected = "rejected"                      # policy said no
    escalated = "escalated"                    # WARDEN declines to decide


class Verdict(BaseModel):
    """The deterministic verifier's answer. This — not the model — decides what happens."""

    status: VerdictStatus
    reasons: list[str] = Field(default_factory=list)
    policy_ids: list[str] = Field(default_factory=list)
    requires_approval: bool = True


class CostRecord(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    usd: float = 0.0
    calls: int = 0

    def add(self, in_tok: int, out_tok: int, usd: float) -> None:
        self.input_tokens += in_tok
        self.output_tokens += out_tok
        self.usd += usd
        self.calls += 1


class RunReport(BaseModel):
    """Everything a human or an auditor needs to understand one run."""

    alert: Alert
    redaction_map_size: int
    context: ContextBundle
    root_cause: RootCause | None = None
    proposal: RemediationProposal | None = None
    verdict: Verdict | None = None
    cost: CostRecord = Field(default_factory=CostRecord)
    audit: list[dict[str, Any]] = Field(default_factory=list)
    halted_reason: str | None = None
