"""Typed contracts for every stage of the pipeline.

Everything that crosses a boundary — into the model, out of the model, into the verifier — is a
pydantic model. An LLM returning free text is unverifiable; a model returning a typed object can be
validated, replayed and diffed.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal, get_args

from pydantic import BaseModel, Field, computed_field


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


# The blast-radius scale, narrowest first. Derived from the type the proposal already uses, so the
# allowed values and their ordering cannot drift apart.
BlastRadius = Literal["single_pod", "single_service", "multi_service", "region"]
BLAST_RADIUS_ORDER: tuple[str, ...] = get_args(BlastRadius)


# ⛔ THE GATE'S FACTS ABOUT ITS OWN ACTIONS: (reversible, narrowest honest blast radius).
#
# Reversibility is a property of the OPERATION, not an opinion about an incident — and until
# 2026-09-12 the verifier read it from a field the MODEL wrote. Two live models then reported
# opposite values for the identical operation, so the same action was rejected by P2 in one run and
# merely escalated in another (docs/live-model-run-2026-09-06.md §3). Worse, `mcp_server.py` builds
# a proposal from untrusted caller arguments, so any client could skip P2 by claiming
# `reversible: true`. P2 now reads this table and nothing else.
#
# Deliberately NOT operator-configurable: a config file is only a different author for the same
# field. The blast radius is a FLOOR — a proposal may widen it, because asking for a human is
# always allowed, and can never narrow it.
ACTION_FACTS: dict[ActionKind, tuple[bool, str]] = {
    # The pod comes back; replacing it is the orchestrator's job. Floor is one pod: restarting a
    # whole deployment is a wider form of the same action, and the proposal must say so.
    ActionKind.restart_pods: (True, "single_pod"),
    # Undone by scaling back down. Replica count is a service-level property, never pod-level.
    ActionKind.scale_up: (True, "single_service"),
    # ⚠ NOT reversible, and the contested one. Issuing the opposite command is not an undo: the
    # terminated task's in-flight work, connections and warm caches are gone, and on a constrained
    # cluster the replacement may not schedule at all. Already denied in prod by P1 — but this table
    # must not lie merely because another policy usually gets there first.
    ActionKind.scale_down: (False, "single_service"),
    # A rollback is a forward deploy of a previous revision; the deploy system holds both, and
    # re-deploying the newer one is routine. Calling it irreversible would reject the correct answer
    # for six of Wave 1's fourteen fault classes and leave a gate that is inert rather than safe.
    ActionKind.rollback_deploy: (True, "single_service"),
    # ⛔ The entry that gives P2 teeth. A promoted replica IS the new primary; failing back is a
    # second failover with a stale ex-primary, not an undo. multi_service because every client with
    # a connection string or a cached DNS answer for that endpoint is affected.
    ActionKind.failover_replica: (False, "multi_service"),
    # A cache is reconstructible by definition — that is what makes it a cache. Its real danger is a
    # stampede, which is P7's and P9's business; overloading "reversible" with "risky" would make
    # P2 unreadable.
    ActionKind.clear_cache: (True, "single_service"),
    # Committed data is untouched, an in-flight transaction is rolled back by the database doing
    # exactly what it guarantees, and the pool reconnects. The question P2 asks is whether the
    # SYSTEM returns to its prior state, not whether one connection object survives.
    ActionKind.terminate_connections: (True, "single_service"),
    # Touch nothing. Present so the table is total over ActionKind: a KeyError inside the gate must
    # be impossible.
    ActionKind.no_action: (True, "single_pod"),
    ActionKind.escalate_to_human: (True, "single_pod"),
}


class RemediationProposal(BaseModel):
    """Structured output from the model. Input to the verifier. Never executed directly."""

    action: ActionKind
    target: str
    reasoning: str
    expected_effect: str
    # ⚠ BOTH ADVISORY. The gate does not take these as permission: P2 reads ACTION_FACTS alone, and
    # P6 reads the wider of the table's floor and this claim. A claim can therefore agree with the
    # table or tighten the gate, never loosen it. They stay REQUIRED because the claim is still
    # evidence ABOUT the model — the benchmark's scorer measures how often it contradicts itself
    # about the same action — and because P10 needs the claim to notice a contradiction at all.
    blast_radius: BlastRadius = Field(
        description="Your honest estimate. WARDEN enforces a per-action floor, so understating "
                    "this cannot widen what you are allowed to do."
    )
    reversible: bool = Field(
        description="Your honest estimate. WARDEN decides reversibility from a fixed per-action "
                    "table: claiming an action is reversible does not make it permitted, and "
                    "claiming it is irreversible sends the proposal to a human."
    )

    # ⛔ `computed_field`, not plain properties: these must survive `model_dump_json()`, which is
    # what `warden run --json` writes and what every benchmark artefact is made of. A report that
    # records only the claim cannot show, later, that the gate overruled it. They are
    # serialization-only, so the schema sent to the model is unchanged and nothing asks a model to
    # fill them in.
    @computed_field
    @property
    def table_reversible(self) -> bool:
        """Reversibility as WARDEN classifies the operation. The model's claim is not consulted."""
        return ACTION_FACTS[self.action][0]

    @computed_field
    @property
    def effective_blast_radius(self) -> str:
        """The wider of WARDEN's floor and the model's claim. A proposal may widen, never narrow."""
        floor = ACTION_FACTS[self.action][1]
        return max(floor, self.blast_radius, key=BLAST_RADIUS_ORDER.index)

    @computed_field
    @property
    def claim_contradicts_table(self) -> bool:
        """The model says this cannot be undone while the table says it can. A human reconciles."""
        return self.table_reversible and not self.reversible


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
