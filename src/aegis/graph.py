"""The orchestration graph.

Why a state graph and not a `while` loop: every transition is a named node with typed state, so a
run can be checkpointed, resumed, replayed and audited. When an operator asks "why did it do that?",
the answer is a list of nodes and the state at each one — not a scrollback of prompts.

The shape is deliberately linear with one branch:

    ingest -> redact -> gather -> analyse -> propose -> verify -> route
                                                                  |
                                        halt / await-approval / execute-safe

`redact` sits before anything reaches a model, and `verify` sits after everything a model produced.
Those two nodes are the whole safety argument.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any, TypedDict

from langgraph.graph import END, START, StateGraph

from .llm import LLMClient
from .models import (
    ActionKind,
    Alert,
    ContextBundle,
    RemediationProposal,
    RootCause,
    RunReport,
    Verdict,
    VerdictStatus,
)
from .observability import record_cost, record_model_call, span
from .redaction import redact, redact_many
from .tools import FixtureBackend, gather
from .verifier import verify


def _append(left: list, right: list) -> list:
    return (left or []) + (right or [])


class AegisState(TypedDict, total=False):
    alert: Alert
    context: ContextBundle
    redacted_logs: list[str]
    redaction_map: dict[str, str]
    root_cause: RootCause
    proposal: RemediationProposal
    verdict: Verdict
    audit: Annotated[list[dict[str, Any]], _append]
    halted_reason: str
    llm: LLMClient
    backend: FixtureBackend


# --------------------------------------------------------------------------- mock reasoning
# Deterministic stand-ins so the full graph runs in CI with no key and no network. They read the
# redacted evidence rather than returning a constant, so the eval suite is testing routing and
# policy, not a hardcoded answer.


@dataclass(frozen=True)
class Signals:
    """Facts read off TYPED state — never off the prompt text.

    The first version of these mocks branched on substrings of the rendered prompt, which contains
    field labels like `RECENT DEPLOYS:` and metric keys like `error_rate`. Every incident therefore
    matched the "bad deploy" branch and produced an identical hypothesis. The instrument was asking
    whether a WORD appeared, when the question was whether a DEPLOY EXISTED.
    """

    has_deploy: bool
    error_rate: float
    memory_utilisation: float
    replica_lag: float
    pool_saturated: bool
    service: str
    log_count: int

    @classmethod
    def of(cls, state: AegisState) -> Signals:
        ctx = state["context"]
        m = ctx.metrics
        used, size = m.get("connection_pool_used", 0.0), m.get("connection_pool_size", 0.0)
        return cls(
            has_deploy=bool(ctx.recent_deploys),
            error_rate=m.get("error_rate", 0.0),
            memory_utilisation=m.get("memory_utilisation", 0.0),
            replica_lag=m.get("replica_lag_seconds", 0.0),
            pool_saturated=bool(size) and used >= size,
            service=state["alert"].service,
            log_count=len(ctx.logs),
        )


def _mock_root_cause(s: Signals) -> RootCause:
    if s.has_deploy and s.error_rate > 0.02:
        return RootCause(
            hypothesis="A recent deploy introduced the error spike.",
            confidence=0.82,
            evidence=["error rate rose after the deploy timestamp"],
            ruled_out=["infrastructure saturation"],
        )
    if s.memory_utilisation >= 0.85:
        return RootCause(
            hypothesis="Pods are being OOM-killed under memory pressure.",
            confidence=0.74,
            evidence=[f"memory utilisation at {s.memory_utilisation:.0%} of limit"],
        )
    if s.pool_saturated or s.replica_lag > 10:
        return RootCause(
            hypothesis="Database read replica is saturated and the connection pool is exhausted.",
            confidence=0.68,
            evidence=[f"replica lag {s.replica_lag:.0f}s, pool at capacity"],
        )
    return RootCause(
        hypothesis="Cause not determined from the available evidence.",
        confidence=0.30,
        evidence=[f"only {s.log_count} log line(s) and no decisive metric"],
    )


def _mock_proposal(s: Signals) -> RemediationProposal:
    if s.has_deploy and s.error_rate > 0.02:
        return RemediationProposal(
            action=ActionKind.rollback_deploy,
            target=s.service,
            reasoning="Revert to the last known-good release.",
            expected_effect="Error rate returns to baseline within one minute.",
            blast_radius="single_service",
            reversible=True,
        )
    if s.memory_utilisation >= 0.85:
        return RemediationProposal(
            action=ActionKind.scale_up,
            target=s.service,
            reasoning="Raise the memory limit and add replica headroom.",
            expected_effect="OOM kills stop.",
            blast_radius="single_service",
            reversible=True,
        )
    if s.pool_saturated or s.replica_lag > 10:
        return RemediationProposal(
            action=ActionKind.failover_replica,
            target=f"{s.service}-db",
            reasoning="Fail over to the healthy replica and drain the saturated one.",
            expected_effect="Connection timeouts clear.",
            blast_radius="multi_service",
            reversible=True,
        )
    return RemediationProposal(
        action=ActionKind.escalate_to_human,
        target="oncall",
        reasoning="Evidence is insufficient to justify an automated action.",
        expected_effect="A human takes over with the gathered context.",
        blast_radius="single_pod",
        reversible=True,
    )


SYSTEM_ANALYSE = (
    "You are an incident analyst. You are shown REDACTED evidence: identifiers appear as "
    "<TYPE_n> placeholders. Never ask for the real values. Produce a hypothesis and a calibrated "
    "confidence. If the evidence does not support a conclusion, say so and score confidence low."
)

SYSTEM_PROPOSE = (
    "You propose ONE remediation from the allowed action set. You do not execute anything and you "
    "do not decide whether it is safe — a deterministic verifier does that. State the blast radius "
    "honestly; understating it will cause your proposal to be rejected on audit."
)


# --------------------------------------------------------------------------- nodes


def node_ingest(state: AegisState) -> AegisState:
    alert = state["alert"]
    return {"audit": [{"node": "ingest", "alert_id": alert.alert_id, "env": alert.environment}]}


def node_gather(state: AegisState) -> AegisState:
    backend = state.get("backend") or FixtureBackend()
    context = gather(state["alert"], backend)
    return {
        "context": context,
        "audit": [
            {
                "node": "gather",
                "logs": len(context.logs),
                "metrics": len(context.metrics),
                "deploys": len(context.recent_deploys),
                "tool_errors": context.tool_errors,
            }
        ],
    }


def node_redact(state: AegisState) -> AegisState:
    """Nothing downstream of here sees a real identifier."""
    context = state["context"]
    redacted_logs, mapping = redact_many(context.logs)
    summary = redact(state["alert"].summary, mapping=mapping)
    alert = state["alert"].model_copy(update={"summary": summary.text})
    return {
        "alert": alert,
        "redacted_logs": redacted_logs,
        "redaction_map": summary.mapping,
        "audit": [{"node": "redact", "identifiers_masked": len(summary.mapping)}],
    }


def _evidence_blob(state: AegisState) -> str:
    ctx = state["context"]
    return (
        f"ALERT: {state['alert'].name} — {state['alert'].summary}\n"
        f"SERVICE: {state['alert'].service} ENV: {state['alert'].environment}\n"
        f"METRICS: {ctx.metrics}\n"
        f"RECENT DEPLOYS: {ctx.recent_deploys}\n"
        f"LOGS:\n" + "\n".join(state.get("redacted_logs", []))
    )


def node_analyse(state: AegisState) -> AegisState:
    llm: LLMClient = state["llm"]
    signals = Signals.of(state)
    with span("analyse", has_deploy=signals.has_deploy, log_count=signals.log_count) as sp:
        rc = llm.structured(
            system=SYSTEM_ANALYSE,
            user=_evidence_blob(state),
            schema=RootCause,
            mock_factory=lambda: _mock_root_cause(signals),
        )
        sp.set_attribute("aegis.confidence", rc.confidence)
        record_model_call(sp, operation="chat", provider=llm.provider_name, model=llm.model,
                          input_tokens=llm.cost.input_tokens,
                          output_tokens=llm.cost.output_tokens, usd=llm.cost.usd)
    return {
        "root_cause": rc,
        "audit": [{"node": "analyse", "confidence": rc.confidence, "hypothesis": rc.hypothesis}],
    }


def node_propose(state: AegisState) -> AegisState:
    llm: LLMClient = state["llm"]
    signals = Signals.of(state)
    with span("propose") as sp:
        proposal = llm.structured(
            system=SYSTEM_PROPOSE,
            user=_evidence_blob(state) + f"\n\nHYPOTHESIS: {state['root_cause'].hypothesis}",
            schema=RemediationProposal,
            mock_factory=lambda: _mock_proposal(signals),
        )
        sp.set_attribute("aegis.action", proposal.action.value)
        sp.set_attribute("aegis.blast_radius", proposal.blast_radius)
        record_model_call(sp, operation="chat", provider=llm.provider_name, model=llm.model,
                          input_tokens=llm.cost.input_tokens,
                          output_tokens=llm.cost.output_tokens, usd=llm.cost.usd)
    return {
        "proposal": proposal,
        "audit": [{"node": "propose", "action": proposal.action.value, "target": proposal.target}],
    }


def node_verify(state: AegisState) -> AegisState:
    """No model here. On purpose."""
    with span("verify", environment=state["alert"].environment) as sp:
        verdict = verify(state["alert"], state["context"], state["root_cause"], state["proposal"])
        sp.set_attribute("aegis.verdict", verdict.status.value)
        sp.set_attribute("aegis.policies", ",".join(verdict.policy_ids))
        sp.set_attribute("aegis.requires_approval", verdict.requires_approval)
    return {
        "verdict": verdict,
        "audit": [
            {"node": "verify", "status": verdict.status.value, "policies": verdict.policy_ids}
        ],
    }


def route_after_verify(state: AegisState) -> str:
    """One outbound edge per verdict status. No status may share a route with another.

    An earlier version sent BOTH `approved_for_human` and `auto_safe` to `await_approval`, so an
    inert action carrying `requires_approval=False` still logged that it was waiting on an operator.
    The verdict and the audit trail disagreed, and the audit trail is the thing an auditor reads.
    """
    status = state["verdict"].status
    return {
        VerdictStatus.rejected: "halt",
        VerdictStatus.escalated: "escalate",
        VerdictStatus.auto_safe: "record_safe",
        VerdictStatus.approved_for_human: "await_approval",
    }[status]


def node_halt(state: AegisState) -> AegisState:
    reasons = "; ".join(state["verdict"].reasons)
    return {"halted_reason": reasons, "audit": [{"node": "halt", "reasons": reasons}]}


def node_escalate(state: AegisState) -> AegisState:
    return {"audit": [{"node": "escalate", "to": "oncall"}]}


def node_await_approval(state: AegisState) -> AegisState:
    """Where a real deployment would post to Slack and wait for a click.

    It stops here by design. Nothing in AEGIS executes an action against infrastructure.
    """
    return {"audit": [{"node": "await_approval", "waiting_on": "operator"}]}


def node_record_safe(state: AegisState) -> AegisState:
    """Inert outcome — `no_action`, `escalate_to_human` or `clear_cache`.

    Recorded rather than queued, because nothing here needs a person to approve it.
    """
    return {
        "audit": [
            {"node": "record_safe", "action": state["proposal"].action.value, "approval": "not required"}
        ]
    }


def build_graph():
    g = StateGraph(AegisState)
    g.add_node("ingest", node_ingest)
    g.add_node("gather", node_gather)
    g.add_node("redact", node_redact)
    g.add_node("analyse", node_analyse)
    g.add_node("propose", node_propose)
    g.add_node("verify", node_verify)
    g.add_node("halt", node_halt)
    g.add_node("escalate", node_escalate)
    g.add_node("await_approval", node_await_approval)
    g.add_node("record_safe", node_record_safe)

    g.add_edge(START, "ingest")
    g.add_edge("ingest", "gather")
    g.add_edge("gather", "redact")
    g.add_edge("redact", "analyse")
    g.add_edge("analyse", "propose")
    g.add_edge("propose", "verify")
    g.add_conditional_edges(
        "verify",
        route_after_verify,
        {
            "halt": "halt",
            "escalate": "escalate",
            "await_approval": "await_approval",
            "record_safe": "record_safe",
        },
    )
    g.add_edge("halt", END)
    g.add_edge("escalate", END)
    g.add_edge("await_approval", END)
    g.add_edge("record_safe", END)
    return g.compile()


def run(alert: Alert, *, llm: LLMClient | None = None, backend: FixtureBackend | None = None) -> RunReport:
    llm = llm or LLMClient()
    app = build_graph()
    with span("aegis.run", alert_id=alert.alert_id, service=alert.service,
              environment=alert.environment, severity=alert.severity.value) as root:
        final = app.invoke({"alert": alert, "llm": llm, "backend": backend, "audit": []})
        record_cost(root, input_tokens=llm.cost.input_tokens,
                    output_tokens=llm.cost.output_tokens, usd=llm.cost.usd)
        if final.get("verdict") is not None:
            root.set_attribute("aegis.verdict", final["verdict"].status.value)
    return RunReport(
        alert=final["alert"],
        redaction_map_size=len(final.get("redaction_map", {})),
        context=final.get("context", ContextBundle()),
        root_cause=final.get("root_cause"),
        proposal=final.get("proposal"),
        verdict=final.get("verdict"),
        cost=llm.cost,
        audit=final.get("audit", []),
        halted_reason=final.get("halted_reason"),
    )
