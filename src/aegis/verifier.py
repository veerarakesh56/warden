"""The deterministic gate. This is what decides — the model only ever proposes.

Every rule here is plain Python over typed data. No model call, no probability, no prompt. That is
the point: if the reasoning layer is stochastic, the deciding layer must not be, or the system has
no floor. Each rule returns a policy id so a rejection can be explained to an auditor without
re-running anything.
"""

from __future__ import annotations

from .models import (
    ActionKind,
    Alert,
    ContextBundle,
    RemediationProposal,
    RootCause,
    Verdict,
    VerdictStatus,
)

# Actions that may ever run without a human, and only when every other policy also passes.
AUTO_SAFE_ACTIONS = {ActionKind.no_action, ActionKind.escalate_to_human, ActionKind.clear_cache}

# Per-environment allow-list. Production is deliberately narrower than staging.
ENV_ALLOWED: dict[str, set[ActionKind]] = {
    "prod": {
        ActionKind.restart_pods,
        ActionKind.scale_up,
        ActionKind.rollback_deploy,
        ActionKind.failover_replica,
        ActionKind.clear_cache,
        ActionKind.no_action,
        ActionKind.escalate_to_human,
    },
    "staging": set(ActionKind),
    "dev": set(ActionKind),
}

MIN_CONFIDENCE = 0.55

# Thresholds for P9. Deliberately modest — this is a floor for "somebody looked at something",
# not a quality bar. Tune per deployment; the point is that it is OUR number, not the model's.
MIN_LOG_LINES = 3
MIN_METRICS = 2


def _evidence_is_substantial(context) -> bool:
    """Is there enough gathered evidence to justify touching production?

    Counted, not asked. A model reporting high confidence over two log lines is the exact failure
    this exists to catch, and it was observed on a live model, not hypothesised.
    """
    has_logs = len(context.logs) >= MIN_LOG_LINES
    has_metrics = len(context.metrics) >= MIN_METRICS
    has_deploys = bool(context.recent_deploys)
    # Two independent kinds of evidence, or a deploy plus one other kind.
    return sum([has_logs, has_metrics, has_deploys]) >= 2


def verify(
    alert: Alert,
    context: ContextBundle,
    root_cause: RootCause,
    proposal: RemediationProposal,
) -> Verdict:
    """Return the binding decision for one proposal."""
    reasons: list[str] = []
    policies: list[str] = []
    rejected = False
    escalate = False

    # P1 — the action must be permitted in this environment at all.
    allowed = ENV_ALLOWED.get(alert.environment, set())
    if proposal.action not in allowed:
        rejected = True
        policies.append("P1-ENV-ALLOWLIST")
        reasons.append(
            f"{proposal.action.value} is not permitted in {alert.environment}."
        )

    # P2 — nothing irreversible in production, ever, regardless of confidence.
    if alert.environment == "prod" and not proposal.reversible:
        rejected = True
        policies.append("P2-IRREVERSIBLE-IN-PROD")
        reasons.append("Irreversible action proposed against production.")

    # P3 — evidence is a precondition for action, not an optional extra.
    if context.is_empty() and proposal.action not in AUTO_SAFE_ACTIONS:
        rejected = True
        policies.append("P3-NO-EVIDENCE")
        reasons.append("No logs, metrics or deploy history were gathered; refusing to act blind.")

    # P4 — a low-confidence hypothesis is a question, not a plan.
    if root_cause.confidence < MIN_CONFIDENCE and proposal.action not in AUTO_SAFE_ACTIONS:
        escalate = True
        policies.append("P4-LOW-CONFIDENCE")
        reasons.append(
            f"Confidence {root_cause.confidence:.2f} is below the {MIN_CONFIDENCE} threshold."
        )

    # P5 — you cannot roll back a deploy that the evidence does not show.
    if proposal.action is ActionKind.rollback_deploy and not context.recent_deploys:
        rejected = True
        policies.append("P5-NO-DEPLOY-TO-ROLL-BACK")
        reasons.append("Rollback proposed but no recent deploy appears in the gathered context.")

    # P6 — wide blast radius is always a human's call.
    if proposal.blast_radius in ("multi_service", "region"):
        escalate = True
        policies.append("P6-BLAST-RADIUS")
        reasons.append(f"Blast radius '{proposal.blast_radius}' exceeds the unattended limit.")

    # P7 — proportionality. Don't fail over a database because something is 'low'.
    heavy = {ActionKind.failover_replica, ActionKind.rollback_deploy}
    if proposal.action in heavy and alert.severity.value in ("low", "medium"):
        escalate = True
        policies.append("P7-DISPROPORTIONATE")
        reasons.append(
            f"{proposal.action.value} is disproportionate to a {alert.severity.value} alert."
        )

    # P8 — a tool failing means the picture is partial. Say so rather than pretending.
    if context.tool_errors and proposal.action not in AUTO_SAFE_ACTIONS:
        escalate = True
        policies.append("P8-PARTIAL-CONTEXT")
        reasons.append(f"{len(context.tool_errors)} context tool(s) failed; evidence is incomplete.")

    # P9 — evidence measured by US, not confidence reported by the model.
    #
    # Added after running against a live model: it returned confidence 0.85 on ALL FOUR bundled
    # incidents, including the one whose entire evidence is two vague log lines. A model's
    # self-reported confidence is not calibrated, so P4 alone would essentially never fire — the
    # gate would be relying on a number the model has no incentive or ability to get right.
    #
    # This counts what was actually gathered. It cannot be talked around by a confident tone.
    if proposal.action not in AUTO_SAFE_ACTIONS and not _evidence_is_substantial(context):
        escalate = True
        policies.append("P9-THIN-EVIDENCE")
        reasons.append(
            f"Evidence is thin ({len(context.logs)} log line(s), {len(context.metrics)} metric(s), "
            f"{len(context.recent_deploys)} deploy(s)); a human should look before acting."
        )

    if rejected:
        return Verdict(
            status=VerdictStatus.rejected,
            reasons=reasons,
            policy_ids=policies,
            requires_approval=True,
        )
    if escalate:
        return Verdict(
            status=VerdictStatus.escalated,
            reasons=reasons or ["Escalated for human judgement."],
            policy_ids=policies,
            requires_approval=True,
        )
    if proposal.action in AUTO_SAFE_ACTIONS:
        return Verdict(
            status=VerdictStatus.auto_safe,
            reasons=["Action is inert or advisory; no approval required."],
            policy_ids=policies,
            requires_approval=False,
        )
    return Verdict(
        status=VerdictStatus.approved_for_human,
        reasons=["Passed all policies. Held for operator approval before execution."],
        policy_ids=policies,
        requires_approval=True,
    )
