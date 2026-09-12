"""The deterministic gate. This is what decides — the model only ever proposes.

Every rule here is plain Python over typed data. No model call, no probability, no prompt. That is
the point: if the reasoning layer is stochastic, the deciding layer must not be, or the system has
no floor. Each rule returns a policy id so a rejection can be explained to an auditor without
re-running anything.
"""

from __future__ import annotations

from .environments import EnvironmentPolicies, default_environment_policies
from .models import (
    ACTION_FACTS,
    ActionKind,
    Alert,
    ContextBundle,
    RemediationProposal,
    RootCause,
    Verdict,
    VerdictStatus,
)

# Actions genuinely inert enough to skip human approval. Deliberately only the two that CANNOT
# touch running infrastructure: doing nothing, and handing off to a person. `clear_cache` was here
# and was removed - flushing a production cache can cause a stampede/latency spike, so it is a real
# action and belongs behind approval like the others. The project's whole claim is "nothing risky
# runs without a human"; this list is where that claim is enforced, so it stays as short as possible.
AUTO_SAFE_ACTIONS = {ActionKind.no_action, ActionKind.escalate_to_human}

# Actions exempt from the EVIDENCE floor (P4, P8, P9). Only escalating to a person: handing an
# incident to a human is the right answer to weak evidence, so measuring the evidence before
# allowing it would be circular.
#
# ⛔ `no_action` was in this set and is not any more. On a real AWS account, 14 of 42 runs answered
# `no_action` about a service with a live fault and the gate allowed every one - two of them at 0.25
# confidence while their own `tool_errors` recorded that WARDEN could not read the logs at all
# (docs/bench/wave1-2026-09-11T155744Z). "Nothing is wrong" is a CLAIM ABOUT THE EVIDENCE, so it
# must clear the same evidence floor as any other claim. A well-evidenced, confident `no_action` is
# still auto_safe - the tool looked properly and found nothing.
EVIDENCE_EXEMPT_ACTIONS = {ActionKind.escalate_to_human}

# The per-environment allow-list is no longer hardcoded here — it lives in environments.yaml so an
# operator can add an environment (qa-staging, pre-prod, qa-prod, ...) or tighten an allowlist without
# editing this gate. P1 consults it below. An unknown environment resolves to the restrictive default
# and fails closed.

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
    *,
    policies_config: EnvironmentPolicies | None = None,
) -> Verdict:
    """Return the binding decision for one proposal.

    `policies_config` lets a caller/test inject a specific environment policy set; by default the
    bundled/operator-configured one is used.
    """
    env_policies = policies_config or default_environment_policies()
    env = env_policies.for_env(alert.environment)

    reasons: list[str] = []
    policies: list[str] = []
    rejected = False
    escalate = False

    # P1 — the action must be permitted in this environment at all (from environments.yaml).
    if not env.permits(proposal.action):
        rejected = True
        policies.append("P1-ENV-ALLOWLIST")
        reasons.append(
            f"{proposal.action.value} is not permitted in {alert.environment}."
        )

    # P2 — nothing irreversible in a production-tier environment, ever, regardless of confidence.
    #
    # ⛔ READS THE TABLE, NOT THE PROPOSAL. `proposal.reversible` is written by the model, and by
    # any caller of the MCP server, so keying a rejection on it let a proposal widen its own
    # permissions: two live models reported opposite values for the identical operation and got
    # opposite verdicts (docs/live-model-run-2026-09-06.md §3). The claim is not discarded — P10
    # escalates when it contradicts the table.
    if env.tier == "prod" and not proposal.table_reversible:
        rejected = True
        policies.append("P2-IRREVERSIBLE-IN-PROD")
        reasons.append(
            f"{proposal.action.value} is classified irreversible in WARDEN's action table, and "
            f"{alert.environment} is production-tier. The proposal claimed "
            f"reversible={proposal.reversible}; the table decided, not the claim."
        )

    # P3 — evidence is a precondition for action, not an optional extra.
    if context.is_empty() and proposal.action not in AUTO_SAFE_ACTIONS:
        rejected = True
        policies.append("P3-NO-EVIDENCE")
        reasons.append("No logs, metrics or deploy history were gathered; refusing to act blind.")

    # P4 — a low-confidence hypothesis is a question, not a plan.
    if root_cause.confidence < MIN_CONFIDENCE and proposal.action not in EVIDENCE_EXEMPT_ACTIONS:
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

    # P6 — wide blast radius is always a human's call. The table sets a FLOOR per action and the
    # proposal may only ever widen it: a model asking for a human is always allowed to, while
    # understating the reach of an action must buy it nothing.
    effective_radius = proposal.effective_blast_radius
    if effective_radius in ("multi_service", "region"):
        escalate = True
        policies.append("P6-BLAST-RADIUS")
        floor = ACTION_FACTS[proposal.action][1]
        reasons.append(
            f"Blast radius '{effective_radius}' exceeds the unattended limit (WARDEN's floor for "
            f"{proposal.action.value} is '{floor}', the proposal claimed "
            f"'{proposal.blast_radius}'; the wider of the two applies)."
        )

    # P7 — proportionality. Don't fail over a database because something is 'low'.
    heavy = {ActionKind.failover_replica, ActionKind.rollback_deploy}
    if proposal.action in heavy and alert.severity.value in ("low", "medium"):
        escalate = True
        policies.append("P7-DISPROPORTIONATE")
        reasons.append(
            f"{proposal.action.value} is disproportionate to a {alert.severity.value} alert."
        )

    # P8 — a tool failing means the picture is partial. Say so rather than pretending.
    if context.tool_errors and proposal.action not in EVIDENCE_EXEMPT_ACTIONS:
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
    if proposal.action not in EVIDENCE_EXEMPT_ACTIONS and not _evidence_is_substantial(context):
        escalate = True
        policies.append("P9-THIN-EVIDENCE")
        reasons.append(
            f"Evidence is thin ({len(context.logs)} log line(s), {len(context.metrics)} metric(s), "
            f"{len(context.recent_deploys)} deploy(s)); a human should look before acting."
        )

    # P10 — the proposal warns that this cannot be undone while the table says it can.
    #
    # P2 reads the table so the model cannot decide; ignoring a warning is a different thing from
    # refusing to obey one. `escalated` and `rejected` both mean nothing runs and both require a
    # person, so escalating here preserves the warning without handing the decision back.
    if proposal.claim_contradicts_table:
        escalate = True
        policies.append("P10-CLAIM-CONTRADICTS-TABLE")
        reasons.append(
            f"The proposal claims {proposal.action.value} is irreversible; WARDEN's action table "
            "classifies it reversible. A human should reconcile that before anything runs."
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
