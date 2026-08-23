"""Every policy gets a test that proves it can FIRE, not just that the happy path passes.

A gate nobody has watched reject something is not a gate.
"""

from aegis.models import (
    ActionKind,
    Alert,
    ContextBundle,
    RemediationProposal,
    RootCause,
    Severity,
    VerdictStatus,
)
from aegis.verifier import verify


def _alert(**kw):
    base = dict(
        alert_id="a-1",
        name="HighErrorRate",
        severity=Severity.critical,
        service="checkout",
        environment="prod",
        summary="5xx rate above 4%",
        started_at="2026-08-21T10:00:00Z",
    )
    base.update(kw)
    return Alert(**base)


def _ctx(**kw):
    # Deliberately realistic rather than minimal. An earlier version used a single log line and a
    # single metric, and P9 (thin evidence) correctly flagged it - the helper was describing a
    # situation no operator would act on, while the tests called it the "clean case".
    base = dict(
        logs=["err 500", "err 500", "NullPointerException"],
        metrics={"error_rate": 0.04, "p99_latency_ms": 2140.0},
        recent_deploys=[{"sha": "abc"}],
    )
    base.update(kw)
    return ContextBundle(**base)


def _rc(confidence=0.9):
    return RootCause(hypothesis="bad deploy", confidence=confidence, evidence=["err"])


def _prop(**kw):
    base = dict(
        action=ActionKind.rollback_deploy,
        target="checkout",
        reasoning="revert the deploy",
        expected_effect="errors return to baseline",
        blast_radius="single_service",
        reversible=True,
    )
    base.update(kw)
    return RemediationProposal(**base)


def test_clean_case_is_held_for_a_human_not_auto_run():
    v = verify(_alert(), _ctx(), _rc(), _prop())
    assert v.status is VerdictStatus.approved_for_human
    assert v.requires_approval is True


def test_p1_action_not_allowed_in_prod():
    v = verify(_alert(), _ctx(), _rc(), _prop(action=ActionKind.scale_down))
    assert v.status is VerdictStatus.rejected
    assert "P1-ENV-ALLOWLIST" in v.policy_ids


def test_p2_irreversible_in_prod_is_rejected_even_at_high_confidence():
    v = verify(_alert(), _ctx(), _rc(confidence=0.99), _prop(reversible=False))
    assert v.status is VerdictStatus.rejected
    assert "P2-IRREVERSIBLE-IN-PROD" in v.policy_ids


def test_p3_refuses_to_act_without_evidence():
    empty = ContextBundle()
    v = verify(_alert(), empty, _rc(), _prop())
    assert v.status is VerdictStatus.rejected
    assert "P3-NO-EVIDENCE" in v.policy_ids


def test_p4_low_confidence_escalates():
    v = verify(_alert(), _ctx(), _rc(confidence=0.2), _prop())
    assert v.status is VerdictStatus.escalated
    assert "P4-LOW-CONFIDENCE" in v.policy_ids


def test_p5_cannot_roll_back_a_deploy_that_is_not_in_evidence():
    v = verify(_alert(), _ctx(recent_deploys=[]), _rc(), _prop())
    assert v.status is VerdictStatus.rejected
    assert "P5-NO-DEPLOY-TO-ROLL-BACK" in v.policy_ids


def test_p6_wide_blast_radius_escalates():
    v = verify(_alert(), _ctx(), _rc(), _prop(blast_radius="region"))
    assert v.status is VerdictStatus.escalated
    assert "P6-BLAST-RADIUS" in v.policy_ids


def test_p7_heavy_action_on_low_severity_escalates():
    v = verify(_alert(severity=Severity.low), _ctx(), _rc(), _prop())
    assert v.status is VerdictStatus.escalated
    assert "P7-DISPROPORTIONATE" in v.policy_ids


def test_p8_partial_context_escalates():
    v = verify(_alert(), _ctx(tool_errors=["metrics timed out"]), _rc(), _prop())
    assert v.status is VerdictStatus.escalated
    assert "P8-PARTIAL-CONTEXT" in v.policy_ids


def test_inert_actions_need_no_approval():
    v = verify(_alert(), ContextBundle(), _rc(), _prop(action=ActionKind.escalate_to_human))
    assert v.status is VerdictStatus.auto_safe
    assert v.requires_approval is False


def test_rejection_beats_escalation_when_both_apply():
    """A hard no must not be softened into 'ask a human' by a second, weaker finding."""
    v = verify(_alert(), _ctx(recent_deploys=[]), _rc(confidence=0.1), _prop())
    assert v.status is VerdictStatus.rejected


# --------------------------------------------------------------------------- P9
# Added after a LIVE model run returned confidence 0.85 on all four bundled incidents, including
# the one whose evidence is two vague log lines. Self-reported confidence is not calibrated, so the
# gate needed a signal it measures itself.


def test_p9_thin_evidence_escalates_even_at_high_confidence():
    thin = ContextBundle(logs=["one line"], metrics={}, recent_deploys=[])
    v = verify(_alert(), thin, _rc(confidence=0.99), _prop(action=ActionKind.restart_pods))
    assert v.status is VerdictStatus.escalated
    assert "P9-THIN-EVIDENCE" in v.policy_ids


def test_p9_does_not_fire_on_a_well_evidenced_incident():
    v = verify(_alert(), _ctx(), _rc(), _prop())
    assert "P9-THIN-EVIDENCE" not in v.policy_ids


def test_p9_accepts_two_independent_kinds_of_evidence():
    """Logs plus metrics, no deploy - enough to reason about."""
    ctx = ContextBundle(
        logs=["a", "b", "c"], metrics={"error_rate": 0.1, "p99": 900.0}, recent_deploys=[]
    )
    v = verify(_alert(), ctx, _rc(), _prop(action=ActionKind.restart_pods))
    assert "P9-THIN-EVIDENCE" not in v.policy_ids


def test_p9_ignores_inert_actions():
    thin = ContextBundle(logs=["one line"])
    v = verify(_alert(), thin, _rc(), _prop(action=ActionKind.escalate_to_human))
    assert "P9-THIN-EVIDENCE" not in v.policy_ids


# --------------------------------------------------------------------------- what counts as inert
# Only doing nothing and handing off to a human skip approval. Everything that can touch running
# infrastructure - clear_cache included - is held for a person, because that is the project's claim.


def test_only_no_action_and_escalate_are_auto_safe():
    from aegis.verifier import AUTO_SAFE_ACTIONS

    assert AUTO_SAFE_ACTIONS == {ActionKind.no_action, ActionKind.escalate_to_human}


def test_clear_cache_in_prod_is_held_for_a_human_not_auto_run():
    """A cache flush can cause a stampede/latency spike, so it is a real action behind approval."""
    v = verify(_alert(), _ctx(), _rc(), _prop(action=ActionKind.clear_cache))
    assert v.status is VerdictStatus.approved_for_human
    assert v.requires_approval is True


def test_thin_evidence_clear_cache_escalates_rather_than_slipping_through_as_safe():
    """The regression this guards: while clear_cache was 'auto_safe' it skipped P9 entirely, so a
    cache flush on two log lines passed unattended. Now it is subject to the evidence floor."""
    thin = ContextBundle(logs=["one line"], metrics={}, recent_deploys=[])
    v = verify(_alert(), thin, _rc(confidence=0.99), _prop(action=ActionKind.clear_cache))
    assert v.status is VerdictStatus.escalated
    assert "P9-THIN-EVIDENCE" in v.policy_ids


# --- environment policy is config-driven now (environments.yaml), not a hardcoded dict -----------

def test_p1_uses_the_env_config_qa_staging_denies_failover():
    """qa-staging is not one of the old three environments; the policy config governs it, and it
    denies a DB failover even though it auto-remediates everything else."""
    v = verify(
        _alert(environment="qa-staging"),
        _ctx(),
        _rc(),
        _prop(action=ActionKind.failover_replica),
    )
    assert v.status is VerdictStatus.rejected
    assert "P1-ENV-ALLOWLIST" in v.policy_ids


def test_p1_unknown_environment_fails_closed():
    """An environment string the policy has never heard of can do nothing but escalate."""
    v = verify(
        _alert(environment="brand-new-region-7"),
        _ctx(),
        _rc(),
        _prop(action=ActionKind.restart_pods),
    )
    assert v.status is VerdictStatus.rejected
    assert "P1-ENV-ALLOWLIST" in v.policy_ids


def test_a_permitted_action_in_a_new_prod_tier_env_still_blocks_irreversible():
    """P2 keys on the env TIER, not the literal string 'prod', so any prod-tier env blocks irreversible."""
    v = verify(
        _alert(environment="prod"),
        _ctx(),
        _rc(confidence=0.99),
        _prop(action=ActionKind.restart_pods, reversible=False),
    )
    assert v.status is VerdictStatus.rejected
    assert "P2-IRREVERSIBLE-IN-PROD" in v.policy_ids
