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
    base = dict(logs=["err"], metrics={"error_rate": 0.04}, recent_deploys=[{"sha": "abc"}])
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
