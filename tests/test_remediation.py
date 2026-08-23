"""The four-way remediation gate: verdict x env auto-remediate x authorised principal x approval."""

from __future__ import annotations

from aegis.models import (
    ActionKind,
    Alert,
    RemediationProposal,
    Severity,
    Verdict,
    VerdictStatus,
)
from aegis.remediation import (
    DryRunBackend,
    RemediationOutcome,
    RemediationRequest,
    decide_remediation,
)


def _alert(environment="staging"):
    return Alert(
        alert_id="inc", name="PodOOMKilled", severity=Severity.high, service="checkout",
        environment=environment, summary="OOM", started_at="2026-08-23T00:00:00Z",
    )


def _prop(action=ActionKind.scale_up, target="checkout", reversible=True):
    return RemediationProposal(
        action=action, target=target, reasoning="r", expected_effect="relief",
        blast_radius="single_service", reversible=reversible,
    )


def _approved_verdict():
    return Verdict(status=VerdictStatus.approved_for_human, policy_ids=[], requires_approval=True)


class _LiveBackend:
    """A fake backend that reports itself live and records the call."""

    live = True

    def __init__(self):
        self.calls = []

    def apply(self, action, target, environment):
        self.calls.append((action, target, environment))
        return f"applied {action.value} to {target}"


# ------------------------------------------------------------------ the gate, step by step

def test_a_rejected_verdict_is_never_applied():
    v = Verdict(status=VerdictStatus.rejected, policy_ids=["P1-ENV-ALLOWLIST"])
    r = decide_remediation(_alert(), _prop(), v, RemediationRequest(principal="role:oncall", approved=True))
    assert r.outcome is RemediationOutcome.blocked
    assert r.changed_infrastructure is False


def test_an_escalated_verdict_is_never_applied():
    v = Verdict(status=VerdictStatus.escalated, policy_ids=["P6-BLAST-RADIUS"])
    r = decide_remediation(_alert(), _prop(), v, RemediationRequest(principal="role:oncall", approved=True))
    assert r.outcome is RemediationOutcome.blocked


def test_unauthorized_principal_cannot_remediate():
    r = decide_remediation(
        _alert(), _prop(), _approved_verdict(),
        RemediationRequest(principal="role:intern", approved=True),
    )
    assert r.outcome is RemediationOutcome.unauthorized


def test_no_principal_cannot_remediate():
    r = decide_remediation(
        _alert(), _prop(), _approved_verdict(), RemediationRequest(approved=True)
    )
    assert r.outcome is RemediationOutcome.unauthorized


def test_prod_is_never_auto_remediated_even_when_authorised_and_approved():
    r = decide_remediation(
        _alert(environment="prod"), _prop(), _approved_verdict(),
        RemediationRequest(principal="role:oncall", approved=True),
    )
    assert r.outcome is RemediationOutcome.not_auto_remediable
    assert r.changed_infrastructure is False


def test_staging_awaits_approval_when_none_given():
    r = decide_remediation(
        _alert(), _prop(), _approved_verdict(),
        RemediationRequest(principal="role:oncall", approved=False),
    )
    assert r.outcome is RemediationOutcome.awaiting_approval


def test_staging_with_approval_dry_runs_by_default_touching_nothing():
    r = decide_remediation(
        _alert(), _prop(), _approved_verdict(),
        RemediationRequest(principal="role:oncall", approved=True),
    )
    assert r.outcome is RemediationOutcome.dry_run
    assert r.changed_infrastructure is False
    assert "DRY RUN" in r.applied_change


def test_a_live_backend_actually_applies_when_every_gate_passes():
    backend = _LiveBackend()
    r = decide_remediation(
        _alert(), _prop(), _approved_verdict(),
        RemediationRequest(principal="svc:aegis-staging", approved=True),
        backend=backend,
    )
    assert r.outcome is RemediationOutcome.applied
    assert r.changed_infrastructure is True
    assert backend.calls == [(ActionKind.scale_up, "checkout", "staging")]


def test_defence_in_depth_denied_action_is_blocked_even_with_an_approved_verdict():
    # failover_replica is denied in staging by the env policy; even a hand-built approved verdict
    # must not get it applied — the executor re-checks the policy.
    r = decide_remediation(
        _alert(), _prop(action=ActionKind.failover_replica), _approved_verdict(),
        RemediationRequest(principal="role:oncall", approved=True),
        backend=_LiveBackend(),
    )
    assert r.outcome is RemediationOutcome.blocked


def test_dry_run_backend_is_honest_about_being_a_simulation():
    assert DryRunBackend().live is False
