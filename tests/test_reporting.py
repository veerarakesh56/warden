"""The remediation report: redacted output + a promotion plan derived from the env policy."""

from __future__ import annotations

from aegis.models import (
    ActionKind,
    Alert,
    RemediationProposal,
    RootCause,
    Severity,
    Verdict,
    VerdictStatus,
)
from aegis.remediation import RemediationOutcome, RemediationResult
from aegis.reporting import build_report


def _alert(environment="staging", summary="OOM"):
    return Alert(
        alert_id="inc-002", name="PodOOMKilled", severity=Severity.high, service="checkout",
        environment=environment, summary=summary, started_at="2026-08-23T00:00:00Z",
    )


def _prop(action=ActionKind.scale_up):
    return RemediationProposal(
        action=action, target="checkout", reasoning="r", expected_effect="relief",
        blast_radius="single_service", reversible=True,
    )


def test_report_masks_identifiers_everywhere_it_renders_them():
    a = _alert(summary="OOM for user priya.nair@corp.io from 10.2.3.4 tenant_id=acme-42")
    rep = build_report(
        a,
        root_cause=RootCause(hypothesis="leak affecting bob@corp.io", confidence=0.8),
        proposal=_prop(),
        verdict=Verdict(status=VerdictStatus.approved_for_human),
    )
    for secret in ("priya.nair@corp.io", "10.2.3.4", "acme-42", "bob@corp.io"):
        assert secret not in rep.markdown, f"{secret} leaked into report markdown"
    # and into the structured data
    blob = str(rep.data)
    for secret in ("priya.nair@corp.io", "10.2.3.4", "bob@corp.io"):
        assert secret not in blob, f"{secret} leaked into report data"


def test_promotion_lists_higher_environments_that_permit_the_action():
    rep = build_report(_alert(environment="staging"), proposal=_prop(ActionKind.scale_up))
    envs = {t.environment for t in rep.promotion}
    # scale_up is allowed in pre-prod, qa-prod and prod -> all are promotion targets from staging.
    assert {"pre-prod", "qa-prod", "prod"} <= envs
    # same-tier and lower environments are not promotion targets
    assert "staging" not in envs and "qa-staging" not in envs and "dev" not in envs


def test_promotion_excludes_environments_that_deny_the_action():
    # failover_replica is denied in pre-prod/qa-prod but allowed in prod.
    rep = build_report(_alert(environment="staging"), proposal=_prop(ActionKind.failover_replica))
    envs = {t.environment for t in rep.promotion}
    assert "pre-prod" not in envs and "qa-prod" not in envs


def test_prod_has_no_promotion_targets():
    rep = build_report(_alert(environment="prod"), proposal=_prop(ActionKind.scale_up))
    assert rep.promotion == ()
    assert "nothing to promote" in rep.markdown.lower()


def test_report_carries_the_remediation_outcome():
    result = RemediationResult(
        outcome=RemediationOutcome.dry_run, action=ActionKind.scale_up, target="checkout",
        environment="staging", principal="role:oncall", detail="applied after approval",
        applied_change="DRY RUN: would scale_up 'checkout' in staging",
    )
    rep = build_report(_alert(), proposal=_prop(), remediation=result)
    assert rep.data["remediation"]["outcome"] == "dry_run"
    assert "dry_run" in rep.markdown


def test_report_always_carries_the_safety_line():
    rep = build_report(_alert(), proposal=_prop())
    assert "Nothing was executed against production" in rep.markdown
