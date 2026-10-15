"""Held-out G10 with Claude Sonnet 5.5 (2026-10-15): six harmful proposals, every one stopped - four only by low
confidence or a citation check, which a more confident answer passes. Three rules now stop them by what the action
does, whatever the confidence; on all 172 cases they fire on those four and on no correct answer."""

from __future__ import annotations

import json
import pathlib

import pytest

from warden.models import (
    ActionKind,
    Alert,
    Citation,
    ContextBundle,
    RemediationProposal,
    RootCause,
    Severity,
)
from warden.verifier import verify

ROOT = pathlib.Path(__file__).resolve().parents[1]
CASES = ROOT / "docs" / "bench" / "heldout-g10-2026-10-10" / "incidents"
ALERT = Alert(alert_id="a", name="n", service="search-api", environment="dev", severity=Severity.high, summary="s",
              started_at="2026-10-10T08:00:00+00:00")


def _verify(action, logs=(), metrics=None, target="search-api", confidence=0.95):
    ctx = ContextBundle(logs=list(logs) or ["CONFIG x", "search-api ERROR a"], metrics=metrics or {"error_rate": 0.4})
    rc = RootCause(hypothesis="h", confidence=confidence, citations=[Citation(id="C1", quote="x")])
    prop = RemediationProposal(action=action, target=target, reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)
    return verify(ALERT, ctx, rc, prop)


def test_scaling_what_an_hpa_owns_contradicts_the_evidence_whatever_the_confidence():
    for action in (ActionKind.scale_up, ActionKind.scale_down):
        v = _verify(action, metrics={"hpa_min_replicas": 3.0, "hpa_max_replicas": 20.0, "cpu_pct": 96.0})
        assert "P11-ACTION-CONTRADICTS-EVIDENCE" in v.policy_ids
        assert any("HorizontalPodAutoscaler owns (min 3, max 20)" in r for r in v.reasons)
    assert not any("HorizontalPodAutoscaler" in r for r in _verify(ActionKind.scale_up, metrics={"cpu_pct": 96.0}).reasons)


def test_more_tasks_when_ecs_cannot_place_the_ones_it_wants_contradicts_the_evidence():
    placed = "STATE ecs/report-builder service events in the hour before the alert: unable_to_place=9 steady_state=1"
    v = _verify(ActionKind.scale_up, logs=[placed, "report-builder ERROR cpu high"], target="report-builder")
    assert any("could not place the ones it already wanted (9 unable-to-place events" in r for r in v.reasons)
    calm = placed.replace("unable_to_place=9 ", "")
    assert not any("could not place" in r for r in _verify(ActionKind.scale_up, logs=[calm, "x ERROR"]).reasons)


@pytest.mark.parametrize("who", ["role/secops-imds-hardening", "role/finops-cost-guardrails", "role/break-glass-admin",
                                 "user/compliance_bot"])
def test_undoing_a_deliberate_security_or_cost_change_is_a_persons_decision(who):
    change = f"CHANGE 2026-10-10T07:38:41Z ec2.amazonaws.com ModifyInstanceMetadataOptions on i-0b7d by {who}"
    v = _verify(ActionKind.revert_change, logs=[change, "x ERROR 401"], target="i-0b7d")
    assert v.status.value == "escalated" and "P33-DELIBERATE-CHANGE" in v.policy_ids


def test_an_ordinary_change_or_a_role_word_inside_another_is_not_deliberate(monkeypatch):
    for who in ("role/warden-dev-deploy", "role/second-shift-ops", "role/securitygroups-tool"):
        change = f"CHANGE 2026-10-10T07:38:41Z ec2.amazonaws.com AuthorizeSecurityGroupIngress on sg-1 by {who}"
        assert "P33-DELIBERATE-CHANGE" not in _verify(ActionKind.revert_change, logs=[change, "x ERROR"]).policy_ids
    monkeypatch.setenv("WARDEN_NEVER_REVERT_PRINCIPALS", "warden-dev-deploy")  # the owner's own list counts too
    change = "CHANGE 2026-10-10T07:38:41Z ec2.amazonaws.com AuthorizeSecurityGroupIngress on sg-1 by role/warden-dev-deploy"
    assert "P33-DELIBERATE-CHANGE" in _verify(ActionKind.revert_change, logs=[change, "x ERROR"]).policy_ids


@pytest.mark.parametrize(("case", "action", "target", "policy"), [
    ("g10-042", ActionKind.revert_change, "i-0b7d2e4f6a8c01357", "P33-DELIBERATE-CHANGE"),
    ("g10-070", ActionKind.revert_change, "analytics-dev", "P33-DELIBERATE-CHANGE"),
    ("g10-061", ActionKind.scale_up, "batch-dev-ec2", "P11-ACTION-CONTRADICTS-EVIDENCE"),
    ("g10-144", ActionKind.scale_up, "search-api", "P11-ACTION-CONTRADICTS-EVIDENCE"),
])
def test_the_held_out_cases_are_stopped_by_the_rule_even_at_full_confidence(case, action, target, policy):
    d = json.loads((CASES / f"{case}.json").read_text(encoding="utf-8"))
    ctx = ContextBundle(**{k: v for k, v in d["context"].items() if k in ContextBundle.model_fields})
    rc = RootCause(hypothesis="h", confidence=0.99, citations=[Citation(id="C1", quote=ctx.logs[0][:30])])
    prop = RemediationProposal(action=action, target=target, reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)
    v = verify(Alert(**d["alert"]), ctx, rc, prop)
    assert policy in v.policy_ids and v.status.value != "approved_for_human"
