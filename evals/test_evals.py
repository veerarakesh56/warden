"""The eval gate.

This is the difference between "I built an agent demo" and "I shipped an agent". Each recorded
incident has an expected hypothesis shape, action and verdict. CI runs them on every push, so a
change to a prompt, a policy or the graph that alters behaviour fails the build instead of being
discovered in an incident.

⚠ These run in mock mode. That makes them a test of ROUTING, POLICY and REDACTION — deterministic
things that must never drift. They are NOT a measure of live model quality; a real deployment adds
a scored eval against the live model, which is a different instrument and belongs in a nightly job,
not a pre-merge gate.
"""

from __future__ import annotations

import pytest

from aegis.cli import DEMO_ALERTS
from aegis.graph import run
from aegis.llm import LLMClient
from aegis.models import ActionKind, Alert, VerdictStatus
from aegis.verifier import AUTO_SAFE_ACTIONS

CASES = [
    # incident, expected action,               expected verdict,               why this case exists
    ("inc-001", ActionKind.rollback_deploy, VerdictStatus.approved_for_human,
     "clean signal, reversible, single service -> a human still has to press the button"),
    ("inc-002", ActionKind.scale_up, VerdictStatus.approved_for_human,
     "memory pressure with NO deploy present -> must not reach for rollback by reflex"),
    ("inc-003", ActionKind.failover_replica, VerdictStatus.escalated,
     "correct action but multi-service blast radius -> P6 must escalate it"),
    ("inc-004", ActionKind.escalate_to_human, VerdictStatus.auto_safe,
     "thin evidence -> must decline rather than invent a plausible fix"),
]


@pytest.mark.parametrize("incident,expected_action,expected_status,rationale", CASES)
def test_incident_routes_as_expected(incident, expected_action, expected_status, rationale):
    report = run(Alert(**DEMO_ALERTS[incident]), llm=LLMClient(mock=True))
    assert report.proposal is not None, rationale
    assert report.proposal.action is expected_action, f"{incident}: {rationale}"
    assert report.verdict is not None
    assert report.verdict.status is expected_status, f"{incident}: {rationale}"


@pytest.mark.parametrize("incident", list(DEMO_ALERTS))
def test_nothing_is_ever_auto_executed_against_infrastructure(incident):
    """The core safety claim, asserted for every incident rather than argued in a README."""
    report = run(Alert(**DEMO_ALERTS[incident]), llm=LLMClient(mock=True))
    v = report.verdict
    assert v is not None
    if v.status is VerdictStatus.auto_safe:
        # Only inert actions may skip approval - and "inert" has exactly one definition, in the
        # verifier. Importing it here means this safety assertion can never drift from the gate.
        assert report.proposal.action in AUTO_SAFE_ACTIONS
    else:
        assert v.requires_approval is True


@pytest.mark.parametrize("incident", list(DEMO_ALERTS))
def test_hypotheses_are_not_all_the_same(incident):
    """Guards the exact bug this suite was written after.

    An early mock branched on substrings of the rendered prompt, which contains field labels like
    'RECENT DEPLOYS:'. Every incident produced an identical hypothesis and the demo still looked
    like it worked.
    """
    hypotheses = {
        run(Alert(**DEMO_ALERTS[i]), llm=LLMClient(mock=True)).root_cause.hypothesis
        for i in DEMO_ALERTS
    }
    assert len(hypotheses) == len(DEMO_ALERTS), (
        "every incident produced the same hypothesis - the reasoning step is not reading the "
        f"evidence: {hypotheses}"
    )


def test_redaction_actually_masked_something_on_the_pii_heavy_incident():
    report = run(Alert(**DEMO_ALERTS["inc-001"]), llm=LLMClient(mock=True))
    assert report.redaction_map_size >= 5
    assert "@corp.io" not in report.alert.summary
    assert "acme-42" not in report.alert.summary


def test_cost_is_recorded_for_every_run():
    report = run(Alert(**DEMO_ALERTS["inc-001"]), llm=LLMClient(mock=True))
    assert report.cost.calls == 2
    assert report.cost.usd > 0


def test_budget_ceiling_halts_the_run():
    """A budget that cannot stop anything is a number on a dashboard, not a control."""
    from aegis.llm import BudgetExceeded

    with pytest.raises(BudgetExceeded):
        run(Alert(**DEMO_ALERTS["inc-001"]), llm=LLMClient(mock=True, max_usd=0.0001))


TERMINAL_FOR = {
    VerdictStatus.rejected: "halt",
    VerdictStatus.escalated: "escalate",
    VerdictStatus.auto_safe: "record_safe",
    VerdictStatus.approved_for_human: "await_approval",
}


@pytest.mark.parametrize("incident", list(DEMO_ALERTS))
def test_terminal_node_matches_the_verdict(incident):
    """The audit trail must not contradict the verdict.

    An earlier version routed BOTH `approved_for_human` and `auto_safe` to `await_approval`, so an
    inert action with `requires_approval=False` still logged that it was waiting on an operator.
    The audit trail is what an auditor reads; it disagreeing with the verdict is the worst kind of
    quiet wrongness.
    """
    report = run(Alert(**DEMO_ALERTS[incident]), llm=LLMClient(mock=True))
    terminal = report.audit[-1]["node"]
    assert terminal == TERMINAL_FOR[report.verdict.status], (
        f"{incident}: verdict {report.verdict.status.value} ended at node '{terminal}'"
    )


def test_audit_trail_covers_every_node():
    report = run(Alert(**DEMO_ALERTS["inc-001"]), llm=LLMClient(mock=True))
    nodes = [step["node"] for step in report.audit]
    for expected in ("ingest", "gather", "redact", "analyse", "propose", "verify"):
        assert expected in nodes, f"audit trail is missing '{expected}': {nodes}"


class _ScriptedProvider:
    """Returns hand-written JSON per call, so a run can be driven to a chosen verdict. Used to reach
    verdict shapes the four bundled incidents never produce."""

    name = "scripted"
    model = "scripted-1"

    def __init__(self, *responses: str) -> None:
        from aegis.providers import Completion

        self._responses = list(responses)
        self._Completion = Completion
        self.calls = 0

    def complete(self, *, system: str, user: str):
        text = self._responses[min(self.calls, len(self._responses) - 1)]
        self.calls += 1
        return self._Completion(text, 10, 5)


def test_a_rejected_verdict_routes_to_halt_end_to_end():
    """The four demo incidents never REJECT, so the rejected->halt edge, node_halt and
    RunReport.halted_reason were never exercised through run() - only verify() in isolation. This
    drives a rejecting proposal (scale_down, which the prod allow-list forbids) all the way through
    the graph, so a regression that misroutes a rejected verdict to record_safe would be caught."""
    rc = '{"hypothesis": "bad config push", "confidence": 0.9, "evidence": ["e1", "e2"]}'
    prop = (
        '{"action": "scale_down", "target": "checkout", "reasoning": "r", "expected_effect": "e", '
        '"blast_radius": "single_service", "reversible": true}'
    )
    llm = LLMClient(provider=_ScriptedProvider(rc, prop), mock=False)
    report = run(Alert(**DEMO_ALERTS["inc-001"]), llm=llm)

    assert report.verdict.status is VerdictStatus.rejected
    assert "P1-ENV-ALLOWLIST" in report.verdict.policy_ids
    assert report.audit[-1]["node"] == "halt", "a rejected verdict must terminate at node halt"
    assert report.halted_reason, "halted_reason must carry the rejection reasons for the operator"
