"""Requirement R39: an unknown, new kind of incident is still handled - it reaches a person. A failure no signature
describes and no counted symptom shows must never be closed by "nothing to do" (P24-UNRECOGNISED), and no action
proposed for it goes ahead on its own."""

from __future__ import annotations

import json

import pytest

from warden.graph import run
from warden.knowledge import default_knowledge_base
from warden.llm import LLMClient
from warden.models import ActionKind, Alert, Severity, VerdictStatus
from warden.providers import Completion


class _Novel:
    """A service failing in a way WARDEN has never seen: a made-up error and metric, nothing counted."""

    name = "novel"

    def logs(self, alert):
        return ["ERR frobnicator desync code=77 shard=4"] * 6

    def metrics(self, alert):
        return {"ledger_desync_events": 31.0, "p99_latency_ms": 900.0}

    def deploys(self, alert):
        return []


def _model(action: str):
    class _Grounded:
        """Cites real evidence verbatim, so the grounding policies pass and only the novelty is left."""

        name, model = "grounded", "g-1"

        def complete(self, *, system, user, schema=None):
            body = {"root_cause": {"hypothesis": "frobnicator desync", "confidence": 0.95, "evidence": ["desync"],
                                   "citations": [{"id": "M1", "quote": "ledger_desync_events=31"},
                                                 {"id": "F1", "quote": "code=77"}]},
                    "proposal": {"action": action, "target": "ledger", "reasoning": "per the evidence",
                                 "expected_effect": "errors stop", "blast_radius": "single_service",
                                 "reversible": True}}
            return Completion(json.dumps(body), 10, 10)

    return _Grounded()


NOVEL = Alert(alert_id="n-1", name="LedgerAnomaly", severity=Severity.high, service="ledger", environment="staging",
              summary="ledger anomaly", started_at="2026-10-03T06:00:00Z")


def test_the_incident_is_one_no_signature_describes():
    from warden.tools import gather

    assert default_knowledge_base().match(NOVEL, gather(NOVEL, _Novel())) == []


@pytest.mark.parametrize("action", [a.value for a in ActionKind])
def test_whatever_is_proposed_for_an_unknown_incident_a_person_gets_it(action):
    report = run(NOVEL, llm=LLMClient(provider=_model(action), mock=False), backend=_Novel())
    if action == ActionKind.escalate_to_human.value:
        assert report.verdict.status is VerdictStatus.auto_safe  # inert, and it IS the hand-off
        return
    assert report.verdict.status in (VerdictStatus.escalated, VerdictStatus.rejected), (action, report.verdict)
    if action == ActionKind.no_action.value:
        assert report.verdict.policy_ids == ["P24-UNRECOGNISED"], report.verdict.policy_ids
