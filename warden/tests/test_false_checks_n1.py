"""Register N1 / audit A-N-1: a plausible report that claims checks which never ran. What WARDEN read is said from
the gathered record - including what came back empty or failed - and a check the model says it ran is marked:
the model reads evidence and runs nothing, so such a claim is false by construction."""

from __future__ import annotations

import json

from warden.cli import DEMO_ALERTS
from warden.gate import hedge
from warden.graph import run
from warden.llm import LLMClient
from warden.models import Alert, ContextBundle
from warden.providers import Completion
from warden.reporting import _returned, build_report
from warden.tools import FixtureBackend

CLAIM = "I checked the connection pool and verified it is healthy; after checking the replicas we ran a failover test."


class _Claims:
    name, model = "claims", "c-1"

    def complete(self, *, system, user, schema=None):
        body = {"root_cause": {"hypothesis": CLAIM, "confidence": 0.9, "evidence": [CLAIM]},
                "proposal": {"action": "escalate_to_human", "target": "checkout", "reasoning": CLAIM,
                             "expected_effect": "a person looks", "blast_radius": "single_service",
                             "reversible": True}}
        return Completion(json.dumps(body), 10, 10)


def test_the_gate_marks_every_check_the_model_says_it_ran():
    out = hedge(CLAIM)
    for said in ("I checked", "after checking", "we ran"):
        assert f"[unverified: {said}]" in out, out
    assert out.count("[unverified:") == 3, out
    assert hedge("The logs show the pool was checked by the health probe.") == \
        "The logs show the pool was checked by the health probe."


def test_a_report_never_carries_an_unmarked_check_claim_from_the_model():
    class _NoMetrics(FixtureBackend):
        def metrics(self, alert):
            return {}

    rep = run(Alert(**DEMO_ALERTS["inc-001"]), llm=LLMClient(provider=_Claims(), mock=False), backend=_NoMetrics())
    md = build_report(rep.alert, root_cause=rep.root_cause, proposal=rep.proposal, verdict=rep.verdict,
                      context=rep.context).markdown
    assert "[unverified: I checked]" in md
    assert "I checked" not in md.replace("[unverified: I checked]", "")
    assert "metrics: returned nothing - unknown, not healthy" in md


def test_what_was_read_says_what_came_back_empty_or_failed():
    ctx = ContextBundle(logs=["a", "b"], metrics={}, empty_reads=["metrics"],
                        tool_errors=["recent_deploys: [timed out] timed out after 5.0s"])
    assert _returned(ctx) == ["logs: 2 line(s)", "metrics: returned nothing - unknown, not healthy",
                              "recent_deploys: could not be read"]
    partial = ContextBundle(logs=["a"], tool_errors=["logs: one stream unreadable"])
    assert _returned(partial)[0] == "logs: 1 line(s) (partly unread)"
