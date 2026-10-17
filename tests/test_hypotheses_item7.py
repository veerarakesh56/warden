"""Item 7 (2026-10-17): ranked hypotheses, each with evidence for and against; a plan only on a cause decided by
evidence WARDEN read itself (P34), and only when WARDEN's own count of the citations separates it from its best rival
(P35) - never the model's self-confidence. Still one model call."""

from __future__ import annotations

import json

from warden import evidence
from warden.cli import DEMO_ALERTS
from warden.graph import run
from warden.grounding import MARGIN, decisive_problem, hypothesis_score, margin_problem
from warden.llm import LLMClient
from warden.models import Alert, RootCause, VerdictStatus
from warden.providers import Completion
from warden.reporting import build_report

INC = Alert(**DEMO_ALERTS["inc-001"])  # a deploy (D1) before a 4.2% error rate (M1); F2 a NullPointerException
D1 = {"id": "D1", "quote": "sha=9f2c1ab"}
M1 = {"id": "M1", "quote": "error_rate=0.042"}
M4 = {"id": "M4", "quote": "cpu_utilisation=0.41"}
F2 = {"id": "F2", "quote": "code=NullPointerException"}
ROLLBACK = {"action": "rollback_deploy", "target": "checkout", "reasoning": "revert", "expected_effect": "errors stop",
            "blast_radius": "single_service", "reversible": True}


class _Scripted:
    name, model = "scripted", "s-1"

    def __init__(self, body: dict) -> None:
        self.body, self.calls = body, 0

    def complete(self, *, system, user, schema=None):
        self.calls += 1
        return Completion(json.dumps(self.body), 10, 10)


def _run(root_cause: dict, proposal: dict = ROLLBACK):
    provider = _Scripted({"root_cause": {"confidence": 0.9, **root_cause}, "proposal": proposal})
    report = run(INC, llm=LLMClient(provider=provider, mock=False))
    return report, provider


def _ranked(chosen: list[dict], rival_for: list[dict] = (), rival_against: list[dict] = (), **extra) -> dict:
    return {"hypothesis": "the deploy broke checkout",
            "hypotheses": [{"cause": "the deploy broke checkout", "supporting": chosen},
                           {"cause": "CPU saturation", "supporting": list(rival_for), "against": list(rival_against),
                            "why_rejected": "CPU is at 41%"}], **extra}


def test_a_well_separated_cause_on_own_reads_reaches_the_approver_in_one_call():
    report, provider = _run(_ranked([D1, M1], rival_against=[M4]))
    assert report.verdict.status is VerdictStatus.approved_for_human, report.verdict.reasons
    assert provider.calls == 1  # several hypotheses, one call
    assert report.cost.calls == 1
    assert [c.id for c in report.root_cause.citations] == ["D1", "M1"]  # cited by the first hypothesis


def test_a_cause_only_log_facts_support_is_no_plan():
    report, _ = _run(_ranked([F2]))
    assert "P34-NO-DECISIVE-EVIDENCE" in report.verdict.policy_ids
    assert report.verdict.status is VerdictStatus.escalated


def test_a_decisive_citation_that_does_not_hold_decides_nothing():
    report, _ = _run(_ranked([{"id": "M1", "quote": "error_rate=0.99"}, F2]))
    assert {"P13-UNGROUNDED", "P34-NO-DECISIVE-EVIDENCE"} <= set(report.verdict.policy_ids)


def test_a_new_answer_without_rivals_weighed_goes_to_a_person():
    report, _ = _run({"hypothesis": "the deploy broke checkout", "citations": [D1, M1]})
    assert report.root_cause.hypotheses == []  # a new answer is never taken for an old one
    assert "P35-NO-RIVAL-HYPOTHESIS" in report.verdict.policy_ids
    assert report.verdict.status is VerdictStatus.escalated


def test_one_hypothesis_is_no_rival_weighed():
    report, _ = _run({"hypothesis": "the deploy broke checkout",
                      "hypotheses": [{"cause": "the deploy broke checkout", "supporting": [D1, M1]}]})
    assert "P35-NO-RIVAL-HYPOTHESIS" in report.verdict.policy_ids
    assert report.verdict.status is VerdictStatus.escalated


def test_two_causes_the_evidence_does_not_separate_escalate_with_both():
    report, _ = _run(_ranked([D1, M1], rival_for=[M4, {"id": "F1", "quote": "upstream"}]))
    assert "P35-HYPOTHESES-TOO-CLOSE" in report.verdict.policy_ids
    why = next(r for r in report.verdict.reasons if "separate" in r)
    assert "the deploy broke checkout" in why
    assert "CPU saturation" in why


def test_the_count_is_the_evidence_not_the_confidence():
    """A confidence of 1.0 does not widen a margin the citations do not give."""
    report, _ = _run({**_ranked([D1], rival_for=[M4]), "confidence": 1.0})
    assert "P35-HYPOTHESES-TOO-CLOSE" in report.verdict.policy_ids


def test_evidence_against_the_chosen_cause_counts_against_it():
    items = evidence.view(run(INC, llm=LLMClient(mock=True)).context)
    rc = RootCause.model_validate(_ranked([D1, M1]) | {"confidence": 0.9})
    assert hypothesis_score(rc.hypotheses[0], items, rc.citations) == 4
    rc.hypotheses[0].against.append(rc.citations[1])  # the same item read against it: it cancels
    assert hypothesis_score(rc.hypotheses[0], items, rc.citations) == 2
    assert MARGIN == 2
    assert margin_problem(rc, items) is None  # 2 over an uncited rival is still the margin
    rc.hypotheses[1].supporting.append(rc.citations[1])  # the rival now holds an own read too: 2 - 2
    assert margin_problem(rc, items)[0] == "too_close"


def test_citing_one_item_twice_counts_once_and_a_failed_read_counts_nothing():
    items = {"M1": evidence.Item("M1", "error_rate=0.042"), "T1": evidence.Item("T1", "logs: access denied")}
    rc = RootCause.model_validate({"hypothesis": "x", "confidence": 0.9, "hypotheses": [
        {"cause": "x", "supporting": [M1, M1, {"id": "T1", "quote": "access denied"}]}, {"cause": "y"}]})
    assert hypothesis_score(rc.hypotheses[0], items, rc.citations) == 2
    only_t = RootCause.model_validate({"hypothesis": "x", "confidence": 0.9,
                                       "citations": [{"id": "T1", "quote": "access denied"}]})
    assert decisive_problem(only_t, items)


def test_an_old_answer_keeps_its_meaning():
    """A recorded answer (no `hypotheses`) is not asked for rivals it was never asked to give: P35 does not apply,
    and P34 reads its citations."""
    items = {"M1": evidence.Item("M1", "error_rate=0.042")}
    old = RootCause.recorded({"hypothesis": "x", "confidence": 0.9, "citations": [M1]})
    assert old.hypotheses is None
    assert margin_problem(old, items) is None
    assert decisive_problem(old, items) is None
    assert RootCause.model_validate_json(old.model_dump_json()).hypotheses is None  # survives a round trip
    ranked = RootCause.recorded({"hypothesis": "x", "confidence": 0.9, "hypotheses": [{"cause": "x"}]})
    assert len(ranked.hypotheses) == 1  # a stored answer that ranked keeps what it ranked


def test_a_root_cause_built_anywhere_else_weighed_no_rival():
    """Fail closed (review, PR 47): only a stored answer read back is "before ranked hypotheses"."""
    items = {"M1": evidence.Item("M1", "error_rate=0.042")}
    fresh = RootCause.model_validate({"hypothesis": "x", "confidence": 0.9, "citations": [M1]})
    assert fresh.hypotheses == []
    assert margin_problem(fresh, items)[0] == "no_rival"


def test_a_fifth_hypothesis_is_dropped_not_the_answer():
    rc = RootCause.model_validate({"hypothesis": "x", "confidence": 0.5,
                                   "hypotheses": [{"cause": f"c{n}"} for n in range(6)]})
    assert [h.cause for h in rc.hypotheses] == ["c0", "c1", "c2", "c3"]


def test_the_report_shows_the_chosen_cause_and_the_rejected_one_with_why():
    report, _ = _run(_ranked([D1, M1], rival_against=[M4]))
    md = build_report(report.alert, root_cause=report.root_cause, proposal=report.proposal, verdict=report.verdict,
                      context=report.context).markdown
    assert "**Ruled out:** CPU saturation - CPU is at 41%" in md
    assert "checked against M4" in md
    assert "WARDEN's evidence count -2" in md  # the rival: nothing for it, an own read against it
    assert "WARDEN's evidence count 4: for D1, M1, against nothing" in md


def test_the_mock_weighs_a_rival_for_every_incident():
    for incident in DEMO_ALERTS:
        rc = run(Alert(**DEMO_ALERTS[incident]), llm=LLMClient(mock=True)).root_cause
        assert len(rc.hypotheses) == 2, incident
        assert rc.hypotheses[1].why_rejected, incident


def test_a_made_up_citation_in_the_chosen_causes_own_support_is_ungrounded():
    """Review, PR 47: the chosen hypothesis's support decides P34 and P35, so a citation of it that does not hold is
    ungrounded (P13), never quietly left out of the count."""
    report, _ = _run({"hypothesis": "the deploy broke checkout", "citations": [D1, M1],
                      "hypotheses": [{"cause": "the deploy broke checkout",
                                      "supporting": [{"id": "M9", "quote": "error_rate=0.99"}]},
                                     {"cause": "CPU saturation", "against": [M4], "why_rejected": "CPU is at 41%"}]})
    assert "P13-UNGROUNDED" in report.verdict.policy_ids
    assert any("M9 is not an evidence id" in r for r in report.verdict.reasons), report.verdict.reasons


def test_the_count_says_which_cause_it_is_for_when_the_model_worded_them_differently():
    """Review, PR 47: the count is the first ranked hypothesis's; when its words differ from the diagnosis's, both."""
    report, _ = _run({"hypothesis": "the 09:58 deploy broke checkout",
                      "hypotheses": [{"cause": "a bad release", "supporting": [D1, M1]},
                                     {"cause": "CPU saturation", "against": [M4], "why_rejected": "CPU is at 41%"}]})
    md = build_report(report.alert, root_cause=report.root_cause, proposal=report.proposal, verdict=report.verdict,
                      context=report.context).markdown
    assert "the count is for the cause it ranked first: a bad release" in md
    same, _ = _run(_ranked([D1, M1], rival_against=[M4]))
    md = build_report(same.alert, root_cause=same.root_cause, proposal=same.proposal, verdict=same.verdict,
                      context=same.context).markdown
    assert "the count is for the cause it ranked first" not in md


def test_a_models_explicit_null_is_no_rival_weighed_not_an_old_answer():
    """Plant check (PR 47): `"hypotheses": null` from the model is made [] in diagnose, so P35 applies - only a stored
    answer read back may carry None."""
    report, _ = _run({"hypothesis": "the deploy broke checkout", "citations": [D1, M1], "hypotheses": None})
    assert report.root_cause.hypotheses == []
    assert "P35-NO-RIVAL-HYPOTHESIS" in report.verdict.policy_ids
