"""B37: the no-fault golden set (pass^k, k=3) and the perturbation suite, offline (the mock model, no network)."""

from __future__ import annotations

import json
import re

import pytest

import golden
from warden.llm import LLMClient
from warden.models import Alert
from warden.providers import Completion


def _mock() -> LLMClient:
    return LLMClient(mock=True)


def test_the_no_fault_set_is_large_enough_and_well_formed():
    cases = golden.no_fault_cases()
    assert len(cases) >= 30
    assert len({c.id for c in cases}) == len(cases)
    for case in cases:
        Alert(**case.alert)  # a real alert, held to the model's own validation
        assert case.alert["alert_id"] == case.id and case.why and case.logs is not None


@pytest.mark.parametrize(("passes", "n", "k", "expected"), [
    ([3, 3], 3, 3, 1.0),
    ([3, 2], 3, 3, 0.5),        # 2 of 3 is a failure under pass^3, though pass@1 would give it 2/3
    ([4], 5, 3, 0.4),           # C(4,3) / C(5,3)
    ([1, 0], 1, 1, 0.5),
])
def test_pass_hat_k(passes, n, k, expected):
    assert golden.pass_hat_k(passes, n, k) == pytest.approx(expected)


@pytest.mark.parametrize(("passes", "n", "k"), [([3], 3, 4), ([3], 3, 0), ([4], 3, 3), ([], 3, 3)])
def test_pass_hat_k_refuses_what_it_cannot_score(passes, n, k):
    with pytest.raises(ValueError):
        golden.pass_hat_k(passes, n, k)


def test_every_no_fault_case_ends_with_no_fix_every_time():
    scored = golden.score_no_fault(golden.no_fault_cases(), _mock)
    assert (scored["n"], scored["k"]) == (3, 3)
    assert scored["failed"] == [], json.dumps(scored["failed"], indent=1)
    assert scored["pass_hat_k"] == pytest.approx(1.0)
    # Offline the answer is the same each time; a case with two outcomes means the deterministic half is not.
    assert all(len(row["outcomes"]) == 1 for row in scored["rows"])


class _Answers:
    """A model that gives the listed answers in turn, across every client the factory makes."""

    name = "scripted"
    model = "scripted-1"

    def __init__(self, *answers: str) -> None:
        self._answers, self.calls = answers, 0

    def complete(self, *, system: str, user: str, schema=None):
        text = self._answers[self.calls % len(self._answers)]
        self.calls += 1
        return Completion(text, 10, 5)


def _answer(action: str, target: str, confidence: float = 0.9) -> str:
    return json.dumps({"root_cause": {"hypothesis": "h", "confidence": confidence, "evidence": ["e"]},
                       "proposal": {"action": action, "target": target, "reasoning": "r", "expected_effect": "e",
                                    "blast_radius": "single_pod", "reversible": True}})


def test_a_model_that_invents_a_fix_fails_the_case_and_one_that_does_so_once_in_three_fails_pass_hat_3():
    case = next(c for c in golden.no_fault_cases() if c.id == "nf-healthy-deploy")
    service = case.alert["service"]
    always = _Answers(_answer("restart_pods", service))
    scored = golden.score_no_fault([case], lambda: LLMClient(provider=always, mock=False))
    assert scored["pass_hat_k"] == 0.0 and scored["failed"][0]["passes"] == 0

    sometimes = _Answers(_answer("escalate_to_human", "oncall"), _answer("escalate_to_human", "oncall"),
                         _answer("restart_pods", service))
    scored = golden.score_no_fault([case], lambda: LLMClient(provider=sometimes, mock=False))
    assert scored["rows"][0]["passes"] == 2 and scored["pass_hat_k"] == 0.0


def test_a_quiet_close_is_counted_apart_from_a_hand_off():
    """A model's "no action" passes (nothing changes) but is not quiet while the gate escalates it: still a page."""
    case = golden.no_fault_cases()[0]
    quiet = _Answers(_answer("no_action", case.alert["service"]))
    scored = golden.score_no_fault([case], lambda: LLMClient(provider=quiet, mock=False))
    assert scored["rows"][0]["passes"] == 3 and scored["rows"][0]["outcomes"] == [("no_action", "escalated")]
    assert scored["quiet_hat_k"] == 0.0
    assert golden.Outcome("no_action", "auto_safe").quiet and not golden.Outcome("escalate_to_human", "auto_safe").quiet
    # The mock always hands off: safe, but a page nobody needed - the number a live run should raise.
    assert golden.score_no_fault([case], _mock)["quiet_hat_k"] == 0.0


ALL_CASES = golden.demo_cases() + golden.no_fault_cases()


@pytest.mark.parametrize("case", ALL_CASES, ids=[c.id for c in ALL_CASES])
def test_perturbations_change_the_input(case):
    renamed = golden.rename(case)
    old = case.alert["service"]
    assert renamed.alert["service"] != old
    word = re.compile(rf"(?<![A-Za-z0-9-]){re.escape(old)}(?![A-Za-z0-9-])")
    assert not any(word.search(line) for line in renamed.logs), renamed.logs
    if len(set(case.logs)) > 1:
        assert golden.reorder(case).logs != case.logs
    noisy = golden.add_noise(case)
    assert len(noisy.logs) > len(case.logs) and set(golden.NOISE_METRICS) <= set(noisy.metrics)


def test_no_perturbation_changes_any_outcome():
    drift = golden.perturbation_drift(ALL_CASES, _mock)
    assert drift == [], json.dumps(drift, indent=1)


def test_the_demo_incidents_still_reach_their_fixes_through_the_golden_backend():
    """The perturbation suite compares against real outcomes: the five demo incidents are not all hand-offs."""
    outcomes = {c.id: golden.Outcome.of(golden.run_case(c, _mock())) for c in golden.demo_cases()}
    assert sum(not o.no_fix for o in outcomes.values()) == 4, outcomes


def test_offline_main_reports_a_clean_run(capsys):
    assert golden.main([]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["model"] == "mock" and out["pass_hat_k"] == 1.0 and out["perturbation_drift"] == []


@pytest.mark.parametrize(("action", "verdict", "no_fix"), [
    ("escalate_to_human", "auto_safe", True),
    ("no_action", "escalated", True),
    ("escalate_to_human", "approved_for_human", False),  # a verdict a person could approve is never "no fix"
    ("restart_pods", "escalated", False),                # nor is a change, even one the gate held back
    ("restart_pods", "rejected", False),
])
def test_what_counts_as_no_fix(action, verdict, no_fix):
    assert golden.Outcome(action, verdict).no_fix is no_fix
