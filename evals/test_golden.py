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
        assert case.alert["alert_id"] == case.id
        assert case.why
        assert case.logs is not None


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
    assert scored["pass_hat_k"] == 0.0
    assert scored["failed"][0]["passes"] == 0

    sometimes = _Answers(_answer("escalate_to_human", "oncall"), _answer("escalate_to_human", "oncall"),
                         _answer("restart_pods", service))
    scored = golden.score_no_fault([case], lambda: LLMClient(provider=sometimes, mock=False))
    assert scored["rows"][0]["passes"] == 2
    assert scored["pass_hat_k"] == 0.0


def test_a_quiet_close_is_counted_apart_from_a_hand_off():
    """A model's "no action" passes (nothing changes) but is not quiet while the gate escalates it: still a page."""
    case = golden.no_fault_cases()[0]
    quiet = _Answers(_answer("no_action", case.alert["service"]))
    scored = golden.score_no_fault([case], lambda: LLMClient(provider=quiet, mock=False))
    assert scored["rows"][0]["passes"] == 3
    assert scored["rows"][0]["outcomes"] == [("no_action", "escalated")]
    assert scored["quiet_hat_k"] == 0.0
    assert golden.Outcome("no_action", "auto_safe").quiet
    assert not golden.Outcome("escalate_to_human", "auto_safe").quiet
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
    assert len(noisy.logs) > len(case.logs)
    assert set(golden.NOISE_METRICS) <= set(noisy.metrics)


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
    assert out["model"] == "mock"
    assert out["pass_hat_k"] == 1.0
    assert out["perturbation_drift"] == []


@pytest.mark.parametrize(("action", "verdict", "no_fix"), [
    ("escalate_to_human", "auto_safe", True),
    ("no_action", "escalated", True),
    ("escalate_to_human", "approved_for_human", False),  # a verdict a person could approve is never "no fix"
    ("restart_pods", "escalated", False),                # nor is a change, even one the gate held back
    ("restart_pods", "rejected", False),
])
def test_what_counts_as_no_fix(action, verdict, no_fix):
    assert golden.Outcome(action, verdict).no_fix is no_fix


# --------------------------------------------------------------------------- the paid run's estimate and hard cap

def test_the_planned_runs_are_what_main_makes():
    no_fault, demo = len(golden.no_fault_cases()), len(golden.demo_cases())
    assert len(golden.planned_runs("no_fault")) == no_fault * golden.K
    assert len(golden.planned_runs("perturbation")) == (no_fault + demo) * (1 + len(golden.PERTURBATIONS))
    assert len(golden.planned_runs()) == len(golden.planned_runs("no_fault")) + len(golden.planned_runs("perturbation"))


def test_the_estimate_is_measured_from_the_rendered_prompts_at_the_listed_price():
    from warden.graph import SYSTEM_DIAGNOSE

    runs = golden.planned_runs("no_fault")[:6]
    chars = golden.prompt_chars(runs)
    assert len(chars) == 6
    assert all(c > len(SYSTEM_DIAGNOSE) for c in chars)
    assert golden.listed_price("claude-sonnet-5-5") == (2.0, 10.0)
    assert golden.listed_price("claude-opus-5-5") == (4.0, 20.0)
    est = golden.estimate("claude-opus-5-5", chars)
    want = sum(chars) / 4 * 4.0 / 1e6 + 6 * golden.EXPECTED_OUT_TOKENS * 20.0 / 1e6
    assert est["expected_usd"] == pytest.approx(want, abs=0.01)
    assert est["high_usd"] > est["expected_usd"]
    with pytest.raises(SystemExit, match="no row"):
        golden.listed_price("some-unpriced-model")


def _no_spend(*_a, **_kw):
    raise AssertionError("a paid client was made")


def test_live_needs_a_model_and_a_budget(monkeypatch):
    monkeypatch.setattr(golden, "Spend", _no_spend)
    for argv in (["--live"], ["--live", "--model", "claude-sonnet-5-5"], ["--live", "--budget-usd", "5"]):
        with pytest.raises(SystemExit):
            golden.main(argv)


def test_live_over_the_budget_prints_the_estimate_and_refuses_to_start(monkeypatch, capsys):
    monkeypatch.setattr(golden, "Spend", _no_spend)
    assert golden.main(["--live", "--model", "claude-opus-5-5", "--budget-usd", "0.5", "--suite", "no_fault"]) == 2
    out = capsys.readouterr()
    assert json.loads(out.out)["estimate"]["expected_usd"] > 0.5
    assert "refused" in out.err
    assert golden.main(["--live", "--model", "claude-opus-5-5", "--budget-usd", "1000", "--dry-run"]) == 0


def _paid_stand_in(monkeypatch, out_tokens: int):
    """Spend's clients answer through a stand-in at the listed price, each answer `out_tokens` long."""
    monkeypatch.setenv("WARDEN_MODEL", "claude-sonnet-5-5")  # main() sets it; restored after the test
    real = golden.LLMClient
    model = _Answers(_answer("escalate_to_human", "oncall"))
    model.model = "claude-sonnet-5-5"
    model.complete = lambda **_kw: Completion(_answer("escalate_to_human", "oncall"), 3_000, out_tokens)

    def client(**kw):
        kw.setdefault("provider", model)
        return real(**kw)
    monkeypatch.setattr(golden, "LLMClient", client)


def _run_until_stopped(spend, runs: int) -> None:
    """Runs one no-fault case again and again on the budget's clients; BudgetStop ends it."""
    case = golden.no_fault_cases()[0]
    for _ in range(runs):
        golden.run_case(case, spend.client())


def test_the_budget_is_a_hard_ceiling_even_when_every_answer_is_as_long_as_it_can_be(monkeypatch, capsys):
    from warden.providers import MAX_OUTPUT_TOKENS

    _paid_stand_in(monkeypatch, MAX_OUTPUT_TOKENS)
    budget = 3.0  # over the estimate (it starts), far under what 99 maximal answers cost (it must stop)
    assert golden.main(["--live", "--model", "claude-sonnet-5-5", "--budget-usd", str(budget),
                        "--suite", "no_fault"]) == 3
    assert "stopped" in capsys.readouterr().err
    spend = golden.Spend(budget, 10.0, 0.01)
    with pytest.raises(golden.BudgetStop):
        _run_until_stopped(spend, 1000)
    assert 0 < spend.spent() <= budget


def test_a_run_within_the_budget_completes_and_reports_what_it_spent(monkeypatch, capsys):
    _paid_stand_in(monkeypatch, 500)
    assert golden.main(["--live", "--model", "claude-sonnet-5-5", "--budget-usd", "3", "--suite", "no_fault"]) == 0
    out = json.loads(capsys.readouterr().out.split("\n}\n", 1)[1])
    assert out["pass_hat_k"] == 1.0
    assert 0 < out["spent_usd"] <= out["budget_usd"] == 3.0


def test_a_run_that_retries_cannot_spend_past_the_budget(monkeypatch):
    """A malformed answer is asked again (three attempts per run): each client is capped at what is left."""
    from warden.providers import MAX_OUTPUT_TOKENS

    monkeypatch.setenv("WARDEN_MODEL", "claude-sonnet-5-5")
    real = golden.LLMClient
    model = _Answers("not json")
    model.model = "claude-sonnet-5-5"
    model.complete = lambda **_kw: Completion("not json", 3_000, MAX_OUTPUT_TOKENS)
    monkeypatch.setattr(golden, "LLMClient", lambda **kw: real(**{"provider": model, **kw}))
    budget = 1.0
    spend = golden.Spend(budget, 10.0, 0.01)
    with pytest.raises(golden.BudgetStop):
        _run_until_stopped(spend, 100)
    assert 0 < spend.spent() <= budget
