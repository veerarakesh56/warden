"""Tests for the LIVE model path — the code that runs when AEGIS is not in mock mode.

This file exists because coverage measurement showed `llm.py` at **60%**: every test in the repo
ran in mock mode, so the retry loop, the JSON extraction and the token accounting had never
executed once. "All tests pass" was true and meant less than it looked.

A fake provider stands in for the network. That is not a compromise — it is the only way to test
the failure modes that matter (a model returning prose, fenced JSON, or garbage three times) on
demand rather than by waiting for them to happen in production.
"""

import pytest
from pydantic import BaseModel

from aegis.llm import BudgetExceeded, LLMClient, ModelRefused, extract_json
from aegis.providers import Completion, ProviderError, resolve


class Toy(BaseModel):
    answer: str
    score: int


class FakeProvider:
    """Returns a scripted sequence of responses, so retry behaviour is deterministic."""

    name = "fake"
    model = "fake-1"

    def __init__(self, *responses: str, in_tok: int = 100, out_tok: int = 50) -> None:
        self._responses = list(responses)
        self.calls = 0
        self._in, self._out = in_tok, out_tok

    def complete(self, *, system: str, user: str) -> Completion:
        self.calls += 1
        text = self._responses[min(self.calls - 1, len(self._responses) - 1)]
        return Completion(text, self._in, self._out)


def _client(provider, **kw):
    return LLMClient(provider=provider, mock=False, **kw)


# --------------------------------------------------------------------- extract_json


@pytest.mark.parametrize(
    "raw",
    [
        '{"answer": "yes", "score": 1}',
        '```json\n{"answer": "yes", "score": 1}\n```',
        '```\n{"answer": "yes", "score": 1}\n```',
        'Here is the result:\n{"answer": "yes", "score": 1}\nHope that helps.',
    ],
    ids=["bare", "json-fence", "plain-fence", "prose-wrapped"],
)
def test_extract_json_handles_every_shape_providers_actually_return(raw):
    assert extract_json(raw) == '{"answer": "yes", "score": 1}'


@pytest.mark.parametrize("raw", ["no json here", "", "}{"])
def test_extract_json_refuses_rather_than_guessing(raw):
    with pytest.raises(ValueError):
        extract_json(raw)


# --------------------------------------------------------------------- the live call path


def test_a_good_response_is_parsed_and_charged():
    p = FakeProvider('{"answer": "ok", "score": 7}')
    c = _client(p)
    out = c.structured(system="s", user="u", schema=Toy)

    assert out.answer == "ok" and out.score == 7
    assert p.calls == 1
    assert c.cost.calls == 1
    assert c.cost.input_tokens == 100 and c.cost.output_tokens == 50
    assert c.cost.usd > 0


def test_a_bad_response_is_retried_then_succeeds():
    p = FakeProvider("total nonsense", '{"answer": "ok", "score": 1}')
    out = _client(p).structured(system="s", user="u", schema=Toy)
    assert out.answer == "ok"
    assert p.calls == 2


def test_persistent_garbage_raises_rather_than_returning_something_unvalidated():
    p = FakeProvider("nope")
    with pytest.raises(ModelRefused):
        _client(p).structured(system="s", user="u", schema=Toy, retries=2)
    assert p.calls == 3  # initial + 2 retries


def test_a_schema_violation_is_not_accepted():
    """Right shape, wrong types. Validation must reject it, not coerce it through."""
    p = FakeProvider('{"answer": "ok", "score": "not-a-number"}')
    with pytest.raises(ModelRefused):
        _client(p).structured(system="s", user="u", schema=Toy, retries=0)


def test_failed_attempts_still_cost_money():
    """A budget that only counts SUCCESSFUL calls can be drained by a model that keeps failing."""
    p = FakeProvider("garbage")
    c = _client(p)
    with pytest.raises(ModelRefused):
        c.structured(system="s", user="u", schema=Toy, retries=2)
    assert c.cost.calls == 3, "retries were not charged"


def test_the_budget_stops_a_run_mid_retry():
    p = FakeProvider("garbage")
    c = _client(p, max_usd=0.0004)
    with pytest.raises(BudgetExceeded):
        c.structured(system="s", user="u", schema=Toy, retries=5)
    assert p.calls < 6, "the ceiling did not interrupt the retry loop"


def test_call_ceiling_is_enforced_across_separate_calls():
    p = FakeProvider('{"answer": "ok", "score": 1}')
    c = _client(p, max_calls=2, max_usd=999)
    c.structured(system="s", user="u", schema=Toy)
    c.structured(system="s", user="u", schema=Toy)
    with pytest.raises(BudgetExceeded):
        c.structured(system="s", user="u", schema=Toy)


def test_provider_and_model_are_reported_for_the_audit_trail():
    c = _client(FakeProvider('{"answer": "a", "score": 1}'))
    assert c.provider_name == "fake"
    assert c.model == "fake-1"


# --------------------------------------------------------------------- provider resolution


def test_unknown_provider_fails_loudly_with_the_valid_options():
    with pytest.raises(ProviderError) as exc:
        resolve("not-a-real-provider")
    assert "gemini" in str(exc.value)


def test_gemini_without_a_key_says_where_to_get_one(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with pytest.raises(ProviderError) as exc:
        resolve("gemini")
    assert "aistudio.google.com" in str(exc.value)
