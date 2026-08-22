"""Tests for the LIVE model path — the code that runs when AEGIS is not in mock mode.

This file exists because coverage measurement showed `llm.py` at **60%**: every test in the repo
ran in mock mode, so the retry loop, the JSON extraction and the token accounting had never
executed once. "All tests pass" was true and meant less than it looked.

A fake provider stands in for the network. That is not a compromise — it is the only way to test
the failure modes that matter (a model returning prose, fenced JSON, or garbage three times) on
demand rather than by waiting for them to happen in production.
"""

import time

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


class _HangingProvider:
    """A provider whose call never returns in time — a dead key that makes the SDK retry endlessly,
    or a wedged network. Observed live when a rotated Gemini key hung the whole run."""

    name = "hang"
    model = "hang-1"

    def complete(self, *, system: str, user: str) -> Completion:
        time.sleep(30)
        return Completion("{}", 1, 1)


def test_a_hung_model_call_times_out_fast_instead_of_hanging_the_run():
    """The budget stops COST; this stops TIME. Without it a hung provider hangs the run forever.

    The assertion is on WHEN control returns: ~2s (the ceiling), not ~30s (the provider's sleep). A
    ModelCallTimeout is not caught by the retry loop, so it stops the run immediately rather than
    retrying into three consecutive hangs.
    """
    from aegis.llm import ModelCallTimeout

    c = LLMClient(provider=_HangingProvider(), mock=False, call_timeout_s=2.0)
    started = time.monotonic()
    with pytest.raises(ModelCallTimeout):
        c.structured(system="s", user="u", schema=Toy, retries=2)
    elapsed = time.monotonic() - started
    # ceiling = call_timeout_s + 2s backstop = 4s; must be far below the 30s sleep, and it must NOT
    # have burned all three retries (~90s) — a timeout is not retried.
    assert elapsed < 12, f"the wall-clock did not fire: waited {elapsed:.1f}s"


class _FlakyProvider:
    """Raises a transient error on the first N calls, then returns valid JSON — a 503/429/reset."""

    name = "flaky"
    model = "flaky-1"

    def __init__(self, fail_times: int) -> None:
        self.fail_times = fail_times
        self.calls = 0

    def complete(self, *, system: str, user: str) -> Completion:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise ProviderError("503 Service Unavailable")
        return Completion('{"answer": "ok", "score": 1}', 100, 50)


def test_a_transient_provider_error_is_retried_not_fatal():
    """The provider SDKs' internal retries are disabled because AEGIS retries here. So a flaky 503
    that would succeed on the next attempt must be RETRIED, not abort the whole run on the first hit.
    This is the regression an adversarial review caught after SDK retries were turned off."""
    p = _FlakyProvider(fail_times=1)
    out = LLMClient(provider=p, mock=False).structured(system="s", user="u", schema=Toy, retries=2)
    assert out.answer == "ok"
    assert p.calls == 2, "the transient error was not retried"


def test_persistent_provider_errors_end_in_ModelRefused_not_a_raw_traceback():
    p = _FlakyProvider(fail_times=99)
    with pytest.raises(ModelRefused):
        LLMClient(provider=p, mock=False).structured(system="s", user="u", schema=Toy, retries=2)
    assert p.calls == 3  # initial + 2 retries, all transient failures


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
