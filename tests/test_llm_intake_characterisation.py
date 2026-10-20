"""Characterisation of LLMClient.__init__/.structured, webhooks._dd_event and investigation.widen, written BEFORE their
cognitive-complexity refactor (Sonar python:S3776) and passing on the code as it was: the same answers, the same
errors and messages, the same calls counted and charged, the same order."""

from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest
from pydantic import BaseModel

from warden import investigation, llm, webhooks
from warden.models import Alert, ContextBundle, Severity
from warden.providers import Completion, ProviderExhausted


class _Out(BaseModel):
    x: int


class _Status(Exception):
    def __init__(self, status):
        super().__init__(f"status {status}")
        self.status_code = status


class _Provider:
    """Answers from a script: a Completion is returned, an exception raised, a float slept."""

    name, model = "fake", "fake-model"

    def __init__(self, *script):
        self.script, self.calls = list(script), 0

    def complete(self, *, system, user, schema):
        self.calls += 1
        step = self.script.pop(0)
        if isinstance(step, float):
            time.sleep(step)
            return Completion('{"x": 1}', 1, 1)
        if isinstance(step, BaseException):
            raise step
        return step


def _ok(x=1, cut_off=False):
    return Completion(f'{{"x": {x}}}', 1000, 200, cut_off)


def _client(provider, **kw):
    return llm.LLMClient(provider=provider, mock=False, max_usd=kw.pop("max_usd", 1.0),
                         max_calls=kw.pop("max_calls", 5), call_timeout_s=kw.pop("call_timeout_s", 5.0), **kw)


def _ask(client, retries=2):
    return client.structured(system="sys", user="user", schema=_Out, retries=retries)


# --------------------------------------------------------------------------- LLMClient.__init__


@pytest.mark.parametrize("usd", [float("nan"), 0.0, -1.0, float("inf")])
def test_a_budget_that_is_not_a_positive_number_is_refused(usd):
    provider = _Provider()
    with pytest.raises(ValueError, match=r"^the model budget must be a positive number of USD, not "):
        llm.LLMClient(provider=provider, mock=False, max_usd=usd, max_calls=1, call_timeout_s=1.0)


@pytest.mark.parametrize(("env", "given", "result"), [
    (None, None, 8), ("6", None, 6), ("12", 3, 3), ("6", 1, 1),
])
def test_max_calls_comes_from_the_argument_then_the_environment_then_eight(monkeypatch, env, given, result):
    if env is None:
        monkeypatch.delenv("WARDEN_MAX_CALLS", raising=False)
    else:
        monkeypatch.setenv("WARDEN_MAX_CALLS", env)
    client = llm.LLMClient(provider=_Provider(), mock=False, max_usd=1.0, max_calls=given, call_timeout_s=1.0)
    assert client.max_calls == result


@pytest.mark.parametrize(("env", "given", "shown"), [
    ("six", None, "-1"), ("-2", None, "-1"), ("0", None, "0"), (None, 0, "0"), (None, True, "True"),
    (None, 2.0, "2.0"), (None, "3", "'3'"),
])
def test_max_calls_that_is_not_a_positive_whole_number_is_refused(monkeypatch, env, given, shown):
    if env is not None:
        monkeypatch.setenv("WARDEN_MAX_CALLS", env)
    provider = _Provider()
    with pytest.raises(ValueError, match=rf"^max_calls must be a positive whole number, not {shown}$"):
        llm.LLMClient(provider=provider, mock=False, max_usd=1.0, max_calls=given, call_timeout_s=1.0)


def test_the_budget_is_checked_before_max_calls(monkeypatch):
    provider = _Provider()
    with pytest.raises(ValueError, match="model budget"):
        llm.LLMClient(provider=provider, mock=False, max_usd=0.0, max_calls=0, call_timeout_s=1.0)


@pytest.mark.parametrize(("prices", "name"), [((float("nan"), 1.0), "WARDEN_PRICE_IN"),
                                              ((1.0, -1.0), "WARDEN_PRICE_OUT")])
def test_a_price_that_is_not_finite_and_non_negative_is_refused(monkeypatch, prices, name):
    monkeypatch.setattr(llm, "model_prices", lambda model: prices)
    provider = _Provider()
    with pytest.raises(ValueError, match=rf"^{name} must be a non-negative number of USD per 1M tokens"):
        llm.LLMClient(provider=provider, mock=False, max_usd=1.0, max_calls=1, call_timeout_s=1.0)


def test_the_call_timeout_is_the_argument_else_the_providers():
    assert _client(_Provider(), call_timeout_s=7.5).call_timeout_s == 7.5
    from warden.providers import call_timeout_s

    p = _Provider()
    assert llm.LLMClient(provider=p, mock=False, max_usd=1.0, max_calls=1).call_timeout_s == call_timeout_s(p)


# --------------------------------------------------------------------------- LLMClient.structured


def test_a_valid_first_answer_is_returned_and_charged_once():
    p = _Provider(_ok(7))
    c = _client(p)
    assert _ask(c) == _Out(x=7)
    assert (p.calls, c.cost.calls, c.cost.input_tokens, c.cost.output_tokens, c.unanswered) == (1, 1, 1000, 200, 0)


def test_an_invalid_answer_is_asked_again_and_each_is_charged():
    p = _Provider(Completion("not json", 10, 5), Completion('{"x": "no"}', 10, 5), _ok(3))
    c = _client(p)
    assert _ask(c) == _Out(x=3)
    assert (p.calls, c.cost.calls, c.cost.input_tokens) == (3, 3, 1020)


def test_three_invalid_answers_are_refused_naming_the_attempts_and_the_last_error():
    c = _client(_Provider(Completion("a", 1, 1), Completion("b", 1, 1), Completion('{"y": 1}', 1, 1)))
    with pytest.raises(llm.ModelRefused, match=r"^_Out not produced after 3 attempts: 1 validation error for _Out"):
        _ask(c)
    assert c.cost.calls == 3


def test_an_answer_cut_off_is_charged_and_not_asked_again():
    p = _Provider(_ok(cut_off=True), _ok())
    c = _client(p)
    with pytest.raises(llm.ModelRefused, match=r"^_Out not produced after 1 attempt: the answer was cut off at the "
                                               r"output cap; asking again would cut it off again$") as err:
        _ask(c)
    assert type(err.value) is llm.ModelRefused
    assert (p.calls, c.cost.calls, c.cost.input_tokens) == (1, 1, 1000)


def test_a_reply_the_provider_could_not_read_counts_as_a_call_and_is_asked_again():
    p = _Provider(ValueError("HTML 200"), _ok(2))
    c = _client(p)
    assert _ask(c) == _Out(x=2)
    assert (p.calls, c.cost.calls, c.cost.input_tokens, c.unanswered) == (2, 2, 1000, 0)


@pytest.mark.parametrize(("error", "calls", "unanswered"), [
    (_Status(503), 3, 3),                         # transient, answered with an error status: reached no model
    (_Status(429), 3, 3),
    (ConnectionRefusedError("refused"), 3, 3),    # never sent
    (RuntimeError("read timeout"), 3, 0),         # transient, and may have been processed
])
def test_a_transient_error_is_tried_three_times(error, calls, unanswered):
    p = _Provider(error, error, error)
    c = _client(p)
    with pytest.raises(llm.ModelRefused, match=rf"^_Out not produced after 3 attempts: {error}$"):
        _ask(c)
    assert (p.calls, c.cost.calls, c.cost.usd, c.unanswered) == (calls, calls, 0.0, unanswered)


@pytest.mark.parametrize(("error", "unanswered"), [(_Status(401), 1), (_Status(400), 1),
                                                  (_Status("403"), 0)])  # a status that is not a number: maybe sent
def test_a_permanent_error_is_not_tried_again(error, unanswered):
    p = _Provider(error, _ok())
    c = _client(p)
    with pytest.raises(llm.ModelRefused, match=rf"^_Out not produced after 1 attempt: {error}$"):
        _ask(c)
    assert (p.calls, c.cost.calls, c.unanswered) == (1, 1, unanswered)


def test_a_transient_error_then_an_answer():
    p = _Provider(_Status(500), _ok(4))
    c = _client(p)
    assert _ask(c) == _Out(x=4)
    assert (c.cost.calls, c.unanswered) == (2, 1)


@pytest.mark.parametrize("fatal", [llm.BudgetExceeded("over"), ProviderExhausted("empty")])
def test_a_blown_budget_or_an_exhausted_provider_stops_at_once(fatal):
    p = _Provider(fatal, _ok())
    c = _client(p)
    with pytest.raises(type(fatal), match=f"^{fatal}$"):
        _ask(c)
    assert (p.calls, c.cost.calls) == (1, 0)


def test_a_hung_call_counts_as_a_call_and_stops_the_run():
    p = _Provider(3.0, _ok())
    c = _client(p, call_timeout_s=0.0)
    with pytest.raises(llm.ModelCallTimeout, match=r"^model call exceeded 2s and was abandoned$"):
        _ask(c)
    assert (p.calls, c.cost.calls, c.cost.usd) == (1, 1, 0.0)


def test_the_call_ceiling_refuses_a_retry_before_it_is_sent():
    p = _Provider(Completion("bad", 1, 1), _ok())
    c = _client(p, max_calls=1)
    with pytest.raises(llm.BudgetExceeded, match=r"^a call would be number 2; the ceiling is 1$"):
        _ask(c)
    assert p.calls == 1


def test_a_prompt_over_the_ceiling_is_refused_before_any_call(monkeypatch):
    monkeypatch.setattr(llm, "MAX_PROMPT_TOKENS", 10)
    p = _Provider(_ok())
    client = _client(p)
    with pytest.raises(llm.BudgetExceeded, match=r"^prompt of ~\d+ tokens exceeds the 10 ceiling$"):
        _ask(client)
    assert p.calls == 0


def test_retries_zero_is_one_attempt():
    c = _client(_Provider(Completion("bad", 1, 1), _ok()))
    with pytest.raises(llm.ModelRefused, match=r"after 1 attempt: "):
        _ask(c, retries=0)


def test_mock_mode_needs_a_factory_and_charges_a_quarter_of_the_characters():
    c = llm.LLMClient(mock=True, max_usd=1.0, max_calls=2, call_timeout_s=1.0)
    with pytest.raises(llm.ModelRefused, match=r"^mock mode needs a mock_factory for _Out$"):
        c.structured(system="s" * 40, user="u" * 80, schema=_Out)
    assert c.cost.calls == 0
    assert c.structured(system="s" * 40, user="u" * 80, schema=_Out, mock_factory=lambda: _Out(x=9)) == _Out(x=9)
    assert (c.cost.calls, c.cost.input_tokens, c.cost.output_tokens) == (1, 30, 120)


# --------------------------------------------------------------------------- webhooks._dd_event

WHEN = datetime(2026, 10, 14, 7, 14, 13, tzinfo=UTC)


def _dd(**over):
    return {"monitor": "12345", "transition": "Triggered", "title": "[Triggered] warden dev: api errors",
            "date": str(int(WHEN.timestamp() * 1000)), "priority": "P2",
            "tags": "env:dev,service:catalog-api,kube_deployment:catalog-api,service:other,team:shop",
            "scope": "kube_namespace:shop functionname:fn1", **over}


def test_dd_event_exact():
    ev = webhooks._dd_event(_dd(), "prod")
    assert (ev.source, ev.rule, ev.state, ev.transitioned_at) == ("alarm", "datadog-12345", "ALARM", WHEN)
    a = ev.alert
    assert (a.alert_id, a.name, a.severity, a.service, a.environment, a.summary, a.started_at) == (
        "datadog-12345", "warden dev: api errors", Severity.high, "catalog-api", "dev", "warden dev: api errors",
        WHEN.isoformat())
    assert list(a.labels.items()) == [("namespace", "shop"), ("lambda", "fn1"), ("environment", "dev"),
                                      ("service", "catalog-api"), ("deployment", "catalog-api"),
                                      ("datadog_monitor", "12345"), ("alarm", "datadog-12345"), ("via", "datadog")]


def test_dd_event_defaults_and_states():
    ev = webhooks._dd_event({"monitor": "7", "transition": "Recovered"}, "qa")
    a = ev.alert
    assert (ev.state, ev.transitioned_at, a.name, a.summary, a.severity, a.service, a.environment) == (
        "OK", datetime.fromtimestamp(0, UTC), "datadog monitor", "datadog monitor", Severity.high, "unknown", "qa")
    assert webhooks._dd_event({"monitor": "7", "transition": "Warn"}, "qa") is None
    assert webhooks._dd_event({"monitor": "x", "transition": "Warn"}, "qa") is None, "the state is judged first"
    assert webhooks._dd_event(_dd(priority="P4", title="[x]  "), "qa").alert.severity == Severity.low
    long = webhooks._dd_event(_dd(tags="service:" + "s" * 300, scope=""), "qa").alert
    assert long.labels["service"] == "s" * 200


@pytest.mark.parametrize(("over", "error"), [({"monitor": "abc"}, ValueError), ({"monitor": ""}, ValueError),
                                            ({"monitor": "1" * 21}, ValueError), ({"date": "soon"}, ValueError)])
def test_dd_event_refusals(over, error):
    delivery = _dd(**over)
    with pytest.raises(error):
        webhooks._dd_event(delivery, "dev")


def test_dd_event_bad_date_is_judged_after_the_monitor():
    delivery = _dd(monitor="x", date="soon")
    with pytest.raises(ValueError, match="^no monitor id$"):
        webhooks._dd_event(delivery, "dev")


# --------------------------------------------------------------------------- investigation.widen


def _inc(**labels):
    return Alert(alert_id="i-1", name="HighErrors", severity=Severity.high, service="checkout", environment="dev",
                 summary="s", started_at=WHEN.isoformat(), labels=labels)


_WIDEN_CONTEXT = ContextBundle(logs=["STATE sqs warden-dev-q2 Messages=3",
                                     "CONFIG lambda warden-dev-fn2 timeout=3 role=warden-dev-r1"])


def test_widen_refuses_with_each_reason_in_order():
    alert = _inc(sqs="warden-dev-q1", s3_bucket="warden-dev-b1")
    requests = [
        {"kind": "secret", "name": "warden-dev-s"},                # not READABLE
        {"kind": "sqs", "name": "bad name!"},                      # not a token
        {"kind": "sqs", "name": "warden-prod-q2"},                 # another environment
        {"kind": "sqs", "name": "warden-dev-unknown"},             # not known
        {"kind": "sqs", "name": "warden-dev-q1"},                  # already read
        {"kind": "s3_bucket", "name": "warden-dev-fn2"},           # loose knowledge, but another bucket is read
        {"kind": "sqs", "name": "warden-dev-q2"},                  # past the 2 x 3 requests read: not even refused
    ]
    widened, accepted, refused = investigation.widen(alert, _WIDEN_CONTEXT, requests)
    assert accepted == []
    assert refused == [{"kind": r["kind"], "name": r["name"], "why": why} for r, why in zip(requests, [
        "not a resource kind WARDEN reads through the environment's reader role",
        "not a plain resource name",
        "not a resource of the incident's environment",
        "the name is not WARDEN's own knowledge for that kind",
        "already read",
        "another s3_bucket is already read",
    ], strict=False)]
    assert widened.labels == alert.labels


def test_widen_accepts_up_to_the_cap_in_order():
    alert = _inc(sqs="warden-dev-q1")
    requests = [
        {"kind": "sqs", "name": "warden-dev-q2"},                  # a STATE line of its kind; a list kind
        {"kind": "lambda", "name": "warden-dev-fn2"},              # a token of a trusted line
        {"kind": "lambda", "name": "warden-dev-r1"},               # a second of a list kind
        {"kind": "sqs", "name": "warden-dev-q9"},                  # the cap
        {"kind": 5, "name": None},
    ]
    widened, accepted, refused = investigation.widen(alert, _WIDEN_CONTEXT, requests)
    assert accepted == [{"kind": "sqs", "name": "warden-dev-q2"}, {"kind": "lambda", "name": "warden-dev-fn2"},
                        {"kind": "lambda", "name": "warden-dev-r1"}]
    assert refused == [{"kind": "sqs", "name": "warden-dev-q9", "why": "at most 3 per round"},
                       {"kind": "5", "name": "None", "why": "at most 3 per round"}]
    assert list(widened.labels.items()) == [("sqs", "warden-dev-q1,warden-dev-q2"),
                                            ("lambda", "warden-dev-fn2,warden-dev-r1")]


def test_widen_reads_at_most_twice_the_cap_and_trims_what_it_echoes():
    long = "x" * 300
    requests = [{"kind": long, "name": long}] * 10
    _, accepted, refused = investigation.widen(_inc(), ContextBundle(), requests)
    assert accepted == []
    assert len(refused) == investigation.MAX_REQUESTS * 2
    assert refused[0] == {"kind": "x" * 40, "name": "x" * 120,
                          "why": "not a resource kind WARDEN reads through the environment's reader role"}


def test_widen_a_label_value_is_not_knowledge_for_another_kind():
    alert = _inc(sqs="warden-dev-shared")
    context = ContextBundle(logs=["CONFIG x warden-dev-shared"])
    _, accepted, refused = investigation.widen(alert, context, [{"kind": "sns_topic", "name": "warden-dev-shared"}])
    assert accepted == []
    assert refused[0]["why"] == "the name is not WARDEN's own knowledge for that kind"
