"""Item 7 leftovers (owner, 2026-10-21).

(2) One metadata-only `llm.call` row per model request - ts, model, prompt_tokens, completion_tokens, latency_ms,
cost (USD: the usage at the model's prices, llm.model_prices) - for the diagnosis, the discussion and Eldane; and no
log line anywhere on the model path holds the prompt or the answer.
(3) Each time WARDEN goes on without the model's answer, exactly one `llm.fallback` row with one reason from a closed
set: rules_only | model_refused | budget_cap | provider_unavailable."""

from __future__ import annotations

import logging
from typing import Any

import pytest

from test_eldane_autonomy import FakeModel, _review
from test_eldane_autonomy import world as eldane_world  # noqa: F401 - the fixture, read by _eldane
from warden import activities, audit, autonomy, discuss, eldane, llm, paging
from warden.activities import DiscussActivities, IncidentActivities
from warden.cli import DEMO_ALERTS
from warden.graph import Diagnosis
from warden.llm import LLMClient
from warden.models import Alert
from warden.providers import Completion, ProviderError

# Canaries built from parts: neither may reach a log line.
CANARY_PROMPT = "canary-" + "prompt-" + "5d1e"
CANARY_ANSWER = "canary-" + "answer-" + "9b7c"
CALL_FIELDS = {"ts", "model", "prompt_tokens", "completion_tokens", "latency_ms", "cost", "ok", "where", "run_id"}
REASON = "reason"
DIAGNOSE = "diagnose"


class Scripted:
    name, model = "fake", "fake-1"

    def __init__(self, *script: Any) -> None:
        self.script, self.calls = list(script), 0

    def complete(self, *, system: str, user: str, schema: Any = None) -> Completion:
        self.calls += 1
        step = self.script[min(self.calls - 1, len(self.script) - 1)]
        if isinstance(step, BaseException):
            raise step
        return step if isinstance(step, Completion) else Completion(step, 1000, 200)


def _status(code: int) -> ProviderError:
    err = ProviderError(f"HTTP {code}")
    err.status_code = code
    return err


def _acts(tmp_path, factory):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    return log, IncidentActivities(audit=log, llm_factory=factory)


def _diagnose(tmp_path, factory, escalate_only=""):
    log, acts = _acts(tmp_path, factory)
    pack = acts.prepare(Alert(**DEMO_ALERTS["inc-002"]))
    acts.diagnose(pack, escalate_only)
    return log, pack.alert.alert_id


def _rows(log, key, kind):
    return [e["body"] for e in log.entries(key, kinds=(kind,))]


def _reasons(log, key=None):
    return [r[REASON] for r in _rows(log, key, llm.FALLBACK)]


# --------------------------------------------------------------------------- (2) one llm.call row per request


def test_each_request_of_a_diagnosis_has_one_metadata_only_row_with_its_cost(tmp_path):
    p = Scripted("not json", _status(503), "still not json")
    log, key = _diagnose(tmp_path, lambda: LLMClient(provider=p, mock=False))
    rows = _rows(log, key, llm.CALL)
    assert p.calls == 3
    assert len(rows) == 3
    prices = llm.model_prices("fake-1")
    for row, answered in zip(rows, (True, False, True), strict=True):
        assert set(row) == CALL_FIELDS
        assert row["model"] == "fake-1"
        assert row["ok"] is answered
        assert row["latency_ms"] >= 0
        tokens = (1000, 200) if answered else (0, 0)
        assert row["prompt_tokens"] == tokens[0]
        assert row["completion_tokens"] == tokens[1]
        assert row["cost"] == pytest.approx(llm.usd(prices, *tokens))
        assert row["where"] == DIAGNOSE


def test_the_cost_is_the_one_the_budget_charges(tmp_path):
    client = LLMClient(provider=Scripted('{"answer": "x"}'), mock=False)
    with pytest.raises(llm.ModelRefused):
        client.structured(system="s", user="u", schema=Diagnosis, retries=0)
    assert sum(c["cost"] for c in client.calls) == pytest.approx(client.cost.usd)


def test_a_mock_diagnosis_has_its_one_row(tmp_path):
    log, key = _diagnose(tmp_path, lambda: LLMClient(mock=True))
    [row] = _rows(log, key, llm.CALL)
    assert set(row) == CALL_FIELDS
    assert row["model"] == "mock"


def test_a_discussion_answer_has_its_row(tmp_path):
    log, inc = _acts(tmp_path, lambda: LLMClient(mock=True))
    acts = DiscussActivities(audit=log, incident=inc, policy=None)
    thread = discuss.Thread(incident="inc-1", lines=["a person: q"])
    acts.discuss_answer(_turn(), thread, {"evidence": "e", "diagnosis": "d"}, False)
    [row] = _rows(log, "discuss-inc-1", llm.CALL)
    assert set(row) == CALL_FIELDS
    assert row["where"] == "discuss"


def test_each_of_eldanes_questions_has_its_row(request):
    critic_world = _eldane(request)
    _review(critic_world)
    rows = _rows(critic_world["log"], None, llm.CALL)
    assert len(rows) == 2
    assert len(critic_world["model"].prompts) == 2
    prices = llm.model_prices(FakeModel.model)
    for row in rows:
        assert set(row) == CALL_FIELDS
        assert row["where"] == "eldane"
        assert row["cost"] == pytest.approx(llm.usd(prices, 10, 10))


def _eldane(request):
    """Eldane's test world (test_eldane_autonomy's fixture), by name: no parameter shadows the import."""
    return request.getfixturevalue("eldane_world")


def _turn(text="why?"):
    return discuss.Turn(channel="C0123456", ts="1760000000.000200", thread_ts="1760000000.000100", user="U1234567", text=text,
                        environment="dev")


# --------------------------------------------------------------------------- (2) no prompt or answer in any log line


def _logged(caplog) -> str:
    out = []
    for r in caplog.records:
        out += [r.getMessage(), str(r.args), r.exc_text or "", str(getattr(r, "exc_info", "") or "")]
    return "\n".join(out)


def test_no_log_line_holds_the_prompt_or_the_answer(tmp_path, caplog, request):
    critic_world = _eldane(request)
    caplog.set_level(logging.DEBUG)  # the root, so every logger's record is captured
    for name in list(logging.root.manager.loggerDict):
        caplog.set_level(logging.DEBUG, logger=name)  # restored at teardown, as the root's is (CodeRabbit, PR 176)
    answer = f'{{"answer": "{CANARY_ANSWER}", "cites": []}}'
    # The client itself: an invalid answer twice (each retried), then a valid one.
    client = LLMClient(provider=Scripted(f"no json {CANARY_ANSWER}", _status(503), answer), mock=False)
    client.structured(system="s", user=CANARY_PROMPT, schema=discuss.Answer)
    # A diagnosis whose every answer is invalid: the rules-only path, with the model's text in its error.
    (tmp_path / "d").mkdir()
    _diagnose(tmp_path / "d", lambda: LLMClient(provider=Scripted(f"not json {CANARY_ANSWER}"), mock=False))
    # A discussion: the person's words are the canary prompt, the model's answer the canary answer.
    log, inc = _acts(tmp_path, lambda: LLMClient(provider=Scripted(answer), mock=False))
    DiscussActivities(audit=log, incident=inc, policy=None).discuss_answer(
        _turn(CANARY_PROMPT), discuss.Thread(incident="inc-1", lines=[f"a person: {CANARY_PROMPT}"]),
        {"evidence": CANARY_PROMPT, "diagnosis": "d"}, False)
    # A discussion whose model answers an object without the answer field: pydantic's error quotes that object - the
    # canary - and the person is told while the worker logs it.
    log, inc = _acts(tmp_path / "d", lambda: LLMClient(provider=Scripted(f'{{"cites": "{CANARY_ANSWER}"}}'),
                                                       mock=False))
    DiscussActivities(audit=log, incident=inc, policy=None).discuss_answer(
        _turn(CANARY_PROMPT), discuss.Thread(incident="inc-2", lines=[f"a person: {CANARY_PROMPT}"]),
        {"evidence": CANARY_PROMPT, "diagnosis": "d"}, False)
    # Eldane, answering with the canary - unreadable, so a "no".
    critic_world["model"].answer = CANARY_ANSWER
    _review(critic_world)
    assert caplog.records  # the run did log - the scan is not of nothing
    text = _logged(caplog)
    assert text.count(CANARY_PROMPT) == 0
    assert text.count(CANARY_ANSWER) == 0


def _exported(exporter) -> str:
    """Everything a span exporter would send: names, attributes, events and their attributes, status descriptions."""
    out = []
    for sp in exporter.get_finished_spans():
        out += [sp.name, str(dict(sp.attributes or {})), str(sp.status.description or "")]
        out += [f"{ev.name} {dict(ev.attributes or {})}" for ev in sp.events]
    return "\n".join(out)


def test_no_exported_span_holds_the_prompt_or_the_answer(tmp_path, monkeypatch, request):
    """With otlp_exporter on, spans leave the account for the owner's collector (item 7b): a new destination. What
    they carry is metadata - never the prompt or the answer, not even inside an error's text."""
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from warden import observability

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(observability, "tracer", lambda: provider.get_tracer("canary"))
    answers = (f"not json {CANARY_ANSWER}", f'{{"root_cause": "{CANARY_ANSWER}"}}', _status(503))
    for i, answer in enumerate(answers):
        (tmp_path / str(i)).mkdir()
        _, acts = _acts(tmp_path / str(i), lambda a=answer: LLMClient(provider=Scripted(a), mock=False))
        pack = acts.prepare(Alert(**DEMO_ALERTS["inc-002"]))
        acts.diagnose(pack.model_copy(update={"prompt": f"{CANARY_PROMPT}\n{pack.prompt}"}))
    critic_world = _eldane(request)
    critic_world["model"].answer = CANARY_ANSWER
    _review(critic_world)
    assert exporter.get_finished_spans()  # spans were made - the scan is not of nothing
    text = _exported(exporter)
    assert text.count(CANARY_PROMPT) == 0
    assert text.count(CANARY_ANSWER) == 0


def test_a_mock_answer_that_failed_is_a_call_not_answered():
    client = LLMClient(mock=True)

    def broken():
        raise ValueError("no answer")

    with pytest.raises(ValueError, match="no answer"):
        client.structured(system="s", user="u", schema=Diagnosis, mock_factory=broken)
    assert [c["ok"] for c in client.calls] == [False]


# --------------------------------------------------------------------------- (3) exactly one llm.fallback row


def test_an_answered_diagnosis_is_no_fallback(tmp_path):
    log, key = _diagnose(tmp_path, lambda: LLMClient(mock=True))
    assert _reasons(log, key) == []


@pytest.mark.parametrize(("script", "reason"), [
    ((_status(503),), llm.PROVIDER_UNAVAILABLE),
    ((ProviderError("connection reset"),), llm.PROVIDER_UNAVAILABLE),
    (("not json",), llm.MODEL_REFUSED),
    ((Completion('{"a": ', 10, 5, refused=True),), llm.MODEL_REFUSED),
    ((_status(401),), llm.MODEL_REFUSED),
], ids=["503", "no-status", "bad-json", "refusal", "bad-key"])
def test_a_failed_diagnosis_is_one_fallback_with_its_reason(tmp_path, script, reason):
    log, key = _diagnose(tmp_path, lambda: LLMClient(provider=Scripted(*script), mock=False))
    assert _reasons(log, key) == [reason]


def test_a_spent_incident_budget_is_one_budget_cap(tmp_path):
    log, key = _diagnose(tmp_path, lambda: LLMClient(provider=Scripted("not json"), mock=False, max_usd=0.0001))
    assert _reasons(log, key) == [llm.BUDGET_CAP]


def test_the_daily_cap_is_one_budget_cap_per_incident(tmp_path):
    log, acts = _acts(tmp_path, lambda: LLMClient(mock=True))
    log.append("earlier", "incident.llm_spend", {"attempt": "a", "calls": 1, "usd": activities.DAILY_MAX_USD + 1,
                                                 "input_tokens": 0, "output_tokens": 0})
    pack = acts.prepare(Alert(**DEMO_ALERTS["inc-002"]))
    acts.diagnose(pack)
    assert _reasons(log, pack.alert.alert_id) == [llm.BUDGET_CAP]


@pytest.mark.parametrize("escalate", ["flapping", ""], ids=["escalate-only", "no-model"])
def test_the_rules_alone_is_one_rules_only(tmp_path, escalate):
    def broken():
        raise ProviderError("not qualified")

    log, key = _diagnose(tmp_path, (lambda: LLMClient(mock=True)) if escalate else broken, escalate_only=escalate)
    assert _reasons(log, key) == [llm.RULES_ONLY]


def test_a_discussion_without_an_answer_is_one_fallback(tmp_path):
    log, inc = _acts(tmp_path, lambda: LLMClient(provider=Scripted(_status(503)), mock=False))
    acts = DiscussActivities(audit=log, incident=inc, policy=None)
    thread = discuss.Thread(incident="inc-1", lines=["a person: q"])
    assert acts.discuss_answer(_turn(), thread, {"evidence": "e", "diagnosis": "d"}, False) == discuss.NO_ANSWER
    log.append("discuss-inc-1", "incident.llm_spend", {"attempt": "x", "calls": discuss.DAILY_CALLS, "usd": 0})
    assert acts.discuss_answer(_turn(), thread, {"evidence": "e", "diagnosis": "d"}, False) == discuss.LIMIT
    assert _reasons(log, "discuss-inc-1") == [llm.PROVIDER_UNAVAILABLE, llm.BUDGET_CAP]


@pytest.mark.parametrize(("failure", "reason"), [
    (ConnectionError("down"), llm.PROVIDER_UNAVAILABLE), ("not a verdict", llm.MODEL_REFUSED)],
    ids=["outage", "unreadable"])
def test_eldane_without_an_answer_is_one_fallback(request, failure, reason):
    critic_world = _eldane(request)
    if isinstance(failure, BaseException):
        def down(**kw):
            raise failure
        critic_world["model"].complete = down
    else:
        critic_world["model"].answer = failure
    _review(critic_world)
    assert _reasons(critic_world["log"]) == [reason]  # the first "no" ends the review: one question, one row


def test_a_catch_trial_eldane_could_not_answer_is_no_second_fallback(request):
    """A catch trial asks about a planted plan WARDEN never acts on: with the provider down, the plan's own question
    is the one fallback - the trial's failure is unscored, not a second row for the same plan."""
    critic_world = _eldane(request)

    def down(**kw):
        raise ConnectionError("down")

    critic_world["model"].complete = down
    _review(critic_world, chance=lambda n: 0)  # 0: a catch trial this time
    assert len(critic_world["log"].entries(kinds=(autonomy.TRIAL,))) == 1  # the trial was asked
    assert _reasons(critic_world["log"]) == [llm.PROVIDER_UNAVAILABLE]


def test_eldanes_daily_cap_is_one_budget_cap(request):
    critic_world = _eldane(request)
    for _ in range(eldane.DAILY_CALLS):
        critic_world["log"].append("other", eldane.CALL, {"ok": True})
    for _ in range(3):
        _review(critic_world)
    assert _reasons(critic_world["log"]) == [llm.BUDGET_CAP] * 3  # one per plan it could not review
    # ...and the daily call cap pages once, however many plans it stops (item 7c).
    assert [e["body"]["condition"] for e in critic_world["log"].entries("pages", kinds=(paging.MODEL_PAGED,))] == \
        [paging.DAILY_CAP]


def test_the_reasons_are_a_closed_set(tmp_path):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    assert sorted(llm.FALLBACK_REASONS) == ["budget_cap", "model_refused", "provider_unavailable", "rules_only"]
    with pytest.raises(ValueError, match="not a fallback reason"):
        activities.fallback(log, "k", "something else", DIAGNOSE)


# --------------------------------------------------------------------------- the pilot report's contract (PR 175)


def test_the_rows_have_the_shape_the_pilot_report_reads(tmp_path):
    """PR 175 (the pilot report) counts these by name: `llm.call` with model, prompt_tokens, completion_tokens,
    latency_ms and cost - a float in US dollars, not cents - and `llm.fallback` with a reason from the closed set.
    It is not on main yet, so this holds the shape; a test that runs the report over these rows comes with it."""
    client = LLMClient(provider=Scripted(_status(503)), mock=False)  # one failed call, then a fallback
    log, key = _diagnose(tmp_path, lambda: client)
    [call] = _rows(log, key, llm.CALL)[:1]
    assert isinstance(call["model"], str)
    for field in ("prompt_tokens", "completion_tokens", "latency_ms"):
        assert isinstance(call[field], int), field
    assert isinstance(call["cost"], float)
    answered = LLMClient(provider=Scripted('{"x": 1}'), mock=False)
    with pytest.raises(llm.ModelRefused):
        answered.structured(system="s", user="u", schema=Diagnosis, retries=0)
    # Dollars: 1,000 prompt and 200 completion tokens at the model's prices, the same as the budget charged.
    assert answered.calls[0]["cost"] == pytest.approx(answered.cost.usd)
    assert answered.calls[0]["cost"] == pytest.approx(llm.usd(llm.model_prices("fake-1"), 1000, 200))
    assert {e["kind"] for e in log.entries(key)} >= {"llm.call", "llm.fallback"}  # the names the report reads
    [fallback_row] = _rows(log, key, llm.FALLBACK)
    assert set(fallback_row) == {REASON, "where", "run_id"}
    assert fallback_row[REASON] in {"rules_only", "model_refused", "budget_cap", "provider_unavailable"}
