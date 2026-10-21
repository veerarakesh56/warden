"""Item 7c: a person is paged - through WARDEN's pager (PR 43), to the page topic it already has - when the model
provider is unavailable, the daily cap is reached or an incident's budget is spent. Once per condition per UTC day,
never once per call; never for a normal error (an answer that was not JSON, a refusal, a retry that got through, a
bad key); and the page says fixed words only - never an error's text, a value from the evidence or a secret."""

from __future__ import annotations

import contextlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import BaseModel

from test_paging import MODULE, _world, pager
from warden import activities, audit, eldane, llm, paging
from warden.activities import IncidentActivities
from warden.cli import DEMO_ALERTS
from warden.llm import LLMClient, ModelRefused
from warden.models import Alert
from warden.providers import Completion, ProviderError, ProviderExhausted

# A secret-shaped value and an evidence value, built from parts: neither may reach a page.
SECRET = "sk-" + "ant-" + "x" * 24
EVIDENCE = "orders-db-" + "7f3a9"
DAY = datetime(2026, 10, 21, 9, 0, tzinfo=UTC)
GOOD = '{"answer": "ok", "score": 1}'
CAP_METRIC, BUDGET_METRIC = paging.MODEL_METRICS[paging.DAILY_CAP], paging.MODEL_METRICS[paging.BUDGET]
CONDITION = "condition"


class Toy(BaseModel):
    answer: str
    score: int


class Scripted:
    name, model = "fake", "fake-1"

    def __init__(self, *script: Any) -> None:
        self.script, self.calls = list(script), 0

    def complete(self, *, system: str, user: str, schema: Any = None) -> Completion:
        self.calls += 1
        step = self.script[min(self.calls - 1, len(self.script) - 1)]
        if isinstance(step, BaseException):
            raise step
        return step if isinstance(step, Completion) else Completion(step, 10, 5)


def _status(code: int) -> ProviderError:
    err = ProviderError(f"HTTP {code} for {EVIDENCE} with key {SECRET}")
    err.status_code = code
    return err


@pytest.fixture
def counted(monkeypatch):
    """Every page count WARDEN sends, as the CloudWatch call would carry it."""
    sent: list[dict[str, Any]] = []

    class CW:
        def put_metric_data(self, **kw):
            sent.append(kw)

    import boto3

    monkeypatch.setenv("WARDEN_HEARTBEAT_NAMESPACE", "WARDEN/ops")
    monkeypatch.setattr(boto3, "client", lambda *a, **k: CW())
    return sent


def _metrics(sent: list[dict[str, Any]]) -> list[str]:
    return [d["MetricName"] for kw in sent for d in kw["MetricData"]]


def _incidents(tmp_path, provider_factory, n=2, **client):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    acts = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(provider=provider_factory(), mock=False,
                                                                       **client))
    for i in range(n):
        pack = acts.prepare(Alert(**{**DEMO_ALERTS["inc-002"], "alert_id": f"inc-page-{i}"}))
        acts.diagnose(pack)
    return log


def _paged(log) -> list[dict[str, Any]]:
    return [e["body"] for e in log.entries("pages", kinds=(paging.MODEL_PAGED,))]


# --------------------------------------------------------------------------- each condition pages once


@pytest.mark.parametrize("failure", [_status(503), _status(429), ProviderError("connection reset"),
                                     ProviderExhausted("the daily quota is used")],
                         ids=["503", "429", "no-status", "exhausted"])
def test_an_unavailable_provider_pages_once_however_many_incidents_it_stops(tmp_path, counted, failure):
    log = _incidents(tmp_path, lambda: Scripted(failure), n=3)
    assert [r[CONDITION] for r in _paged(log)] == [paging.PROVIDER_UNAVAILABLE]
    assert _metrics(counted) == ["ModelProviderUnavailable"]


def test_a_spent_budget_pages_once(tmp_path, counted):
    log = _incidents(tmp_path, lambda: Scripted("not json"), n=2, max_usd=0.00001)
    assert [r[CONDITION] for r in _paged(log)] == [paging.BUDGET]
    assert _metrics(counted) == [BUDGET_METRIC]


MOCK_CEILING = "mock-ceiling"


@pytest.mark.parametrize("how", ["spent-in-a-call", "call-ceiling-before-a-call", "prompt-too-large", MOCK_CEILING])
def test_every_way_the_budget_stops_a_call_names_the_budget(how):
    from warden.llm import BudgetExceeded

    mock = how == MOCK_CEILING
    # Spent in a call: the request's own estimate passes, and the answer's 100,000 tokens of input then cost more.
    client = LLMClient(provider=None if mock else Scripted(Completion(GOOD, 100_000, 5)), mock=mock, max_calls=1,
                       max_usd=0.01 if how == "spent-in-a-call" else 10.0)
    ask = {"system": "s", "user": "u" * (llm.MAX_PROMPT_TOKENS * 5 if how == "prompt-too-large" else 1), "schema": Toy,
           "mock_factory": lambda: Toy(answer="a", score=1)}
    if how in ("call-ceiling-before-a-call", MOCK_CEILING):
        client.structured(**ask)
    with pytest.raises(BudgetExceeded):
        client.structured(**ask)
    assert client.stopped_by == paging.BUDGET


def test_the_daily_cap_pages_once_for_every_incident_it_stops(tmp_path, counted):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    log.append("earlier", "incident.llm_spend", {"attempt": "a", "calls": 1, "usd": activities.DAILY_MAX_USD + 1,
                                                 "input_tokens": 0, "output_tokens": 0})
    p = Scripted('{"x": 1}')
    acts = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(provider=p, mock=False))
    for i in range(3):
        acts.diagnose(acts.prepare(Alert(**{**DEMO_ALERTS["inc-002"], "alert_id": f"inc-cap-{i}"})))
    assert p.calls == 0  # the cap stopped the model before any call
    assert [r[CONDITION] for r in _paged(log)] == [paging.DAILY_CAP]
    assert _metrics(counted) == [CAP_METRIC]


def test_eldanes_daily_call_cap_pages_once(tmp_path, counted):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    for _ in range(eldane.DAILY_CALLS):
        log.append("inc-1", eldane.CALL, {"ok": True})
    rows = {"model": "m", "evidence": [{"prompt": "p"}]}
    for _ in range(3):
        assert "daily ceiling" in eldane._skip(log, {"d": 1}, {"model": "other"}, rows["model"], "why",
                                               rows["evidence"])
    assert [r[CONDITION] for r in _paged(log)] == [paging.DAILY_CAP]
    assert _metrics(counted) == [CAP_METRIC]


def test_each_condition_pages_again_the_next_day_and_not_before(tmp_path, counted):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    assert paging.model_condition(log, paging.BUDGET, now=DAY)
    assert not paging.model_condition(log, paging.BUDGET, now=DAY + timedelta(hours=14))  # 23:00 the same day
    assert paging.model_condition(log, paging.PROVIDER_UNAVAILABLE, now=DAY)  # another condition is its own page
    assert paging.model_condition(log, paging.BUDGET, now=DAY + timedelta(days=1))
    assert _metrics(counted) == [BUDGET_METRIC, "ModelProviderUnavailable", BUDGET_METRIC]


def test_no_condition_counts_nothing(tmp_path, counted):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    assert not paging.model_condition(log, "")
    assert not paging.model_condition(log, "something-else")
    assert counted == []
    assert _paged(log) == []


# --------------------------------------------------------------------------- normal errors page nobody


@pytest.mark.parametrize("script", [("not json",), (_status(503), GOOD), (_status(401),),
                                    (_status(400),), (GOOD,)],
                         ids=["bad-json", "retry-got-through", "bad-key", "malformed-request", "answered"])
def test_a_normal_error_pages_nobody(tmp_path, counted, script):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    client = LLMClient(provider=Scripted(*script), mock=False)
    with contextlib.suppress(ModelRefused):  # only what it pages is under test
        client.structured(system="s", user="u", schema=Toy)
    assert client.stopped_by == ""
    assert not paging.model_condition(log, client.stopped_by)
    assert counted == []


@pytest.mark.parametrize("answer", [Completion('{"answer": "', 10, 5, refused=True),
                                    Completion('{"answer": "', 10, 5, cut_off=True)], ids=["refused", "cut-off"])
def test_a_refused_or_cut_off_answer_pages_nobody(counted, answer):
    client = LLMClient(provider=Scripted(answer), mock=False)
    with pytest.raises(ModelRefused, match="asking again would"):
        client.structured(system="s", user="u", schema=Toy)
    assert client.stopped_by == ""
    assert counted == []


# --------------------------------------------------------------------------- the page says nothing it should not


def test_the_record_and_the_count_carry_no_error_text_value_or_secret(tmp_path, counted):
    log = _incidents(tmp_path, lambda: Scripted(_status(503)), n=1)
    [row] = _paged(log)
    assert set(row) == {"condition", "day"}
    for kw in counted:
        text = json.dumps(kw)
        assert SECRET not in text
        assert EVIDENCE not in text
        assert [set(d) for d in kw["MetricData"]] == [{"MetricName", "Value", "Unit"}]


def _model_pages_tf() -> str:
    tf = (MODULE / "paging.tf").read_text(encoding="utf-8")
    return tf[tf.index("model_pages = {"):tf.index('resource "aws_cloudwatch_metric_alarm" "model"')]


def test_each_condition_has_an_alarm_on_its_metric_that_reaches_the_pager_and_the_topic_only():
    tf = (MODULE / "paging.tf").read_text(encoding="utf-8")
    block = _model_pages_tf()
    for condition, metric in paging.MODEL_METRICS.items():
        assert re.search(rf'{condition} = \{{\s*metric = "{metric}"', block), condition
        assert f'aws_cloudwatch_metric_alarm.model["{condition}"].alarm_name' in tf[tf.index("self_alarms = "):]
    alarm = tf[tf.index('resource "aws_cloudwatch_metric_alarm" "model"'):]
    alarm = alarm[:alarm.index("\n}\n")]
    assert "alarm_actions       = [var.page_topic_arn]" in alarm  # the topic the repo pages already: no address here
    assert "@" not in block
    assert 'treat_missing_data  = "notBreaching"' in alarm


def test_the_pages_words_are_fixed_and_the_pager_opens_one_page_per_alarm():
    """What the pager says is the alarm's description: fixed words, no interpolation of any value. While its page is
    open, the same alarm going into ALARM again opens no second page."""
    says = re.findall(r'says\s*=\s*"([^"]*)"', _model_pages_tf())
    assert len(says) == len(paging.MODEL_METRICS)
    for text in says:
        assert "${" not in text
    p, _, _, said = _world()
    event = {"source": "aws.cloudwatch", "detail-type": "CloudWatch Alarm State Change",
             "detail": {"alarmName": "warden-ops-model-provider-unavailable", "state": {"value": "ALARM"},
                        "configuration": {"description": says[0]}}}
    assert pager.handler(event, pager=p) == {"opened": True}
    assert pager.handler(event, pager=p) == {"opened": False}
    assert len(said) == 1
    assert says[0] in said[0][1]
