"""`warden history` shows exactly what the model was sent - the same bytes WARDEN handed the
provider, after redaction, never a re-render that could differ - and every masked value stays masked.

The incident here runs through the real read side (IncidentActivities.prepare: gather, redact, quarantine, tripwire)
and the real diagnose activity, whose model is the SDK provider with its HTTP client replaced by one that records the
request (no paid call). Its input and result are encoded as Temporal records them (WARDEN's pydantic converter, then
the codec bound to the workflow), and `history` must print the recorded request's system and user text, byte for byte.
"""

from __future__ import annotations

import asyncio
import json
import os
import types

import pytest
from temporalio.api.common.v1 import ActivityType, Payloads
from temporalio.api.enums.v1 import EventType
from temporalio.api.history.v1 import (
    ActivityTaskCompletedEventAttributes,
    ActivityTaskScheduledEventAttributes,
    HistoryEvent,
)
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.converter import WorkflowSerializationContext
from tests.fakes import AWS_ACCESS_KEY_ID, HUNTER2, JWT, dsn

from warden import audit, graph, providers, temporal_history
from warden.activities import IncidentActivities
from warden.cli import DEMO_ALERTS
from warden.codec import EncryptionCodec
from warden.llm import LLMClient
from warden.models import Alert
from warden.temporal_history import NO_ANSWER, NOT_SENT, history
from warden.tools import FixtureBackend

KEY = os.urandom(32)
WID = "inc-history-sent"
NS = "warden-test"
EMAIL = "canary.person" + "@example.com"
IP = "10.77" + ".66.55"
PASSWORD = HUNTER2 + "-canary"
CANARIES = (EMAIL, IP, AWS_ACCESS_KEY_ID, JWT, PASSWORD)


class CanaryBackend(FixtureBackend):
    """The bundled incident's evidence, plus log lines carrying every canary."""

    def logs(self, alert):
        return [
            *super().logs(alert),
            f"ERROR login failed for {EMAIL} from {IP} token {JWT}",
            f"WARN connecting {dsn('postgres', 'app', PASSWORD, 'db.internal:5432/orders')} key {AWS_ACCESS_KEY_ID}",
        ]


def _provider(*answers: str):
    """The Anthropic SDK provider, its client replaced by one that records each request and gives the answers in turn
    (the last one again once they run out)."""
    p = providers.AnthropicProvider.__new__(providers.AnthropicProvider)
    p.model, p.name, p.version, p.effort = "test-model", "anthropic", "test", ""
    responses = [
        types.SimpleNamespace(
            content=[types.SimpleNamespace(type="text", text=answer)],
            stop_reason="end_turn",
            stop_details=None,
            usage=types.SimpleNamespace(input_tokens=1000, output_tokens=200),
        )
        for answer in answers
    ]
    sent: list[dict] = []
    p._client = types.SimpleNamespace(
        messages=types.SimpleNamespace(
            create=lambda **kw: sent.append(kw) or responses[min(len(sent), len(responses)) - 1]
        )
    )
    return p, sent


def _alert() -> Alert:
    raw = dict(DEMO_ALERTS["inc-002"])
    return Alert(**{**raw, "labels": {"owner": EMAIL, "client_ip": IP}})


def _incident(tmp_path, *, mock: bool = False, first_answer: str = ""):
    """prepare + diagnose of one incident: (pack, diagnosed, the requests the provider was sent)."""
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    pack = IncidentActivities(audit=log, backend=CanaryBackend()).prepare(_alert())
    first = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(mock=True)).diagnose(pack)
    if mock:
        return pack, first, []
    answer = graph.Diagnosis(root_cause=first.root_cause, proposal=first.proposal).model_dump_json()
    p, sent = _provider(*([first_answer] if first_answer else []), answer)
    log2 = audit.AuditLog(
        tmp_path / "b.db", key=None
    )  # a fresh incident budget: the mock run spent none, but be sure
    diagnosed = IncidentActivities(
        audit=log2, llm_factory=lambda: LLMClient(provider=p, mock=False)
    ).diagnose(pack)
    return pack, diagnosed, sent


def _bound() -> EncryptionCodec:
    return EncryptionCodec(KEY).with_context(
        WorkflowSerializationContext(namespace=NS, workflow_id=WID)
    )


def _recorded(*values) -> list:
    """The values as Temporal records them for WARDEN: the pydantic converter, then the codec bound to the workflow."""
    plain = pydantic_data_converter.payload_converter.to_payloads(list(values))
    return list(asyncio.run(_bound().encode(plain)))


def _events(pack, diagnosed, *, completed: bool = True) -> list[HistoryEvent]:
    s = HistoryEvent(event_id=5, event_type=EventType.EVENT_TYPE_ACTIVITY_TASK_SCHEDULED)
    s.activity_task_scheduled_event_attributes.CopyFrom(
        ActivityTaskScheduledEventAttributes(
            activity_type=ActivityType(name="diagnose"),
            input=Payloads(payloads=_recorded(pack, "")),
        )
    )
    if not completed:
        return [s]
    c = HistoryEvent(event_id=7, event_type=EventType.EVENT_TYPE_ACTIVITY_TASK_COMPLETED)
    c.activity_task_completed_event_attributes.CopyFrom(
        ActivityTaskCompletedEventAttributes(
            scheduled_event_id=5, result=Payloads(payloads=_recorded(diagnosed))
        )
    )
    return [s, c]


class Client:
    namespace = NS

    def get_workflow_handle(self, wid):
        assert wid == WID
        return self


def _history(events) -> str:
    async def read(_handle):
        for e in events:
            yield e

    return asyncio.run(history(Client(), WID, key=KEY, events=read))


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    pack, diagnosed, sent = _incident(tmp_path_factory.mktemp("sent"))
    return pack, diagnosed, sent, _history(_events(pack, diagnosed))


def test_the_model_was_really_asked_once_and_the_answer_recorded_what_it_sent(run):
    _, diagnosed, sent, _ = run
    assert len(sent) == 1
    assert not diagnosed.model_unavailable
    [step] = [s for s in diagnosed.steps if s.get("node") == "diagnose"]
    assert step["provenance"]["sent_user_sha256"] == temporal_history._sha256(
        sent[0]["messages"][0]["content"]
    )
    assert step["provenance"]["sent_system_sha256"] == temporal_history._sha256(sent[0]["system"])


def test_history_shows_the_system_text_byte_for_byte_as_the_api_request_carried_it(run):
    *_, sent, out = run
    system = sent[0]["system"]
    assert (
        f"byte-identical to what was sent (sha256 {temporal_history._sha256(system)}) ---\n{system}\n--- user"
        in out
    )


def test_history_shows_the_user_text_byte_for_byte_as_the_api_request_carried_it(run):
    *_, sent, out = run
    [message] = sent[0]["messages"]
    user = message["content"]
    assert (
        f"byte-identical to what was sent (sha256 {temporal_history._sha256(user)}) ---\n{user}\n--- end ---"
        in out
    )


def test_what_is_shown_is_the_recorded_prompt_not_a_fresh_render(run):
    """The data marker in a prompt is random per render: the one shown is the one the call recorded and sent."""
    pack, _, sent, out = run
    assert pack.prompt in sent[0]["messages"][0]["content"]
    assert pack.prompt in out


@pytest.mark.parametrize("canary", CANARIES, ids=["email", "ip", "aws-key", "jwt", "password"])
def test_no_masked_value_reaches_the_model_or_the_history(run, canary):
    *_, sent, out = run
    assert canary not in json.dumps(sent)  # the model never saw it
    assert canary not in out  # and no decryption here shows it


def test_the_masked_values_are_placeholders_where_the_model_was_shown_them(run):
    *_, out = run
    assert "<EMAIL_" in out


def test_a_call_whose_text_this_code_cannot_rebuild_is_not_shown(tmp_path, run):
    """A prompt changed after the call (here: the recorded input altered) is never shown as what the model saw."""
    pack, diagnosed, sent, _ = run
    changed = pack.model_copy(update={"prompt": pack.prompt + " "})
    out = _history(_events(changed, diagnosed))
    assert "--- user: not shown" in out
    assert sent[0]["messages"][0]["content"] not in out


def test_a_changed_system_prompt_is_not_shown_as_what_was_sent(monkeypatch, run):
    pack, diagnosed, *_ = run
    monkeypatch.setattr(graph, "SYSTEM_DIAGNOSE", graph.SYSTEM_DIAGNOSE + " changed")
    out = _history(_events(pack, diagnosed))
    assert "--- system: not shown" in out
    assert graph.SYSTEM_DIAGNOSE not in out


def test_a_call_with_no_answer_recorded_shows_nothing_as_sent(run):
    pack, diagnosed, *_ = run
    out = _history(_events(pack, diagnosed, completed=False))
    assert NO_ANSWER in out
    assert "byte-identical" not in out


def test_a_mock_run_sent_nothing_and_says_so(tmp_path):
    pack, diagnosed, sent = _incident(tmp_path, mock=True)
    out = _history(_events(pack, diagnosed))
    assert sent == []
    assert NOT_SENT in out
    assert "byte-identical" not in out


def test_a_raw_value_in_a_sent_text_stays_masked_and_is_marked_not_identical(run):
    """Had a value reached the model unmasked, history still masks it - and says the text shown differs."""
    pack, diagnosed, *_ = run
    from warden.llm import ask_for

    leaky = pack.model_copy(update={"prompt": f"{pack.prompt}\nowner {EMAIL}"})
    [step] = [s for s in diagnosed.steps if s.get("node") == "diagnose"]
    prov = {
        **step["provenance"],
        "sent_user_sha256": temporal_history._sha256(ask_for(leaky.prompt, graph.Diagnosis)),
    }
    forged = diagnosed.model_copy(update={"steps": [{**step, "provenance": prov}]})
    out = _history(_events(leaky, forged))
    assert "--- user: NOT byte-identical" in out
    assert EMAIL not in out


def test_the_events_themselves_are_masked_too():
    """A raw value in any other payload (an activity result, a signal) is masked where the history shows it."""
    c = HistoryEvent(event_id=9, event_type=EventType.EVENT_TYPE_ACTIVITY_TASK_COMPLETED)
    c.activity_task_completed_event_attributes.CopyFrom(
        ActivityTaskCompletedEventAttributes(
            scheduled_event_id=8,
            result=Payloads(payloads=_recorded({"who": EMAIL, "key": AWS_ACCESS_KEY_ID})),
        )
    )
    out = _history([c])
    assert EMAIL not in out
    assert AWS_ACCESS_KEY_ID not in out
    assert "<EMAIL_1>" in out


def test_a_name_from_the_history_is_masked_and_gated_too():
    """A signal name comes from the history itself, not from a payload: history() masks it and strips its control
    characters (the values are masked in lines(); this is the gate over the whole event text)."""
    from temporalio.api.history.v1 import WorkflowExecutionSignaledEventAttributes

    e = HistoryEvent(event_id=4, event_type=EventType.EVENT_TYPE_WORKFLOW_EXECUTION_SIGNALED)
    e.workflow_execution_signaled_event_attributes.CopyFrom(
        WorkflowExecutionSignaledEventAttributes(signal_name=f"approve {EMAIL}\x07")
    )
    out = _history([e])
    assert EMAIL not in out
    assert "\x07" not in out


@pytest.fixture(scope="module")
def retried(tmp_path_factory):
    """A call whose first answer failed validation: the retry carried the feedback. The bad answer
    echoes a canary in a wrong-typed field, so feedback that quoted a value would carry it."""
    pack, diagnosed, sent = _incident(
        tmp_path_factory.mktemp("retry"),
        first_answer=json.dumps({"root_cause": {"hypothesis": [EMAIL]}}),
    )
    return pack, diagnosed, sent, _history(_events(pack, diagnosed))


def test_a_retried_call_records_what_it_appended_and_hashes_the_text_it_sent(retried):
    _, diagnosed, sent, _ = retried
    first, last = (r["messages"][0]["content"] for r in sent)
    [step] = [s for s in diagnosed.steps if s.get("node") == "diagnose"]
    prov = step["provenance"]
    assert len(sent) == 2
    assert last.startswith(first)
    assert prov["sent_appended"] == last[len(first) :]
    assert prov["sent_user_sha256"] == temporal_history._sha256(last)


def test_history_shows_a_retried_call_s_text_byte_for_byte_feedback_included(retried):
    *_, sent, out = retried
    user = sent[-1]["messages"][0]["content"]
    sha = temporal_history._sha256(user)
    assert f"byte-identical to what was sent (sha256 {sha}) ---\n{user}\n--- end ---" in out
    assert "a retry: the answer before failed validation" in out


def test_the_feedback_appended_carries_no_evidence_value(retried):
    _, diagnosed, *_ = retried
    [step] = [s for s in diagnosed.steps if s.get("node") == "diagnose"]
    appended = step["provenance"]["sent_appended"]
    assert appended.startswith("\n\nYour last answer failed validation: ")
    assert not any(c in appended for c in CANARIES)
    assert "<EMAIL_" not in appended
