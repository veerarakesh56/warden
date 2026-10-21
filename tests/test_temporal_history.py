"""`warden history <workflow-id>` (register B36): one workflow's history, decrypted only in its own context, redacted,
and through the terminal's gate."""

from __future__ import annotations

import asyncio
import json
import os

import pytest
from temporalio.api.common.v1 import ActivityType, Payload, Payloads
from temporalio.api.enums.v1 import EventType
from temporalio.api.history.v1 import (
    ActivityTaskCompletedEventAttributes,
    ActivityTaskScheduledEventAttributes,
    HistoryEvent,
    WorkflowExecutionSignaledEventAttributes,
)
from temporalio.converter import WorkflowSerializationContext
from tests.fakes import AWS_ACCESS_KEY_ID

from warden import temporal_history
from warden.codec import EncryptionCodec
from warden.temporal_history import UNREADABLE, history, render, shown

KEY = os.urandom(32)
WID = "inc-alert-1"
NS = "warden-test"


def bound(wid: str = WID, key: bytes = KEY) -> EncryptionCodec:
    return EncryptionCodec(key).with_context(
        WorkflowSerializationContext(namespace=NS, workflow_id=wid)
    )


def encrypted(value: object, wid: str = WID, key: bytes = KEY) -> Payload:
    plain = Payload(metadata={"encoding": b"json/plain"}, data=json.dumps(value).encode())
    return asyncio.run(bound(wid, key).encode([plain]))[0]


def scheduled(n: int, name: str, *values: Payload) -> HistoryEvent:
    e = HistoryEvent(event_id=n, event_type=EventType.EVENT_TYPE_ACTIVITY_TASK_SCHEDULED)
    e.activity_task_scheduled_event_attributes.CopyFrom(
        ActivityTaskScheduledEventAttributes(
            activity_type=ActivityType(name=name), input=Payloads(payloads=list(values))
        )
    )
    e.event_time.FromSeconds(1_800_000_000)
    return e


def completed(n: int, value: Payload) -> HistoryEvent:
    e = HistoryEvent(event_id=n, event_type=EventType.EVENT_TYPE_ACTIVITY_TASK_COMPLETED)
    e.activity_task_completed_event_attributes.CopyFrom(
        ActivityTaskCompletedEventAttributes(result=Payloads(payloads=[value]))
    )
    return e


def test_payloads_are_decrypted_in_their_workflow_s_context():
    text = asyncio.run(
        render(
            [
                scheduled(5, "diagnose", encrypted({"service": "checkout"})),
                completed(6, encrypted({"verdict": "approved_for_human"})),
            ],
            bound(),
        )
    )
    lines = text.splitlines()
    assert lines[0].startswith("#5 ")
    assert lines[0].endswith("ACTIVITY_TASK_SCHEDULED diagnose")
    assert lines[1] == '    {"service":"checkout"}'
    assert lines[2] == "#6 ? ACTIVITY_TASK_COMPLETED"
    assert lines[3] == '    {"verdict":"approved_for_human"}'


@pytest.mark.parametrize(
    "payload",
    [
        encrypted({"x": 1}, wid="inc-other"),  # recorded in another workflow
        encrypted({"x": 1}, key=os.urandom(32)),  # another key
        Payload(metadata={"encoding": b"json/plain"}, data=b'{"x": 1}'),  # never encrypted
    ],
)
def test_a_payload_that_does_not_decrypt_here_is_never_shown(payload):
    text = asyncio.run(render([completed(9, payload)], bound()))
    assert UNREADABLE in text
    assert '"x"' not in text


def test_what_is_shown_is_redacted_and_gated():
    secret, email = AWS_ACCESS_KEY_ID, "person" + "@example.com"
    raw = asyncio.run(
        render(
            [completed(3, encrypted({"key": secret, "who": email, "note": "\x1b[31mred"}))], bound()
        )
    )
    out = shown(raw)
    assert secret not in out
    assert email not in out
    assert "\x1b" not in out


def test_a_signal_names_itself():
    e = HistoryEvent(event_id=7, event_type=EventType.EVENT_TYPE_WORKFLOW_EXECUTION_SIGNALED)
    e.workflow_execution_signaled_event_attributes.CopyFrom(
        WorkflowExecutionSignaledEventAttributes(
            signal_name="approve", input=Payloads(payloads=[encrypted({"plan_hash": "abc"})])
        )
    )
    assert (
        asyncio.run(render([e], bound())).splitlines()[0]
        == "#7 ? WORKFLOW_EXECUTION_SIGNALED approve"
    )


def test_at_most_max_events_and_long_values_cut(monkeypatch):
    monkeypatch.setattr(temporal_history, "MAX_EVENTS", 2)
    monkeypatch.setattr(temporal_history, "MAX_VALUE_CHARS", 10)
    text = asyncio.run(
        render([completed(n, encrypted({"long": "y" * 50})) for n in range(1, 5)], bound())
    )
    assert text.count("COMPLETED") == 2
    assert "more events not shown" in text
    assert "[cut]" in text


def test_a_non_json_payload_says_its_size_not_its_bytes():
    plain = Payload(metadata={"encoding": b"binary/plain"}, data=b"\x00\x01secret")
    value = asyncio.run(bound().encode([plain]))[0]
    text = asyncio.run(render([completed(1, value)], bound()))
    assert "[8 bytes, encoding binary/plain]" in text
    assert "secret" not in text


class Client:
    namespace = NS

    def __init__(self, events):
        self.events, self.asked = events, []

    def get_workflow_handle(self, wid):
        self.asked.append(wid)
        return self


def test_history_reads_one_workflow_and_decrypts_in_its_context():
    events = [
        completed(1, encrypted({"ok": True})),
        completed(2, encrypted({"ok": True}, wid="inc-other")),
    ]

    async def read(_handle):
        for e in events:
            yield e

    client = Client(events)
    out = asyncio.run(history(client, WID, key=KEY, events=read))
    assert client.asked == [WID]
    assert '{"ok":true}' in out
    assert UNREADABLE in out


def test_the_cli_loads_what_status_loads_and_no_more():
    import inspect

    from warden import cli

    src = inspect.getsource(cli)
    assert '{"link": "label", "history": "status"}' in src
    assert '"history")' in src


def test_identifiers_are_masked_and_the_rest_stays_readable():
    email = "person" + "@example.com"
    out = shown(
        asyncio.run(
            render([completed(3, encrypted({"who": email, "service": "checkout"}))], bound())
        )
    )
    assert email not in out
    assert "checkout" in out  # masked, not withheld: the history is still readable


def test_control_characters_never_reach_the_terminal():
    """Payload values are JSON (control characters escaped); a name from the history itself is not."""
    e = HistoryEvent(event_id=7, event_type=EventType.EVENT_TYPE_WORKFLOW_EXECUTION_SIGNALED)
    e.workflow_execution_signaled_event_attributes.CopyFrom(
        WorkflowExecutionSignaledEventAttributes(
            signal_name="approve\x07\b", input=Payloads(payloads=[encrypted({"note": "a\bb\x07c"})])
        )
    )
    out = shown(asyncio.run(render([e], bound())))
    assert "\b" not in out
    assert "\x07" not in out
