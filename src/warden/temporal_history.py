"""One workflow's Temporal history, decrypted and redacted, for a person who may read it (register B36).

Every Temporal payload WARDEN writes is encrypted (codec.py), bound to its namespace and workflow, so the Temporal
server and its web UI show only ciphertext. `warden history <workflow-id>` reads one workflow's history with the
person's own Temporal API key and decrypts each payload with WARDEN's codec in that workflow's own context - the only
context it decrypts in. No codec server, no new holder of the key, no change to the payload format (owner decision,
2026-10-21: option B; a codec server for the web UI stays a later option).

Who may read it: whoever can load WARDEN_TEMPORAL_KEY and a Temporal API key - in the cloud runtime, a person whose own
AWS identity may read those secrets (settings.RESTRICTED: the same as `warden status`). What they see: each event's
number, time, type and the activity or signal it names, and its payloads as JSON - then the whole text through the
redactor (identifiers and secrets masked, as everywhere WARDEN shows evidence) and the terminal's outbound gate. A
payload that does not decrypt here (another key, another workflow, never encrypted) is said to be unreadable, never
shown. Nothing is written anywhere.

What the model was sent (owner, 2026-10-21: "exactly what the model saw"): after the events, each `diagnose` call's
system and user text, as llm.py handed them to the provider - the redacted prompt recorded in the call's own input,
rebuilt with llm.ask_for, the one function the call itself used - and shown ONLY when it hashes to what that call
recorded it sent (provenance sent_system_sha256 / sent_user_sha256). A text this code cannot rebuild byte for byte is
not shown, and why is said. The prompt was redacted before it was sent, so it holds the placeholders the model was
shown, never the values behind them: no decryption here reaches the redaction map, which never enters Temporal's
history (activities.EvidencePack). It too goes through the redactor and the gate; if they change anything, it is shown
masked and marked "NOT byte-identical", never unmasked.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator, Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC
from typing import Any

from temporalio.api.common.v1 import Payload, Payloads
from temporalio.api.enums.v1 import EventType
from temporalio.api.history.v1 import HistoryEvent

from .codec import REFUSED, EncryptionCodec

MAX_EVENTS = 500
MAX_VALUE_CHARS = 2_000
UNREADABLE = "[unreadable here: another key, another workflow, or never encrypted]"


def _payloads(message: Any) -> list[Payload]:
    """Every Payload inside a protobuf message, in field order, however deep."""
    found: list[Payload] = []
    for field, value in message.ListFields():
        if field.message_type is None:
            continue
        repeated = getattr(
            field, "is_repeated", None
        )  # protobuf 5+; older ones say it with `label`
        if repeated is None:
            repeated = field.label == field.LABEL_REPEATED
        items = value if repeated else [value]
        for item in items:
            if isinstance(item, Payload):
                found.append(item)
            elif isinstance(item, Payloads):
                found.extend(item.payloads)
            elif hasattr(item, "ListFields"):
                found.extend(_payloads(item))
    return found


def _attributes(event: HistoryEvent) -> Any:
    which = event.WhichOneof("attributes")
    return getattr(event, which) if which else None


def _name(attributes: Any) -> str:
    """The activity, signal or workflow type an event names, if it names one."""
    if attributes is None:
        return ""
    fields = attributes.DESCRIPTOR.fields_by_name
    for field in ("activity_type", "workflow_type"):
        if field in fields and attributes.HasField(field):
            return getattr(attributes, field).name
    return str(getattr(attributes, "signal_name", "") or "")


def _value(p: Payload) -> str:
    if p.metadata.get("encoding") == REFUSED:
        return UNREADABLE
    try:
        text = json.dumps(json.loads(p.data), sort_keys=True, separators=(",", ":"))
    except ValueError:
        text = f"[{len(p.data)} bytes, encoding {p.metadata.get('encoding', b'').decode('ascii', 'replace')}]"
    return text if len(text) <= MAX_VALUE_CHARS else text[:MAX_VALUE_CHARS] + " [cut]"


@dataclass(frozen=True)
class Decoded:
    """One event, its attributes, and its payloads decrypted in the workflow's context."""

    event: HistoryEvent
    attributes: Any
    values: list[Payload]


async def decode(events: Iterable[HistoryEvent], codec: EncryptionCodec) -> list[Decoded]:
    """At most MAX_EVENTS + 1 events (the one past the limit only says there are more), payloads decrypted by `codec`."""
    out: list[Decoded] = []
    for n, event in enumerate(events):
        if n > MAX_EVENTS:
            break
        attributes = _attributes(event)
        encrypted = _payloads(attributes) if attributes is not None else []
        out.append(
            Decoded(event, attributes, list(await codec.decode(encrypted)) if encrypted else [])
        )
    return out


def lines(decoded: list[Decoded]) -> list[str]:
    from .environments import both_times

    out: list[str] = []
    for n, d in enumerate(decoded):
        if n >= MAX_EVENTS:
            out.append(f"... more events not shown (at most {MAX_EVENTS})")
            break
        kind = EventType.Name(d.event.event_type).removeprefix("EVENT_TYPE_")
        when = (
            both_times(d.event.event_time.ToDatetime().replace(tzinfo=UTC))
            if d.event.HasField("event_time")
            else "?"
        )
        name = _name(d.attributes)
        out.append(f"#{d.event.event_id} {when} {kind}" + (f" {name}" if name else ""))
        out.extend(f"    {_value(value)}" for value in d.values)
    return out


async def render(events: Iterable[HistoryEvent], codec: EncryptionCodec) -> str:
    """The events as lines, payloads decrypted by `codec` (bound to the workflow), at most MAX_EVENTS."""
    return "\n".join(lines(await decode(events, codec)))


# --------------------------------------------------------------------------- what the model was sent

DIAGNOSE = "diagnose"  # activities.IncidentActivities.diagnose: the incident's model call (graph._diagnose)
NO_ANSWER = (
    "no answer is recorded (the call failed, timed out or is still running): what it sent cannot be proven, "
    "so it is not shown"
)
NOT_SENT = "no record of the text sent: the model was not asked, or the call was recorded before WARDEN kept its hash"


def _json(p: Payload) -> Any:
    if p.metadata.get("encoding") == REFUSED:
        return None
    try:
        return json.loads(p.data)
    except ValueError:
        return None


def _calls(decoded: list[Decoded]) -> Iterator[tuple[int, Any, Any]]:
    """Each diagnose call: its scheduled event's id, its first input (the EvidencePack) and its result (or None)."""
    done = {
        d.attributes.scheduled_event_id: d
        for d in decoded
        if d.event.event_type == EventType.EVENT_TYPE_ACTIVITY_TASK_COMPLETED
    }
    for d in decoded:
        if (
            d.event.event_type == EventType.EVENT_TYPE_ACTIVITY_TASK_SCHEDULED
            and _name(d.attributes) == DIAGNOSE
        ):
            result = done.get(d.event.event_id)
            yield (
                d.event.event_id,
                _json(d.values[0]) if d.values else None,
                _json(result.values[0]) if result is not None and result.values else None,
            )


def _provenance(result: Any) -> dict[str, Any]:
    steps = result.get("steps") if isinstance(result, dict) else None
    for step in steps if isinstance(steps, list) else []:
        if (
            isinstance(step, dict)
            and step.get("node") == DIAGNOSE
            and isinstance(step.get("provenance"), dict)
        ):
            return step["provenance"]
    return {}


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _block(label: str, text: str, sent: str) -> list[str]:
    """One text as sent - only when it IS what was sent - through the redactor and the gate like everything shown."""
    rebuilt = _sha256(text)
    if rebuilt != sent:
        return [
            (
                f"--- {label}: not shown. This code rebuilds a different text (sha256 {rebuilt[:16]}, sent "
                f"{sent[:16]}): the prompt or its schema changed since the call, so it would not be what the model saw"
            )
        ]
    safe = shown(text)
    if safe == text:
        return [f"--- {label}: byte-identical to what was sent (sha256 {sent}) ---", text]
    return [
        (
            f"--- {label}: NOT byte-identical to what was sent (sha256 {sent}): the redactor or the terminal gate "
            "masked something here, and it stays masked ---"
        ),
        safe,
    ]


def what_was_sent(event_id: int, pack: Any, result: Any) -> list[str]:
    """One diagnose call's system and user text, as the provider was handed them, proven by the recorded hashes."""
    from .graph import SYSTEM_DIAGNOSE, Diagnosis
    from .llm import ask_for

    head = f"== What the model was sent: {DIAGNOSE} call #{event_id} =="
    prompt = pack.get("prompt") if isinstance(pack, dict) else None
    if not isinstance(prompt, str):
        return [head, "    its input does not decrypt here: nothing shown"]
    if result is None:
        return [head, f"    {NO_ANSWER}"]
    sent = _provenance(result)
    if not (sent.get("sent_system_sha256") and sent.get("sent_user_sha256")):
        why = result.get("model_unavailable") if isinstance(result, dict) else ""
        return [head, f"    {NOT_SENT}" + (f" ({shown(str(why))})" if why else "")]
    return [
        head,
        *_block("system", SYSTEM_DIAGNOSE, str(sent["sent_system_sha256"])),
        *_block("user", ask_for(prompt, Diagnosis), str(sent["sent_user_sha256"])),
        "--- end ---",
    ]


def model_inputs(decoded: list[Decoded]) -> str:
    """Every diagnose call in the history, what it sent (what_was_sent); empty when the history has none."""
    return "\n".join(line for call in _calls(decoded[:MAX_EVENTS]) for line in what_was_sent(*call))


def shown(text: str) -> str:
    """What a person is shown: identifiers and secrets masked by the redactor, then the terminal's outbound gate (no
    secret, no control character)."""
    from .gate import for_terminal
    from .redaction import redact

    return for_terminal(redact(text).text)


async def history(
    client: Any,
    workflow_id: str,
    *,
    key: bytes,
    previous: tuple[bytes, ...] = (),
    events: Callable[[Any], AsyncIterator[HistoryEvent]] | None = None,
) -> str:
    """One workflow's history, decrypted in its own context and redacted."""
    from temporalio.converter import WorkflowSerializationContext

    codec = EncryptionCodec(key, previous).with_context(
        WorkflowSerializationContext(namespace=client.namespace, workflow_id=workflow_id)
    )
    handle = client.get_workflow_handle(workflow_id)
    read = events or (lambda h: h.fetch_history_events(page_size=100))
    collected = []
    async for event in read(handle):
        collected.append(event)
        if len(collected) > MAX_EVENTS:
            break
    decoded = await decode(collected, codec)
    sent = model_inputs(decoded)
    # The events redacted as one text; each sent text on its own (what_was_sent), so a placeholder the redactor issues
    # here can never be confused with one the model was shown.
    return shown("\n".join(lines(decoded))) + (f"\n\n{sent}" if sent else "")
