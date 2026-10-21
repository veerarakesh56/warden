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
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable, Iterable
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
        repeated = getattr(field, "is_repeated", None)  # protobuf 5+; older ones say it with `label`
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


async def render(events: Iterable[HistoryEvent], codec: EncryptionCodec) -> str:
    """The events as lines, payloads decrypted by `codec` (bound to the workflow), at most MAX_EVENTS."""
    from .environments import both_times

    lines: list[str] = []
    for n, event in enumerate(events):
        if n >= MAX_EVENTS:
            lines.append(f"... more events not shown (at most {MAX_EVENTS})")
            break
        attributes = _attributes(event)
        kind = EventType.Name(event.event_type).removeprefix("EVENT_TYPE_")
        when = both_times(event.event_time.ToDatetime().replace(tzinfo=UTC)) if event.HasField("event_time") else "?"
        name = _name(attributes)
        lines.append(f"#{event.event_id} {when} {kind}" + (f" {name}" if name else ""))
        encrypted = _payloads(attributes) if attributes is not None else []
        for value in await codec.decode(encrypted) if encrypted else []:
            lines.append(f"    {_value(value)}")
    return "\n".join(lines)


def shown(text: str) -> str:
    """What a person is shown: identifiers and secrets masked by the redactor, then the terminal's outbound gate (no
    secret, no control character)."""
    from .gate import for_terminal
    from .redaction import redact

    return for_terminal(redact(text).text)


async def history(client: Any, workflow_id: str, *, key: bytes, previous: tuple[bytes, ...] = (),
                  events: Callable[[Any], AsyncIterator[HistoryEvent]] | None = None) -> str:
    """One workflow's history, decrypted in its own context and redacted."""
    from temporalio.converter import WorkflowSerializationContext

    codec = EncryptionCodec(key, previous).with_context(
        WorkflowSerializationContext(namespace=client.namespace, workflow_id=workflow_id))
    handle = client.get_workflow_handle(workflow_id)
    read = events or (lambda h: h.fetch_history_events(page_size=100))
    collected = []
    async for event in read(handle):
        collected.append(event)
        if len(collected) > MAX_EVENTS:
            break
    return shown(await render(collected, codec))
