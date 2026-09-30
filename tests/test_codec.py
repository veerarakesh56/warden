"""The payload codec: ciphertext only, tamper-evident, bound to its key."""

from __future__ import annotations

import asyncio
import base64
import os

import pytest
from temporalio.api.common.v1 import Payload

from warden import codec


def _payload(text: str) -> Payload:
    return Payload(metadata={"encoding": b"json/plain"}, data=text.encode())


def test_round_trip_and_nothing_readable_on_the_wire():
    c = codec.EncryptionCodec(os.urandom(32))
    [enc] = asyncio.run(c.encode([_payload('{"email":"priya.nair@corp.io"}')]))
    assert b"priya" not in enc.data and b"json/plain" not in enc.SerializeToString()
    [dec] = asyncio.run(c.decode([enc]))
    assert dec.data == b'{"email":"priya.nair@corp.io"}' and dec.metadata["encoding"] == b"json/plain"


def test_a_changed_byte_is_detected_and_refused_not_raised():
    """Second review (2026-09-30): raising here failed every task of the workflow the payload
    reached. A payload that does not decrypt becomes the refused marker instead."""
    c = codec.EncryptionCodec(os.urandom(32))
    [enc] = asyncio.run(c.encode([_payload("x")]))
    enc.data = enc.data[:-1] + bytes([enc.data[-1] ^ 1])
    [dec] = asyncio.run(c.decode([enc]))
    assert dec.metadata["encoding"] == codec.REFUSED and not dec.data


def test_another_key_cannot_read_it():
    [enc] = asyncio.run(codec.EncryptionCodec(os.urandom(32)).encode([_payload("x")]))
    [dec] = asyncio.run(codec.EncryptionCodec(os.urandom(32)).decode([enc]))
    assert dec.metadata["encoding"] == codec.REFUSED


@pytest.mark.parametrize("data", [b"", b"short", os.urandom(64)], ids=["empty", "short", "random"])
def test_a_forged_ciphertext_is_refused_not_raised(data):
    """The reviewer copied the (plain) key id from a real payload and sent random bytes."""
    c = codec.EncryptionCodec(os.urandom(32))
    forged = Payload(metadata={"encoding": codec.ENCODING, "encryption-key-id": c.key_id}, data=data)
    [dec] = asyncio.run(c.decode([forged]))
    assert dec.metadata["encoding"] == codec.REFUSED


def test_a_ciphertext_is_bound_to_its_workflow():
    """Second review: the ciphertext was bound only to the key, so an approval signal (or an
    activity result) recorded in one workflow's history decrypted in any other."""
    from temporalio.converter import ActivitySerializationContext, WorkflowSerializationContext

    base = codec.EncryptionCodec(os.urandom(32))
    a = base.with_context(WorkflowSerializationContext(namespace="ns", workflow_id="rem-A"))
    b = base.with_context(WorkflowSerializationContext(namespace="ns", workflow_id="rem-B"))
    a_act = base.with_context(ActivitySerializationContext(
        namespace="ns", activity_id="1", activity_type="check_approval", activity_task_queue="q",
        workflow_id="rem-A", workflow_type="RemediationWorkflow", is_local=False))
    [enc] = asyncio.run(a.encode([_payload("approved")]))
    assert asyncio.run(a.decode([enc]))[0].data == b"approved"
    assert asyncio.run(a_act.decode([enc]))[0].data == b"approved"  # same workflow, activity side
    for other in (b, base, base.with_context(WorkflowSerializationContext(namespace="ns2", workflow_id="rem-A"))):
        assert asyncio.run(other.decode([enc]))[0].metadata["encoding"] == codec.REFUSED
    [unbound] = asyncio.run(base.encode([_payload("x")]))
    assert asyncio.run(a.decode([unbound]))[0].metadata["encoding"] == codec.REFUSED  # no downgrade


def test_the_key_comes_from_the_environment_and_is_required(monkeypatch):
    monkeypatch.delenv("WARDEN_TEMPORAL_KEY", raising=False)
    with pytest.raises(RuntimeError, match="plain text"):
        codec.data_converter()
    monkeypatch.setenv("WARDEN_TEMPORAL_KEY", base64.b64encode(os.urandom(32)).decode())
    assert codec.data_converter().payload_codec is not None
    with pytest.raises(ValueError, match="32 bytes"):
        codec.EncryptionCodec(b"short")


def test_a_plain_payload_never_becomes_a_value():
    """Audit A-B-L13: decode used to hand a plain payload straight to the workflow, so anything
    that could write to the history without the key could feed the workflow unencrypted input.
    It now decodes to a marker that no converter can turn into a value."""
    conv = codec.data_converter(os.urandom(32))
    [marked] = asyncio.run(conv.payload_codec.decode([_payload('{"approval":"forged"}')]))
    assert marked.metadata["encoding"] == codec.REFUSED and b"forged" not in marked.SerializeToString()
    with pytest.raises(Exception):  # noqa: B017 - any conversion error; the SDK then drops or fails
        conv.payload_converter.from_payloads([marked], [dict])



def test_failure_messages_and_stack_traces_are_encrypted_too():
    """FAILURE-MODES S2: a failed activity's message and stack trace go into Temporal history, and an
    exception can quote evidence. The converter encodes them as a payload, and the codec encrypts it
    (independent review 2026-09-28: this was claimed and untested)."""
    from temporalio.api.failure.v1 import Failure

    conv = codec.data_converter(os.urandom(32))
    try:
        raise RuntimeError("connect to 10.0.7.22 as priya.nair@corp.io failed")
    except RuntimeError as exc:
        failure = Failure()
        conv.failure_converter.to_failure(exc, conv.payload_converter, failure)
    asyncio.run(conv.payload_codec.encode_failure(failure))
    wire = failure.SerializeToString()
    assert b"priya.nair" not in wire and b"10.0.7.22" not in wire
    assert failure.message == "Encoded failure" and failure.HasField("encoded_attributes")
