"""The payload codec: ciphertext only, tamper-evident, bound to its key."""

from __future__ import annotations

import asyncio
import base64
import os

import pytest
from cryptography.exceptions import InvalidTag
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


def test_a_changed_byte_is_detected():
    c = codec.EncryptionCodec(os.urandom(32))
    [enc] = asyncio.run(c.encode([_payload("x")]))
    enc.data = enc.data[:-1] + bytes([enc.data[-1] ^ 1])
    with pytest.raises(InvalidTag):
        asyncio.run(c.decode([enc]))


def test_another_key_cannot_read_it():
    [enc] = asyncio.run(codec.EncryptionCodec(os.urandom(32)).encode([_payload("x")]))
    with pytest.raises(ValueError, match="different key"):
        asyncio.run(codec.EncryptionCodec(os.urandom(32)).decode([enc]))


def test_the_key_comes_from_the_environment_and_is_required(monkeypatch):
    monkeypatch.delenv("WARDEN_TEMPORAL_KEY", raising=False)
    with pytest.raises(RuntimeError, match="plain text"):
        codec.data_converter()
    monkeypatch.setenv("WARDEN_TEMPORAL_KEY", base64.b64encode(os.urandom(32)).decode())
    assert codec.data_converter().payload_codec is not None
    with pytest.raises(ValueError, match="32 bytes"):
        codec.EncryptionCodec(b"short")


def test_a_plain_payload_is_refused_not_passed_through():
    """Audit A-B-L13: decode used to hand a plain payload straight to the workflow, so anything
    that could write to the history without the key could feed the workflow unencrypted input."""
    with pytest.raises(ValueError, match="unencrypted payload refused"):
        asyncio.run(codec.EncryptionCodec(os.urandom(32)).decode([_payload('{"approval":"forged"}')]))
