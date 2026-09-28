"""Encrypt every Temporal payload before it leaves the worker (AES-256-GCM).

Temporal stores every workflow input, activity input and result in its history, in plain form by
default. An alert carries identifiers WARDEN redacts everywhere else (people's emails, tenant ids),
and the history outlives the incident. With this codec, the Temporal server, its database and its
web UI hold only ciphertext; only a worker or client with the key can read a payload. Failure
messages and stack traces are encoded the same way (they can quote evidence too).

Key: `WARDEN_TEMPORAL_KEY`, 32 random bytes as base64 (SSM in the cloud, loadable through
settings.py). Every payload records which key encrypted it; a payload from another key fails loudly
instead of decoding to garbage.

ponytail: one active key; add a list of previous keys for decode when rotation is needed.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import os
from collections.abc import Sequence

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from temporalio.api.common.v1 import Payload
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.converter import (
    DataConverter,
    DefaultFailureConverterWithEncodedAttributes,
    PayloadCodec,
)

ENCODING = b"binary/encrypted-aes256gcm"


class EncryptionCodec(PayloadCodec):
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("the Temporal payload key must be 32 bytes")
        self._aes = AESGCM(key)
        self.key_id = hashlib.sha256(key).hexdigest()[:16].encode()

    async def encode(self, payloads: Sequence[Payload]) -> list[Payload]:
        out = []
        for p in payloads:
            nonce = os.urandom(12)
            data = nonce + self._aes.encrypt(nonce, p.SerializeToString(), self.key_id)
            out.append(Payload(metadata={"encoding": ENCODING, "encryption-key-id": self.key_id}, data=data))
        return out

    async def decode(self, payloads: Sequence[Payload]) -> list[Payload]:
        out = []
        for p in payloads:
            if p.metadata.get("encoding") != ENCODING:
                out.append(p)  # not ours (e.g. written before encryption was on)
                continue
            if p.metadata.get("encryption-key-id") != self.key_id:
                raise ValueError("payload was encrypted with a different key")
            plain = Payload()
            plain.ParseFromString(self._aes.decrypt(p.data[:12], p.data[12:], self.key_id))
            out.append(plain)
        return out


def key_from_env() -> bytes:
    raw = os.environ.get("WARDEN_TEMPORAL_KEY", "")
    if not raw:
        raise RuntimeError("WARDEN_TEMPORAL_KEY is not set: workflow payloads would be stored in plain text")
    return base64.b64decode(raw)


def data_converter(key: bytes | None = None) -> DataConverter:
    """The converter every WARDEN client and worker uses: pydantic models, encrypted payloads and
    encoded failure details."""
    return dataclasses.replace(
        pydantic_data_converter,
        payload_codec=EncryptionCodec(key if key is not None else key_from_env()),
        failure_converter_class=DefaultFailureConverterWithEncodedAttributes,
    )
