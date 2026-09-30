"""Encrypt every Temporal payload before it leaves the worker (AES-256-GCM).

Temporal stores every workflow input, activity input and result in its history, in plain form by
default. An alert carries identifiers WARDEN redacts everywhere else (people's emails, tenant ids),
and the history outlives the incident. With this codec, the Temporal server, its database and its
web UI hold only ciphertext; only a worker or client with the key can read a payload. Failure
messages and stack traces are encoded the same way (they can quote evidence too).

Key: `WARDEN_TEMPORAL_KEY`, 32 random bytes as base64 (Secrets Manager in the cloud, loadable through
settings.py). Every payload records which key encrypted it, and is bound (AES-GCM associated data) to
the namespace and workflow it belongs to. A payload that does not decrypt here - not encrypted, another
key, a forged or changed ciphertext, or one recorded in ANOTHER workflow - decodes to the REFUSED
marker, which no converter turns into a value. It never raises: the SDK decodes a whole activation at
once, so one bad payload would fail every task of its workflow (second review, 2026-09-30).

Honest limits:
- Workflow ids, activity and signal names, and timestamps stay in plain text; only payloads are
  encrypted.
- Within ONE workflow an old payload can be replayed into a later slot of the same kind; approvals are
  single-use (nonces) and `apply` re-verifies its plan and approvals from WARDEN's own audit log.
- Anyone who can complete a workflow's activity tasks can make it stop (an unreadable result fails its
  workflow task) - the same principals can terminate it outright. The watchdog for a remediation that
  never finishes is out of band (plan G6).
- A `Replayer` must be given the namespace the history was recorded in: its default namespace
  ("ReplayNamespace") binds nothing it replays, so every payload would be refused.

ponytail: one active key; add a list of previous keys for decode when rotation is needed.
"""

from __future__ import annotations

import base64
import copy
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
    SerializationContext,
    WithSerializationContext,
)

ENCODING = b"binary/encrypted-aes256gcm"
REFUSED = b"binary/refused-unencrypted"  # what a plain payload decodes to: unreadable by design


class EncryptionCodec(PayloadCodec, WithSerializationContext):
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("the Temporal payload key must be 32 bytes")
        self._aes = AESGCM(key)
        self.key_id = hashlib.sha256(key).hexdigest()[:16].encode()
        self.scope = b""  # "<namespace>/<workflow id>" once the SDK gives a context

    def with_context(self, context: SerializationContext) -> EncryptionCodec:
        """The SDK hands every client, workflow and activity operation the workflow it concerns; the
        ciphertext is bound to it, so a payload recorded in one workflow never decrypts in another."""
        workflow_id = getattr(context, "workflow_id", None)
        bound = copy.copy(self)
        bound.scope = f"{getattr(context, 'namespace', '')}/{workflow_id}".encode() if workflow_id else b""
        return bound

    def _aad(self) -> bytes:
        return self.key_id + b"\x00" + self.scope

    async def encode(self, payloads: Sequence[Payload]) -> list[Payload]:
        out = []
        for p in payloads:
            nonce = os.urandom(12)
            data = nonce + self._aes.encrypt(nonce, p.SerializeToString(), self._aad())
            out.append(Payload(metadata={"encoding": ENCODING, "encryption-key-id": self.key_id}, data=data))
        return out

    async def decode(self, payloads: Sequence[Payload]) -> list[Payload]:
        out = []
        for p in payloads:
            if p.metadata.get("encoding") != ENCODING:
                # Audit A-B-L13: a plain payload was written by something without the key - a
                # misconfigured client, or someone forging input - and used to reach the workflow
                # as data. It is replaced by a marker no converter can read, so it never becomes a
                # value. NOT an exception here: the SDK decodes a whole activation at once, so
                # raising let ONE plain signal (any name, even unhandled) fail every task of a
                # workflow that had already applied a change - no success check, no rollback
                # (independent review, 2026-09-28). Now a plain signal is dropped by the SDK
                # ("Failed deserializing signal input"), a plain update or start fails, and the
                # workflow carries on.
                out.append(Payload(metadata={"encoding": REFUSED}))
                continue
            try:  # another key fails here too: the key id is in the associated data
                plain = Payload()
                plain.ParseFromString(self._aes.decrypt(p.data[:12], p.data[12:], self._aad()))
            except Exception:  # noqa: BLE001 - wrong key, forged or changed bytes, another workflow
                plain = Payload(metadata={"encoding": REFUSED})
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
