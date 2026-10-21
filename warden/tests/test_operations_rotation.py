"""Register S4: secret rotation. Every secret WARDEN can load has a rotation row in docs/OPERATIONS.md, and the
payload codec - whose key cannot simply change under running workflows - decrypts with previous keys."""

from __future__ import annotations

import asyncio
import os
import pathlib
import re

from temporalio.api.common.v1 import Payload

from warden import codec, settings

OPS = pathlib.Path(__file__).resolve().parents[1] / "docs" / "OPERATIONS.md"


def test_every_loadable_secret_has_a_rotation_row():
    text = OPS.read_text(encoding="utf-8")
    table = text[text.index("## Secret and key rotation"):]
    rows = [line for line in table.splitlines() if line.startswith("| `")]
    named = {name for row in rows for name in re.findall(r"`(WARDEN_[A-Z_]+|[A-Z]+_API_KEY)`", row.split("|")[1])}
    assert settings.SECRETS - named == set(), f"no rotation row: {sorted(settings.SECRETS - named)}"


def _roundtrip(writer, reader):
    async def go():
        sealed = await writer.encode([Payload(metadata={"encoding": b"json/plain"}, data=b'{"x": 1}')])
        return (await reader.decode(sealed))[0]
    return asyncio.run(go())


def test_a_payload_from_before_a_rotation_still_reads_and_new_ones_use_the_new_key():
    old, new = os.urandom(32), os.urandom(32)
    before = codec.EncryptionCodec(old)
    after = codec.EncryptionCodec(new, previous=[old])
    assert _roundtrip(before, after).data == b'{"x": 1}'  # written before the rotation, read after it
    assert _roundtrip(after, after).data == b'{"x": 1}'
    sealed = asyncio.run(after.encode([Payload(data=b"y")]))[0]
    assert sealed.metadata["encryption-key-id"] == after.key_id != before.key_id


def test_without_the_previous_key_an_old_payload_is_refused_not_misread():
    old, new = os.urandom(32), os.urandom(32)
    refused = _roundtrip(codec.EncryptionCodec(old), codec.EncryptionCodec(new))
    assert refused.metadata["encoding"] == codec.REFUSED


def test_previous_keys_come_from_the_environment(monkeypatch):
    import base64

    a, b = os.urandom(32), os.urandom(32)
    monkeypatch.setenv("WARDEN_TEMPORAL_KEY_PREVIOUS", ",".join(base64.b64encode(k).decode() for k in (a, b)))
    assert codec.previous_keys_from_env() == [a, b]
    assert "WARDEN_TEMPORAL_KEY_PREVIOUS" in settings.SECRETS
