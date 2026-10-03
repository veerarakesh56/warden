"""Register S15: Temporal reachable without authentication. WARDEN talks to Temporal Cloud with its service
account's API key over TLS, and refuses - before any connection - an unauthenticated server off this machine."""

from __future__ import annotations

import asyncio

import pytest

from warden import runtime, settings

KEY = bytes(32)


@pytest.fixture
def seen(monkeypatch):
    calls = []

    async def connect(target, **options):
        calls.append((target, options))
        return "client"

    monkeypatch.setattr(runtime.Client, "connect", connect)
    for name in ("WARDEN_TEMPORAL_ADDRESS", "WARDEN_TEMPORAL_API_KEY", "WARDEN_TEMPORAL_NAMESPACE"):
        monkeypatch.delenv(name, raising=False)
    return calls


def test_temporal_cloud_is_reached_with_the_api_key_over_tls(seen, monkeypatch):
    monkeypatch.setenv("WARDEN_TEMPORAL_ADDRESS", "ns.acct.tmprl.cloud:7233")
    monkeypatch.setenv("WARDEN_TEMPORAL_NAMESPACE", "ns.acct")
    monkeypatch.setenv("WARDEN_TEMPORAL_API_KEY", "k" * 8)
    assert asyncio.run(runtime.connect(key=KEY)) == "client"
    target, options = seen[0]
    assert target == "ns.acct.tmprl.cloud:7233" and options["namespace"] == "ns.acct"
    assert options["api_key"] == "k" * 8 and options["tls"] is True and options["data_converter"] is not None


@pytest.mark.parametrize("address", ["ns.acct.tmprl.cloud:7233", "10.0.3.7:7233", "temporal.internal:7233"])
def test_a_remote_server_without_a_key_is_refused_before_any_connection(seen, monkeypatch, address):
    monkeypatch.setenv("WARDEN_TEMPORAL_ADDRESS", address)
    with pytest.raises(RuntimeError, match="unauthenticated"):
        asyncio.run(runtime.connect(key=KEY))
    assert seen == []


@pytest.mark.parametrize("address", ["127.0.0.1:7233", "localhost:7233", "[::1]:7233"])
def test_the_local_dev_server_needs_no_key(seen, monkeypatch, address):
    monkeypatch.setenv("WARDEN_TEMPORAL_ADDRESS", address)
    asyncio.run(runtime.connect(key=KEY))
    assert "api_key" not in seen[0][1] and "tls" not in seen[0][1]


def test_the_api_key_is_a_secret_loaded_only_where_temporal_is_used():
    assert "WARDEN_TEMPORAL_API_KEY" in settings.SECRETS
    assert "WARDEN_TEMPORAL_API_KEY" in settings.RESTRICTED
