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
    assert target == "ns.acct.tmprl.cloud:7233"
    assert options["namespace"] == "ns.acct"
    assert options["api_key"] == "k" * 8
    assert options["tls"] is True
    assert options["data_converter"] is not None


@pytest.mark.parametrize("address", ["ns.acct.tmprl.cloud:7233", "10.0.3.7:7233", "temporal.internal:7233"])
def test_a_remote_server_without_a_key_is_refused_before_any_connection(seen, monkeypatch, address):
    monkeypatch.setenv("WARDEN_TEMPORAL_ADDRESS", address)
    connecting = runtime.connect(key=KEY)  # a coroutine: nothing runs until asyncio.run awaits it
    with pytest.raises(RuntimeError, match="unauthenticated"):
        asyncio.run(connecting)
    assert seen == []


@pytest.mark.parametrize("address", ["127.0.0.1:7233", "localhost:7233", "[::1]:7233"])
def test_the_local_dev_server_needs_no_key(seen, monkeypatch, address):
    monkeypatch.setenv("WARDEN_TEMPORAL_ADDRESS", address)
    asyncio.run(runtime.connect(key=KEY))
    assert "api_key" not in seen[0][1]
    assert "tls" not in seen[0][1]


def test_the_api_key_is_a_secret_loaded_only_where_temporal_is_used():
    assert "WARDEN_TEMPORAL_API_KEY" in settings.SECRETS
    assert "WARDEN_TEMPORAL_API_KEY" in settings.RESTRICTED


@pytest.mark.parametrize("address", [
    "evil.example:7233",                       # another host
    "ns.acct.tmprl.cloud.evil.example:7233",   # a look-alike suffix
    "other.acct.tmprl.cloud:7233",             # another namespace's endpoint
    "ns.acct.tmprl.cloud:443",                 # another port
    "ap-south-1.aws.api.temporal.io:7233",     # a regional endpoint: not the configured one
    "10.0.3.7:7233",
])
def test_the_api_key_goes_only_to_the_configured_namespace_endpoint(seen, monkeypatch, address):
    """B23: with a key set, any address but <namespace>.tmprl.cloud:7233 is refused before a connection is tried."""
    monkeypatch.setenv("WARDEN_TEMPORAL_ADDRESS", address)
    monkeypatch.setenv("WARDEN_TEMPORAL_NAMESPACE", "ns.acct")
    monkeypatch.setenv("WARDEN_TEMPORAL_API_KEY", "k" * 8)
    connecting = runtime.connect(key=KEY)
    with pytest.raises(RuntimeError, match="only the namespace's own"):
        asyncio.run(connecting)
    assert seen == []


@pytest.mark.parametrize("namespace", ["", "ns", "ns.acct.tmprl.cloud:7233#", "NS.acct/x"])
def test_a_namespace_that_is_not_name_dot_account_is_refused(seen, monkeypatch, namespace):
    monkeypatch.setenv("WARDEN_TEMPORAL_ADDRESS", "ns.acct.tmprl.cloud:7233")
    monkeypatch.setenv("WARDEN_TEMPORAL_NAMESPACE", namespace)
    monkeypatch.setenv("WARDEN_TEMPORAL_API_KEY", "k" * 8)
    connecting = runtime.connect(key=KEY)
    with pytest.raises(RuntimeError, match="not a Temporal Cloud namespace"):
        asyncio.run(connecting)
    assert seen == []


def test_the_endpoint_check_is_case_insensitive_and_the_local_server_is_not_checked(seen, monkeypatch):
    monkeypatch.setenv("WARDEN_TEMPORAL_ADDRESS", "NS.ACCT.TMPRL.CLOUD:7233")
    monkeypatch.setenv("WARDEN_TEMPORAL_NAMESPACE", "ns.acct")
    monkeypatch.setenv("WARDEN_TEMPORAL_API_KEY", "k" * 8)
    assert asyncio.run(runtime.connect(key=KEY)) == "client"
    monkeypatch.setenv("WARDEN_TEMPORAL_ADDRESS", "127.0.0.1:7233")
    monkeypatch.delenv("WARDEN_TEMPORAL_NAMESPACE")
    assert asyncio.run(runtime.connect(key=KEY)) == "client"

