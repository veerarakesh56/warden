"""Register R8-O2: the proving ground's Redis takes TLS in transit as well as at rest, and every client of it in the
benchmark apps connects with TLS - a server that requires TLS refuses a plain client, so the two move together."""

from __future__ import annotations

import ast
import importlib.util
import pathlib
import re
import socket
import ssl
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_redis_takes_tls_in_transit_and_every_app_client_uses_it():
    data = (ROOT / "terraform" / "fullstack" / "data.tf").read_text(encoding="utf-8")
    group = data[data.index('resource "aws_elasticache_replication_group" "redis"'):]
    group = group[:group.index("\n}\n")]
    assert re.search(r"transit_encryption_enabled = true\b", group) and re.search(r"at_rest_encryption_enabled = true\b", group)
    clients = [(p, line) for p in (ROOT / "scenarios" / "fullstack").rglob("*.py")
               for line in p.read_text(encoding="utf-8").splitlines() if "redis.Redis(" in line]
    assert len(clients) >= 3, clients
    assert all("ssl=True" in line for _, line in clients), [str(p) for p, line in clients if "ssl=True" not in line]


# --------------------------------------------------------------------------- redis-py 8: every option explicit
# redis-py 6.0 turned the TLS host name check on, and 8.0 changed what a client does when the cache is unwell:
# RESP3, 10 retries with exponential backoff, TCP keepalive, 5 s timeouts. The fault scenarios time how fast the
# apps fail when ElastiCache is sick, so each client states every one of those options instead of taking the
# library's defaults: RESP2, one try (no retry), no keepalive, its own timeouts; TLS verifies the certificate and
# the host name (REDIS_HOST is the ElastiCache endpoint name the certificate is issued for).
# redis-py itself is in the apps' check environment (CI · apps), which runs these; the tool's and the infra's
# environments have no redis, so only the tests that build a client skip there - the source checks always run.

EXPLICIT = {"ssl": True, "ssl_cert_reqs": "required", "ssl_check_hostname": True, "protocol": 2,
            "socket_keepalive": False}
# Each client's own timeouts (seconds), as they were under redis 5.2.1: what the fault scenarios were timed with.
TIMEOUTS = {"app/app.py": (2, 2), "lambdas/ops/app.py": (10, 5), "lambdas/reconciler/app.py": (3, 3)}


def _client_calls() -> dict[str, dict]:
    """{file: the keyword arguments of its one redis.Redis(...) call}; retry= is rebuilt from its source."""
    found: dict[str, dict] = {}
    base = ROOT / "scenarios" / "fullstack"
    for path in sorted(base.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "Redis"
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "redis"):
                rel = path.relative_to(base).as_posix()
                assert rel not in found, f"{rel}: more than one redis.Redis(...) call"
                assert not node.args and all(k.arg for k in node.keywords), f"{rel}: keyword arguments only"
                kwargs = {}
                for k in node.keywords:
                    if k.arg == "retry":
                        kwargs[k.arg] = ast.unparse(k.value)
                    elif k.arg != "host":
                        kwargs[k.arg] = ast.literal_eval(k.value)
                found[rel] = kwargs
    return found


def test_every_redis_client_states_protocol_retries_keepalive_timeouts_and_tls():
    calls = _client_calls()
    assert set(calls) == set(TIMEOUTS), calls
    for rel, kwargs in calls.items():
        assert {k: kwargs.get(k) for k in EXPLICIT} == EXPLICIT, rel
        assert kwargs.get("retry") == "Retry(NoBackoff(), 0)", (rel, kwargs.get("retry"))
        assert (kwargs.get("socket_timeout"), kwargs.get("socket_connect_timeout")) == TIMEOUTS[rel], rel
        assert kwargs.get("port") == 6379, rel


@pytest.fixture
def redis():
    return pytest.importorskip("redis")


def _retry(redis, source: str | None) -> dict:
    """The client's retry= as redis-py gets it: only Retry(NoBackoff(), <n>) is understood; none = the default."""
    if source is None:
        return {}
    call = ast.parse(source, mode="eval").body
    assert (isinstance(call, ast.Call) and ast.unparse(call.func) == "Retry" and len(call.args) == 2
            and ast.unparse(call.args[0]) == "NoBackoff()"), source
    return {"retry": redis.retry.Retry(redis.backoff.NoBackoff(), ast.literal_eval(call.args[1]))}


def _built(redis, kwargs: dict, **override):
    """The client as its source builds it (host aside), under the installed redis-py."""
    plain = {k: v for k, v in kwargs.items() if k != "retry"}
    return redis.Redis(**{"host": "cache.example.invalid", **plain, **_retry(redis, kwargs.get("retry")), **override})


@pytest.mark.parametrize("rel", sorted(TIMEOUTS))
def test_the_installed_redis_py_builds_each_client_as_stated(redis, rel):
    """What redis-py actually makes of the options (no server needed: a connection object is built, not opened)."""
    conn = _built(redis, _client_calls()[rel]).connection_pool.make_connection()
    assert isinstance(conn, redis.connection.SSLConnection)
    assert conn.cert_reqs == ssl.CERT_REQUIRED and conn.check_hostname is True
    assert conn.protocol == 2
    assert conn.retry.get_retries() == 0
    assert conn.socket_keepalive is False
    assert (conn.socket_timeout, conn.socket_connect_timeout) == TIMEOUTS[rel]


def test_the_app_cache_client_is_the_one_checked(redis, monkeypatch):
    """app.cache() itself, not only its source text: the image's client under the installed redis-py."""
    pytest.importorskip("psycopg")
    pytest.importorskip("boto3")
    monkeypatch.setenv("REDIS_HOST", "cache.example.invalid")
    spec = importlib.util.spec_from_file_location("fullstack_app_r8", ROOT / "scenarios" / "fullstack" / "app" / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    conn = module.cache().connection_pool.make_connection()
    assert conn.protocol == 2 and conn.retry.get_retries() == 0 and conn.socket_keepalive is False
    assert conn.check_hostname is True and conn.cert_reqs == ssl.CERT_REQUIRED
    assert (conn.socket_timeout, conn.socket_connect_timeout) == (2, 2)


@pytest.mark.parametrize("rel", sorted(TIMEOUTS))
def test_a_cache_that_never_answers_fails_the_call_after_one_timeout(redis, rel):
    """A server that takes the TCP connection and never answers (the TLS handshake stalls): one try, so the call
    fails after about one timeout. redis-py 8's default retry (10 tries with backoff) would take many times longer.
    The client's own options, with only the timeouts shortened so the test is quick."""
    server = socket.create_server(("127.0.0.1", 0))
    try:
        port = server.getsockname()[1]
        client = _built(redis, _client_calls()[rel], host="127.0.0.1", port=port, socket_timeout=0.3,
                        socket_connect_timeout=0.3)
        started = time.monotonic()
        with pytest.raises(redis.exceptions.TimeoutError):
            client.ping()
        assert 0.25 < time.monotonic() - started < 1.2
    finally:
        server.close()
