"""The fullstack lab's ops Lambda (Redis admin inside the VPC) and the traffic Lambda's failed-call log, run against
stand-ins: the tool's test environment has no redis-py, and neither Lambda may reach a network here."""

from __future__ import annotations

import importlib.util
import logging
import pathlib
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
LAMBDAS = ROOT / "demo-app" / "lambdas"
INFO = {
    "used_memory": 1,
    "maxmemory": 2,
    "maxmemory_policy": "volatile-lru",
    "evicted_keys": 3,
    "connected_clients": 4,
    "other": 5,
}
FIGURES = {k: v for k, v in INFO.items() if k != "other"}


class ResponseError(Exception):
    pass


class FakeRedis:
    """Records every key written and deleted; `full_after` makes the server refuse writes past that many keys."""

    def __init__(self, keys=(), full_after=None):
        self.keys = list(keys)
        self.written: list[str] = []
        self.deletes: list[int] = []
        self.full_after = full_after

    def info(self):
        return dict(INFO)

    def pipeline(self, transaction):
        assert transaction is False
        return FakePipe(self)

    def scan_iter(self, match, count):
        assert count == 1000
        return [k for k in self.keys if k.startswith(match.rstrip("*"))]

    def delete(self, *names):
        self.deletes.append(len(names))
        return len(names)


class FakePipe:
    def __init__(self, r):
        self.r, self.queued = r, []

    def set(self, name, value, ex):
        assert ex == 3600
        assert len(value) == 100 * 1024
        self.queued.append(name)

    def execute(self):
        if (
            self.r.full_after is not None
            and len(self.r.written) + len(self.queued) > self.r.full_after
        ):
            raise ResponseError("OOM command not allowed")
        self.r.written.extend(self.queued)


@pytest.fixture
def ops(monkeypatch):
    made = []

    def client(**kwargs):
        made.append(kwargs)
        return monkeypatch.fake

    redis = types.ModuleType("redis")
    redis.Redis = client
    redis.exceptions = types.SimpleNamespace(ResponseError=ResponseError)
    backoff, retry = types.ModuleType("redis.backoff"), types.ModuleType("redis.retry")
    backoff.NoBackoff = lambda: "no-backoff"
    retry.Retry = lambda *a: ("retry", *a)
    for name, mod in (("redis", redis), ("redis.backoff", backoff), ("redis.retry", retry)):
        monkeypatch.setitem(sys.modules, name, mod)
    monkeypatch.setenv("REDIS_HOST", "cache.internal")
    spec = importlib.util.spec_from_file_location("fs_ops_lambda", LAMBDAS / "ops" / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.made = made
    return mod


def test_info_returns_only_the_memory_and_eviction_figures(ops, monkeypatch):
    monkeypatch.fake = FakeRedis()
    assert ops.handler({"op": "info"}, None) == FIGURES
    assert ops.made[0]["host"] == "cache.internal"


def test_fill_writes_the_asked_megabytes_in_batches_of_fifty(ops, monkeypatch):
    monkeypatch.fake = FakeRedis()
    out = ops.handler(
        {"op": "fill", "mb": 6}, None
    )  # 6 MB of 100 KiB values: 61 keys, so a batch of 50 and 11
    assert out == {"written": 61, **FIGURES}
    assert monkeypatch.fake.written == [f"filler:{i}" for i in range(61)]


def test_fill_defaults_to_400_megabytes_and_stops_at_the_servers_refusal(ops, monkeypatch, caplog):
    monkeypatch.fake = FakeRedis(full_after=120)
    with caplog.at_level(logging.INFO):
        out = ops.handler({"op": "fill", "prefix": "filler:x"}, None)
    assert out == {"written": 100, **FIGURES}  # the third batch of 50 is refused whole
    assert "fill stopped by the server after 100 keys" in caplog.text
    assert "fill prefix=filler:x keys=100" in caplog.text


def test_flush_deletes_every_key_under_the_prefix_in_batches_of_five_hundred(ops, monkeypatch):
    monkeypatch.fake = FakeRedis(keys=[f"filler:{i}" for i in range(1001)] + ["cart:1"])
    assert ops.handler({"op": "flush_prefix"}, None) == {"deleted": 1001, **FIGURES}
    assert monkeypatch.fake.deletes == [500, 500, 1]


def test_flush_of_an_exact_batch_sends_no_empty_delete(ops, monkeypatch):
    monkeypatch.fake = FakeRedis(keys=[f"filler:{i}" for i in range(500)])
    assert ops.handler({"op": "flush_prefix"}, None) == {"deleted": 500, **FIGURES}
    assert monkeypatch.fake.deletes == [500]


@pytest.mark.parametrize("op", ["fill", "flush_prefix"])
def test_an_application_prefix_is_refused_before_any_write(ops, monkeypatch, op):
    monkeypatch.fake = FakeRedis(keys=["cart:1"])
    with pytest.raises(ValueError, match="refusing prefix 'cart:'"):
        ops.handler({"op": op, "prefix": "cart:"}, None)
    assert monkeypatch.fake.written == []
    assert monkeypatch.fake.deletes == []


def test_an_unknown_op_is_refused(ops, monkeypatch):
    monkeypatch.fake = FakeRedis()
    with pytest.raises(ValueError, match="unknown op 'drop'"):
        ops.handler({"op": "drop"}, None)


def test_a_traffic_call_that_cannot_connect_logs_the_error_with_its_traceback_and_returns_0(
    monkeypatch, caplog
):
    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=lambda *a, **k: None))
    spec = importlib.util.spec_from_file_location("fs_traffic_log", LAMBDAS / "traffic" / "app.py")
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)

    class Refused:
        def open(self, *_a, **_k):
            raise ConnectionRefusedError("nobody home")

    monkeypatch.setattr(app, "_opener", lambda _url: Refused())
    with caplog.at_level(logging.ERROR):
        status = app._call("GET", "https://api.example/orders")
    assert status == 0
    [record] = caplog.records
    assert record.getMessage() == "GET https://api.example/orders failed"
    assert record.exc_info[0] is ConnectionRefusedError
    assert "nobody home" in caplog.text  # in the traceback
