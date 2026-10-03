"""Register C13: WARDEN fails together with the incident and nobody notices. A worker beats only when a whole round
trip through Temporal works (a workflow run by a worker on its task queue, its result decoded, the clock in
tolerance); a failed beat publishes nothing, and the alarm that pages on missing beats reads silence as failure."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from warden import runtime


class _Client:
    def __init__(self, server_time=None, error=None):
        self.server_time, self.error = server_time, error

    async def execute_workflow(self, *a, **kw):
        if self.error:
            raise self.error
        return self.server_time or datetime.now(UTC)


def test_a_beat_is_published_only_when_the_round_trip_works():
    beats = []
    assert asyncio.run(runtime.beat(_Client(), lambda: beats.append(1))) == "" and beats == [1]
    skewed = _Client(server_time=datetime.now(UTC) + timedelta(hours=1))
    assert "clock" in asyncio.run(runtime.beat(skewed, lambda: beats.append(1))) and beats == [1]


def test_a_beat_that_cannot_run_is_missed_never_a_crashed_worker(monkeypatch):
    lines, beats = [], []
    sleeps = {"n": 0}

    async def sleep(_s):
        sleeps["n"] += 1
        if sleeps["n"] >= 2:
            raise asyncio.CancelledError

    monkeypatch.setattr(runtime.asyncio, "sleep", sleep)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(runtime.heartbeat(_Client(error=RuntimeError("temporal down")), lambda: beats.append(1),
                                      every=timedelta(seconds=1), log=lines.append))
    assert beats == [] and len(lines) == 2 and all("heartbeat missed" in line for line in lines)


def test_the_publisher_is_off_without_a_namespace_and_names_the_metric_with_one(monkeypatch):
    monkeypatch.delenv("WARDEN_HEARTBEAT_NAMESPACE", raising=False)
    assert runtime.cloudwatch_publisher() is None
    sent = []

    class _Cw:
        def put_metric_data(self, **kw):
            sent.append(kw)

    import boto3

    monkeypatch.setenv("WARDEN_HEARTBEAT_NAMESPACE", "WARDEN/dev")
    monkeypatch.setattr(boto3, "client", lambda *a, **kw: _Cw())
    monkeypatch.setattr("warden.environments.region", lambda: "test-region-1")
    runtime.cloudwatch_publisher()()
    assert sent == [{"Namespace": "WARDEN/dev", "MetricData": [{"MetricName": "Heartbeat", "Value": 1, "Unit": "Count",
                                                               "Dimensions": [{"Name": "TaskQueue", "Value": "warden"}]}]}]


def test_the_default_beat_is_five_minutes():
    assert runtime.HEARTBEAT_EVERY == timedelta(minutes=5)
