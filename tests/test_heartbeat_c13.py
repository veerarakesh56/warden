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
    assert asyncio.run(runtime.beat(_Client(), lambda: beats.append(1))) == ""
    assert beats == [1]
    skewed = _Client(server_time=datetime.now(UTC) + timedelta(hours=1))
    assert "clock" in asyncio.run(runtime.beat(skewed, lambda: beats.append(1)))
    assert beats == [1]


def test_a_beat_that_cannot_run_is_missed_never_a_crashed_worker(monkeypatch):
    lines, beats = [], []
    sleeps = {"n": 0}

    async def sleep(_s):
        sleeps["n"] += 1
        if sleeps["n"] >= 2:
            raise asyncio.CancelledError

    monkeypatch.setattr(runtime.asyncio, "sleep", sleep)
    client = _Client(error=RuntimeError("temporal down"))
    beating = runtime.heartbeat(client, lambda: beats.append(1), every=timedelta(seconds=1), log=lines.append)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(beating)
    assert beats == []
    assert len(lines) == 2
    assert all("heartbeat missed" in line for line in lines)


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


def test_the_synthetic_incident_passes_only_when_the_model_answered_and_the_report_is_sent(monkeypatch):
    """Register C13's daily synthetic shadow incident: a bundled recording through the whole diagnosis path. The mock
    model answers here (CI); a run whose model never answered is a failure, never a pass."""
    assert runtime.synthetic() == ""
    from warden import graph

    real = graph.run

    def unanswered(alert, **kw):
        report = real(alert, **kw)
        return report.model_copy(update={"verdict": report.verdict.model_copy(
            update={"policy_ids": ["P0-MODEL-UNAVAILABLE", *report.verdict.policy_ids]})})
    monkeypatch.setattr(graph, "run", unanswered)
    assert runtime.synthetic() == "the model did not answer"


def test_the_synthetic_incident_reads_its_recording_and_fails_when_it_reads_nothing(monkeypatch):
    """Scenario fs-22: the day's incident id was looked up as the fixture's name, so the synthetic read no
    evidence from its first day, and passed."""
    from warden import graph

    seen = []
    real = graph.run

    def watch(alert, **kw):
        report = real(alert, **kw)
        seen.append(report.context)
        return report
    monkeypatch.setattr(graph, "run", watch)
    assert runtime.synthetic() == ""
    assert seen[0].logs
    assert not seen[0].tool_errors

    def blind(alert, **kw):
        report = real(alert, **kw)
        return report.model_copy(update={"context": report.context.model_copy(
            update={"logs": [], "metrics": {}, "recent_deploys": [], "tool_errors": ["logs: [failed] x"]})})
    monkeypatch.setattr(graph, "run", blind)
    assert runtime.synthetic() == "the recorded evidence was not read"


def test_the_synthetic_incident_fails_when_the_injection_detector_did_not_scan(monkeypatch):
    """Register R47: every environment scans, and the daily synthetic incident proves the detector loads where it runs -
    the cloud's llm zone loads it there - not only that the model answers."""
    from warden import graph

    real = graph.run

    def unscanned(alert, **kw):
        report = real(alert, **kw)
        return report.model_copy(update={"context": report.context.model_copy(
            update={"tripwire": "unavailable: model not loaded (OSError)"})})
    monkeypatch.setattr(graph, "run", unscanned)
    assert runtime.synthetic() == "the injection detector did not run (unavailable: model not loaded (OSError))"


def test_the_synthetic_runs_once_a_day_and_publishes_only_on_success(monkeypatch):
    clock = {"now": datetime(2026, 10, 3, 0, 0, tzinfo=UTC)}

    class _Dt:
        @staticmethod
        def now(tz=None):
            return clock["now"]

    runs, shadows, sleeps = [], [], {"n": 0}
    results = iter(["", "the model did not answer"])
    monkeypatch.setattr(runtime, "datetime", _Dt)
    monkeypatch.setattr(runtime, "synthetic", lambda: runs.append(clock["now"]) or next(results))

    async def sleep(_s):
        sleeps["n"] += 1
        clock["now"] += timedelta(hours=12)
        if sleeps["n"] >= 4:
            raise asyncio.CancelledError

    async def beat(*a, **kw):
        return ""
    monkeypatch.setattr(runtime.asyncio, "sleep", sleep)
    monkeypatch.setattr(runtime, "beat", beat)
    beating = runtime.heartbeat(_Client(), lambda: None, shadow=lambda: shadows.append(1))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(beating)
    assert len(runs) == 2
    assert runs[1] - runs[0] == timedelta(hours=24)  # beats every turn; the synthetic daily
    assert shadows == [1]  # published for the first (passed), not the second (failed)
