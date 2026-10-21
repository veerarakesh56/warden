"""Item 7a: every model request's time, in whole milliseconds, on WARDEN's record - an answer, a failure and every
retry alike. Measured with the monotonic clock inside the activity that makes the call (LLMClient, eldane.ask), never
from workflow time, so a clock step cannot make one negative and a replay cannot change one."""

from __future__ import annotations

import time
from typing import Any

import pytest
from pydantic import BaseModel

from warden import audit, eldane, llm
from warden.activities import IncidentActivities
from warden.cli import DEMO_ALERTS
from warden.llm import LLMClient, ModelCallTimeout, ModelRefused
from warden.models import Alert
from warden.providers import Completion, ProviderError

PAUSE_S = 0.02  # each fake request takes at least this long, so a measured time is seen to be one
GOOD = '{"answer": "ok", "score": 1}'


class Toy(BaseModel):
    answer: str
    score: int


class Scripted:
    """Each request waits PAUSE_S, then answers the next scripted text - or raises it, when it is an exception."""

    name, model = "fake", "fake-1"

    def __init__(self, *script: Any) -> None:
        self.script, self.calls = list(script), 0

    def complete(self, *, system: str, user: str, schema: Any = None) -> Completion:
        self.calls += 1
        time.sleep(PAUSE_S)
        step = self.script[min(self.calls - 1, len(self.script) - 1)]
        if isinstance(step, BaseException):
            raise step
        return Completion(step, 10, 5)


def _asked(provider: Any, **kw: Any) -> LLMClient:
    client = LLMClient(provider=provider, mock=False, **kw)
    try:
        client.structured(system="s", user="u", schema=Toy)
    except (ModelRefused, ModelCallTimeout):
        pass
    return client


def _measured(values: list[int], count: int) -> None:
    assert len(values) == count
    assert all(isinstance(v, int) for v in values)
    assert all(v >= PAUSE_S * 1000 * 0.5 for v in values), values  # each one a real duration, never negative


def test_an_answer_has_its_time():
    _measured(_asked(Scripted(GOOD)).latencies_ms, 1)


def test_a_retry_has_a_time_for_each_request():
    _measured(_asked(Scripted("not json", GOOD)).latencies_ms, 2)


def test_a_failure_has_a_time_for_each_request_retries_included():
    p = Scripted(ProviderError("503 Service Unavailable"))
    client = _asked(p)
    assert p.calls == 3
    _measured(client.latencies_ms, 3)


def test_a_permanent_failure_has_its_time():
    err = ProviderError("401")
    err.status_code = 401
    _measured(_asked(Scripted(err)).latencies_ms, 1)


def test_a_request_that_timed_out_has_its_time():
    class Hung:
        name, model = "hang", "hang-1"

        def complete(self, *, system: str, user: str, schema: Any = None) -> Completion:
            time.sleep(10)
            return Completion(GOOD, 1, 1)

    client = _asked(Hung(), call_timeout_s=0.1)
    assert len(client.latencies_ms) == 1
    assert client.latencies_ms[0] >= 2000  # the backstop: call_timeout_s + 2 s


def test_a_mock_answer_has_its_time_too():
    client = LLMClient(mock=True)
    client.structured(system="s", user="u", schema=Toy, mock_factory=lambda: Toy(answer="a", score=1))
    assert len(client.latencies_ms) == 1
    assert client.latencies_ms[0] >= 0


def test_a_time_is_never_negative():
    assert llm.elapsed_ms(time.monotonic() + 5) == 0  # a reading from "the future" is clamped, not negative
    assert llm.elapsed_ms(time.monotonic() - 1.5) >= 1500


def test_the_measure_is_the_monotonic_clock_not_the_wall_clock(monkeypatch):
    """Plant check's target: a wall clock stepped back an hour mid-call changes nothing."""
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() - 3600)
    _measured(_asked(Scripted(GOOD)).latencies_ms, 1)


def test_the_incidents_spend_row_carries_each_requests_time(tmp_path):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    p = Scripted(ProviderError("503 Service Unavailable"))
    acts = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(provider=p, mock=False))
    pack = acts.prepare(Alert(**DEMO_ALERTS["inc-002"]))
    acts.diagnose(pack)
    [row] = [e["body"] for e in log.entries(pack.alert.alert_id, kinds=("incident.llm_spend",))]
    assert p.calls == 3
    _measured(row["latency_ms"], 3)


def test_a_mock_diagnosis_row_has_a_time_for_its_one_call(tmp_path):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    acts = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(mock=True))
    pack = acts.prepare(Alert(**DEMO_ALERTS["inc-002"]))
    acts.diagnose(pack)
    [row] = [e["body"] for e in log.entries(pack.alert.alert_id, kinds=("incident.llm_spend",))]
    assert len(row["latency_ms"]) == 1
    assert row["latency_ms"][0] >= 0


@pytest.mark.parametrize("answer", [ProviderError("down"), '{"agree": true, "reasons": []}'], ids=["failed", "answered"])
def test_eldanes_call_row_has_its_time(tmp_path, answer):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    eldane.ask(log, "inc-1", Scripted(answer), "evidence", set(), purpose="blind")
    [row] = [e["body"] for e in log.entries("inc-1", kinds=(eldane.CALL,))]
    assert isinstance(row["latency_ms"], int)
    assert row["latency_ms"] >= PAUSE_S * 1000 * 0.5
