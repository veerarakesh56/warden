"""B35 self-alarms: WARDEN pages a person when WARDEN itself is broken, through the pager (paging.tf), and never for a
planned pause.

- Every runtime zone, not only the core one: the core zone's beat needs each deployed zone's worker polling its queue.
- Temporal refusing a worker's key, the model's key refused, the audit database unreachable or full: ERROR lines,
  which the worker-errors alarm pages - every zone writes to the one worker log group.
- An error inside an EventBridge-invoked Lambda: the event goes to the dead-letter queue (which pages) by Lambda's
  on-failure destination, instead of being dropped after Lambda's retries.
- Paused (SSM tf/paused): no worker, front door or stopped-task signal pages.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import pathlib
import re
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest
from google.protobuf.timestamp_pb2 import Timestamp
from pydantic import BaseModel
from temporalio.api.enums.v1 import TaskQueueType
from temporalio.service import RPCError, RPCStatusCode

from warden import audit, cli, llm, runtime
from warden.observability import GatedFormatter
from warden.workflows import ZONES, zone_queue

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "terraform" / "modules" / "warden-runtime"
# paging.tf's worker-errors filter: an ERROR or CRITICAL line in the log gate's format.
_WORKER_ERRORS = re.compile(r" (ERROR|CRITICAL) ")


def _tf(name: str) -> str:
    return (MODULE / name).read_text(encoding="utf-8")


def _resource(tf: str, header: str) -> str:
    body = tf[tf.index(header):]
    return body[:body.index("\n}\n")]


def _paged_line(record: logging.LogRecord) -> str:
    return GatedFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s").format(record)


# ------------------------------------------------------------------ every zone, through the core zone's beat

class _Poller:
    def __init__(self, ago: timedelta):
        self.last_access_time = Timestamp()
        self.last_access_time.FromDatetime(datetime.now(UTC) - ago)


class _Service:
    def __init__(self, pollers: dict[str, list[_Poller]], error: Exception | None = None):
        self.pollers, self.error, self.asked = pollers, error, []

    async def describe_task_queue(self, req):
        self.asked.append((req.namespace, req.task_queue.name, req.task_queue_type))
        if self.error:
            raise self.error
        return type("Got", (), {"pollers": self.pollers.get(req.task_queue.name, [])})()


class _Client:
    namespace = "warden-ns"

    def __init__(self, pollers=None, error=None, clock_error=None):
        self.workflow_service = _Service(pollers or {}, error)
        self.clock_error = clock_error

    async def execute_workflow(self, *a, **kw):
        if self.clock_error:
            raise self.clock_error
        return datetime.now(UTC)


def _live(*zones, ago=timedelta(seconds=30)):
    return {zone_queue(z): [_Poller(ago)] for z in zones}


def test_the_beat_vouches_for_every_zone_and_names_a_silent_one():
    beats = []
    every = tuple(ZONES)
    client = _Client(_live(*every))
    assert asyncio.run(runtime.beat(client, lambda: beats.append(1), zones=every)) == ""
    assert beats == [1]
    assert [a[1] for a in client.workflow_service.asked] == [zone_queue(z) for z in every]
    assert {(a[0], a[2]) for a in client.workflow_service.asked} == {
        ("warden-ns", TaskQueueType.TASK_QUEUE_TYPE_ACTIVITY)}

    stale = _live(*every)
    stale[zone_queue("read")] = [_Poller(timedelta(minutes=4))]  # a worker gone: still listed, not polling
    stale.pop(zone_queue("act"))  # no worker at all
    problem = asyncio.run(runtime.beat(_Client(stale), lambda: beats.append(1), zones=every))
    assert beats == [1], "a beat was published with a zone not polling"
    assert "read, act zones" in problem
    assert "polled" in problem


def test_without_zones_the_beat_is_the_round_trip_alone():
    beats = []
    client = _Client()
    assert asyncio.run(runtime.beat(client, lambda: beats.append(1))) == ""
    assert beats == [1]
    assert client.workflow_service.asked == []


def test_a_zone_that_cannot_be_described_is_a_missed_beat_never_a_crashed_worker(monkeypatch):
    beats, lines = [], []

    async def sleep(_s):
        raise asyncio.CancelledError

    monkeypatch.setattr(runtime.asyncio, "sleep", sleep)
    client = _Client(error=RPCError("unavailable", RPCStatusCode.UNAVAILABLE, b""))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(runtime.heartbeat(client, lambda: beats.append(1), every=timedelta(seconds=1), log=lines.append,
                                      zones=("llm",)))
    assert beats == []
    assert lines
    assert "heartbeat missed" in lines[0]


def test_the_zones_come_from_the_runtime_and_a_zone_warden_lacks_refuses_to_start(monkeypatch):
    monkeypatch.delenv("WARDEN_HEARTBEAT_ZONES", raising=False)
    assert runtime.heartbeat_zones() == ()
    monkeypatch.setenv("WARDEN_HEARTBEAT_ZONES", " read,llm ,, notify,act")
    assert runtime.heartbeat_zones() == ("read", "llm", "notify", "act")
    monkeypatch.setenv("WARDEN_HEARTBEAT_ZONES", "read,nope")
    with pytest.raises(ValueError, match="nope"):
        runtime.heartbeat_zones()


def test_only_the_core_zones_beat_vouches_for_the_other_zones(monkeypatch):
    monkeypatch.setenv("WARDEN_HEARTBEAT_ZONES", "read,llm")
    assert runtime.heartbeat_zones("core") == ("read", "llm")
    for zone in ("all", "read", "llm", "notify", "act"):
        assert runtime.heartbeat_zones(zone) == (), zone


def test_the_core_worker_refuses_to_start_with_a_zone_warden_lacks(monkeypatch, capsys):
    monkeypatch.setenv("WARDEN_HEARTBEAT_ZONES", "read,nope")

    async def connect(*a, **kw):
        raise AssertionError("connected before the zones were checked")

    monkeypatch.setattr(runtime, "connect", connect)
    args = argparse.Namespace(cmd="worker", zone="core", platform="none")
    assert asyncio.run(cli._workflow_command(args)) == 1
    assert "nope" in capsys.readouterr().err


def test_the_core_worker_beats_for_the_zones_it_was_given(monkeypatch):
    monkeypatch.setenv("WARDEN_HEARTBEAT_ZONES", "read,act")
    seen = {}

    class _Started(Exception):
        pass

    async def heartbeat(client, publish, **kw):
        seen.update(kw)
        raise _Started

    @contextlib.asynccontextmanager
    async def serving(*a, **kw):
        yield

    async def ok(*a, **kw):
        return ""

    async def connect(*a, **kw):
        return object()

    monkeypatch.setattr(runtime, "connect", connect)
    monkeypatch.setattr(runtime, "serving", serving)
    monkeypatch.setattr(runtime, "check_clock", ok)
    monkeypatch.setattr(runtime, "heartbeat", heartbeat)
    monkeypatch.setattr(runtime, "cloudwatch_publisher", lambda *a: (lambda: None))
    monkeypatch.setattr(runtime, "open_audit", lambda: None)
    monkeypatch.setattr(runtime, "approver_policy", lambda: None)
    monkeypatch.setattr(cli, "resolve_backend", lambda: None)
    monkeypatch.setattr(cli, "_install_log_gate", lambda: None)
    with pytest.raises(_Started):
        asyncio.run(cli._workflow_command(argparse.Namespace(cmd="worker", zone="core", platform="none")))
    assert seen["zones"] == ("read", "act")


def test_terraform_gives_the_core_zone_every_other_deployed_zone():
    compute = _tf("compute.tf")
    assert ('each.key == "core" ? { WARDEN_HEARTBEAT_ZONES = join(",", sort([for z in keys(local.zones) : z if z != '
            '"core"])) } : {},') in compute
    # Every zone Terraform deploys is one WARDEN has: the worker refuses a zone it lacks (heartbeat_zones).
    zones_block = _tf("iam.tf").split("  zones = {", 1)[1].split("\n  }\n", 1)[0]
    deployed = set(re.findall(r"^\s{4}(\w+)\s*=\s*\{", zones_block, re.MULTILINE)) - {"core"}
    assert deployed == set(ZONES)
    assert "or a zone (read, llm, notify, act...) has no worker polling its queue" in _tf("heartbeat.tf")


# ------------------------------------------------------------------ keys refused, the audit database gone

def test_temporal_refusing_the_key_is_an_error_line_the_worker_errors_alarm_pages(caplog):
    caplog.set_level(logging.INFO)
    for status in (RPCStatusCode.UNAUTHENTICATED, RPCStatusCode.PERMISSION_DENIED):
        caplog.clear()
        with pytest.raises(RPCError):
            asyncio.run(runtime.beat(_Client(clock_error=RPCError("no", status, b"")), lambda: None))
        errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
        assert len(errors) == 1
        assert status.name in errors[0].getMessage()
        assert _WORKER_ERRORS.search(_paged_line(errors[0]))
    caplog.clear()
    with pytest.raises(RPCError):
        asyncio.run(runtime.beat(_Client(clock_error=RPCError("busy", RPCStatusCode.UNAVAILABLE, b"")),
                                 lambda: None))
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR], "an outage is the missing beats' page"


class _Toy(BaseModel):
    answer: str


class _Refusing:
    name, model = "refusing", "refusing-1"

    def __init__(self, status: int, attr: str = "status_code"):
        self.status, self.attr = status, attr

    def complete(self, *, system: str, user: str, schema: Any = None):
        err = RuntimeError("the provider said: sk-detail")
        setattr(err, self.attr, self.status)
        raise err


@pytest.mark.parametrize(("status", "attr", "paged"), [
    (401, "status_code", True), (403, "status_code", True), (401, "code", True),
    (400, "status_code", False), (404, "status_code", False), (429, "status_code", False), (503, "code", False)])
def test_the_models_key_refused_is_an_error_line_and_nothing_else_is(caplog, status, attr, paged):
    caplog.set_level(logging.INFO)
    with pytest.raises(llm.ModelRefused):
        llm.LLMClient(provider=_Refusing(status, attr), mock=False).structured(system="s", user="u", schema=_Toy,
                                                                                retries=0)
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == (1 if paged else 0)
    if paged:
        assert f"HTTP {status}" in errors[0].getMessage()
        assert "sk-detail" not in errors[0].getMessage()
        assert _WORKER_ERRORS.search(_paged_line(errors[0]))


class _Db:
    def __init__(self, error: Exception):
        self.error = error

    def execute(self, *a, **kw):
        raise self.error


def _store(error: Exception, pg: bool = True) -> Any:
    store = object.__new__(audit._Store)
    store._lock, store.pg, store.db = threading.RLock(), pg, _Db(error)
    return store


@pytest.mark.parametrize("error", [psycopg.OperationalError("gone"), psycopg.errors.DiskFull("full"),
                                   psycopg.errors.AdminShutdown("stopped")])
def test_the_audit_database_gone_or_full_is_one_error_line(caplog, error):
    caplog.set_level(logging.INFO)
    with pytest.raises(type(error)):
        _store(error).run("SELECT 1")
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1
    assert type(error).__name__ in errors[0].getMessage()
    assert "gone" not in errors[0].getMessage()  # its kind, never its text
    assert "full)" not in errors[0].getMessage()
    assert _WORKER_ERRORS.search(_paged_line(errors[0]))
    again = type(error)("again")
    with pytest.raises(type(error)), audit._said_when_unreachable(True):
        _store(again).run("SELECT 1")  # inside a transaction's guard as well: said once, not twice
    assert len([r for r in caplog.records if r.levelno >= logging.ERROR]) == 2


def test_the_audit_database_unreachable_at_start_or_at_commit_is_said_too(caplog, monkeypatch):
    def refuse(dsn):
        raise psycopg.OperationalError("connection refused")

    monkeypatch.setattr(audit, "_pg_connect", refuse)
    with pytest.raises(psycopg.OperationalError):
        audit._Store("postgresql://warden@audit.invalid/warden")

    class _NoCommit:
        def transaction(self):
            raise psycopg.errors.AdminShutdown("stopped")

    store = _store(psycopg.OperationalError("unused"))
    store.db = _NoCommit()
    with pytest.raises(psycopg.errors.AdminShutdown), store.transaction():
        pass
    said = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(said) == 2
    assert "(OperationalError)" in said[0]
    assert "(AdminShutdown)" in said[1]


@pytest.mark.parametrize(("error", "pg"), [(psycopg.errors.DeadlockDetected("retry"), True),
                                           (psycopg.errors.SerializationFailure("retry"), True),
                                           (psycopg.errors.UniqueViolation("dup"), True),
                                           (psycopg.OperationalError("not postgres"), False)])
def test_a_retried_conflict_a_bad_row_or_sqlite_pages_nobody(caplog, error, pg):
    with pytest.raises(type(error)):
        _store(error, pg).run("SELECT 1")
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


def test_the_worker_errors_alarm_names_what_it_now_pages():
    paging = _tf("paging.tf")
    assert 'log_group_name = aws_cloudwatch_log_group.worker.name' in paging
    assert "the model's or Temporal's key refused, or the audit database unreachable or full" in paging
    # Every zone writes to the one log group the filter reads.
    assert '"awslogs-group"         = aws_cloudwatch_log_group.worker.name' in _tf("compute.tf")


# ------------------------------------------------------------------ an error inside an EventBridge-invoked Lambda

def test_an_event_a_lambda_failed_on_goes_to_the_paging_dead_letter_queue():
    front = _tf("frontdoor.tf")
    assert 'async_front_doors = ["alarm", "actor-use"]' in front
    cfg = _resource(front, 'resource "aws_lambda_function_event_invoke_config" "front_door"')
    assert "for_each                     = toset(local.async_front_doors)" in cfg
    assert "destination = aws_sqs_queue.alarm_dlq.arn" in cfg
    assert "on_failure" in cfg
    assert "depends_on = [aws_iam_role_policy.front_door]" in cfg
    # Each function EventBridge invokes is in the list: every event target that is a front door.
    targets = re.findall(r'arn\s*=\s*aws_lambda_function\.front_door\["([\w-]+)"\]\.arn', front + _tf("witness.tf"))
    assert set(targets) == {"alarm", "actor-use"}
    iam = _tf("iam.tf")
    assert ('contains(local.async_front_doors, each.key) ? [{ Sid = "KeepWhatFailed", Effect = "Allow", Action = '
            '["sqs:SendMessage"], Resource = aws_sqs_queue.alarm_dlq.arn }] : [],') in iam
    # The queue pages, and is one of the self-alarms the pager repeats.
    assert "or WARDEN's function failed on it every time" in front
    assert "aws_cloudwatch_metric_alarm.alarm_dlq.alarm_name" in _tf("paging.tf")


# ------------------------------------------------------------------ a planned pause pages nobody

def test_paused_no_front_door_or_stopped_worker_pages_and_the_pager_still_does():
    paging = _tf("paging.tf")
    assert ("paged_functions = merge(var.paused ? {} : { for k, f in aws_lambda_function.front_door : k => "
            "f.function_name },") in paging
    assert "{ ack = aws_lambda_function.ack.function_name, pager = aws_lambda_function.pager.function_name })" in paging
    stopped = _resource(paging, 'resource "aws_cloudwatch_event_rule" "worker_stopped"')
    assert 'state       = var.paused ? "DISABLED" : "ENABLED"' in stopped
    # The heartbeat - which now speaks for every zone - and the worker errors stay off while paused.
    for alarm in ("heartbeat", "synthetic"):
        assert "actions_enabled     = !var.paused" in _resource(_tf("heartbeat.tf"),
                                                                f'resource "aws_cloudwatch_metric_alarm" "{alarm}"')
    assert "actions_enabled     = !var.paused" in _resource(paging, 'resource "aws_cloudwatch_metric_alarm" '
                                                                    '"worker_errors"')
    self_alarms = paging[paging.index("self_alarms = "):paging.index("paged_functions")]
    paused_part = self_alarms[:self_alarms.index("], [")]
    for name in ("heartbeat", "synthetic", "worker_errors"):
        assert f"aws_cloudwatch_metric_alarm.{name}.alarm_name" in paused_part
