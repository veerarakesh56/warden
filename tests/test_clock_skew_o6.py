"""Register O6: a worker whose clock is off the Temporal server's refuses to start."""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta

from temporalio.testing import WorkflowEnvironment

from warden import codec, runtime

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)


def test_a_server_time_inside_the_round_trip_passes():
    assert runtime.skew_problem(NOW, NOW + timedelta(seconds=1), NOW + timedelta(seconds=2)) == ""
    assert runtime.skew_problem(NOW, NOW - timedelta(seconds=59), NOW + timedelta(seconds=1)) == ""


def test_a_clock_off_by_more_than_the_tolerance_is_refused():
    behind = runtime.skew_problem(NOW, NOW + timedelta(minutes=3), NOW + timedelta(seconds=1))
    ahead = runtime.skew_problem(NOW, NOW - timedelta(minutes=3), NOW + timedelta(seconds=1))
    assert "behind" in behind and "O6" in behind
    assert "ahead of" in ahead


def test_the_worker_runs_the_clock_check_against_the_servers_time():
    async def main():
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, runtime.worker(env.client, log=None, policy=None, task_queue="q"):  # what `warden worker` runs
            return await runtime.check_clock(env.client, "q", wait_s=20)

    assert asyncio.run(main()) == ""


def test_the_worker_command_stops_when_the_clock_is_off(monkeypatch, capsys):
    import contextlib

    from warden import cli

    async def connect():
        return object()

    @contextlib.asynccontextmanager
    async def worker(client, **kw):
        yield None

    async def check_clock(client):
        return "this host's clock is 180s behind the Temporal server's (register O6)"

    monkeypatch.setattr(runtime, "connect", connect)
    monkeypatch.setattr(runtime, "worker", worker)
    monkeypatch.setattr(runtime, "check_clock", check_clock)
    monkeypatch.setattr(runtime, "open_audit", lambda: None)
    monkeypatch.setattr(runtime, "_path", lambda env, default=None: env)
    monkeypatch.setattr(runtime, "approver_policy", lambda: None)
    monkeypatch.setattr(cli, "_platform", lambda name: None)
    monkeypatch.setattr(cli, "resolve_backend", lambda: None)

    class _Stop:  # a worker that got past the check would wait here for Ctrl+C; end the test instead
        async def wait(self):
            return None

    monkeypatch.setattr(cli.asyncio, "Event", _Stop)
    assert cli.main(["worker"]) == 1
    out, err = capsys.readouterr()
    assert "O6" in err and "worker running" not in out
