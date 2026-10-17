"""Hidden warnings, harness lot (owner, 2026-10-17): the `pragma: no cover` lines are covered now, and the harness's
kept broad catches on clean-up leave a record instead of a bare `pass`."""

from __future__ import annotations

import logging
import pathlib
import subprocess
import sys

import pytest
from scenarios import fullstack_cli, ops_db, runner

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import replay_gate  # after the sys.path line above


def test_the_benchmark_without_boto3_says_what_to_install(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", None)  # `import boto3` raises ImportError
    with pytest.raises(runner.RunnerError, match=r"needs boto3: pip install -e '\.\[aws\]'"):
        runner._live_harness(1.0)
    with pytest.raises(fullstack_cli.StepError, match=r"pip install -e '\.\[aws,k8s,postgres\]'"):
        fullstack_cli.live_env(pathlib.Path("unused"))


def test_the_kubernetes_wave_without_its_client_says_what_to_install(monkeypatch):
    monkeypatch.setitem(sys.modules, "kubernetes", None)
    with pytest.raises(runner.RunnerError, match=r"needs the client: pip install -e '\.\[k8s\]'"):
        runner._k8s_live_harness(1.0)


def test_the_replay_gate_names_no_commit_when_git_is_absent(monkeypatch):
    def absent(*a, **kw):
        raise FileNotFoundError("git")

    monkeypatch.setattr(subprocess, "run", absent)
    assert replay_gate._git_commit() == "unknown"


class _Stuck:
    def cancel(self):
        raise RuntimeError("cancel refused")

    def close(self):
        raise OSError("already gone")


def test_releasing_a_long_query_that_will_not_cancel_or_close_goes_on_and_says_so(monkeypatch, caplog):
    monkeypatch.setitem(ops_db._LONG_QUERY, "conn", _Stuck())
    with caplog.at_level(logging.DEBUG, logger="scenarios.ops_db"):
        got = ops_db.op_db_release_everything(None, None)
    assert got["cancelled_long_queries"] == 0
    assert "the long query was not cancelled (RuntimeError)" in caplog.text
    assert "the long query's connection did not close (OSError)" in caplog.text
