"""scripts/preflight_fullstack_ops.py beyond the happy path (characterisation before the cognitive-complexity split
of main): each refusal, a dirty stack before or after, an inject that raises, a revert that raises, a fault not yet
visible - each with the exact line it prints and its exit code."""

from __future__ import annotations

import importlib.util

import pytest
from scenarios import fullstack_cli as cli
from scenarios import ops_fullstack as fs
from scenarios import runner

_spec = importlib.util.spec_from_file_location("preflight_fs", runner.ROOT / "scripts" / "preflight_fullstack_ops.py")
pf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pf)


def _fault(events: list, fid: str, *, inject_raises=None, revert_raises=None) -> fs.Fault:
    def inject(c, t):
        events.append(f"inject {fid}")
        if inject_raises:
            raise inject_raises

    def revert(c, t):
        events.append(f"revert {fid}")
        if revert_raises:
            raise revert_raises
        return {"reverted": fid}

    return fs.Fault(inject, revert, lambda c, t: (True, ""), f"area-{fid}")


def _env(faults: dict, baseline=list) -> cli.Env:
    env = cli.dry_env()
    env.faults.update(faults)
    env.baseline = baseline
    env.dry_run = False
    return env


def test_refusals_before_anything_is_touched():
    with pytest.raises(SystemExit, match="--only 'fs-99' matched no fault"):
        pf.main(["--only", "fs-99"])
    with pytest.raises(SystemExit, match="--only 'fs-00' matched no fault"):
        pf.main(["--only", "fs-00"])


def test_a_dirty_stack_stops_before_the_first_inject(tmp_path, capsys):
    events: list = []
    env = _env({"fs-07": _fault(events, "fs-07")}, baseline=lambda: ["shop is down"])
    assert pf.main(["--apply", "--only", "fs-07", "--run", str(tmp_path)], env=env) == 1
    assert capsys.readouterr().out == "NOT AT BASELINE before starting: ['shop is down']\n"
    assert events == []
    assert env.target.redis_fill_mb == 50


def test_each_fault_is_reported_and_one_failure_fails_the_run(tmp_path, capsys, monkeypatch):
    events: list = []
    shown = {"area-fs-12": [], "area-fs-19": ["queue depth 5"]}
    monkeypatch.setattr(fs, "check_baseline", lambda c, t, areas: shown[areas[0]])
    env = _env({"fs-07": _fault(events, "fs-07", inject_raises=RuntimeError("throttled")),
                "fs-12": _fault(events, "fs-12"), "fs-19": _fault(events, "fs-19")})
    assert pf.main(["--apply", "--only", "fs-07,fs-12,fs-19", "--run", str(tmp_path), "--settle-minutes", "0"],
                   env=env) == 1
    assert events == ["inject fs-07", "revert fs-07", "inject fs-12", "revert fs-12", "inject fs-19", "revert fs-19"]
    assert capsys.readouterr().out == (
        "FAIL fs-07: inject raised RuntimeError: throttled; after revert baseline clean\n"
        "OK   fs-12: landed: NOT VISIBLE YET (warning); after revert baseline clean\n"
        "OK   fs-19: landed: queue depth 5; after revert baseline clean\n"
        "\n1 FAILED - do not run the wave\n")


def test_a_revert_that_raises_stops_everything(tmp_path, capsys):
    events: list = []
    env = _env({"fs-07": _fault(events, "fs-07", inject_raises=ValueError("bad"), revert_raises=KeyError("gone"))})
    assert pf.main(["--apply", "--only", "fs-07", "--run", str(tmp_path), "--settle-minutes", "0"], env=env) == 1
    assert capsys.readouterr().out == ("FAIL fs-07: inject raised ValueError: bad; then REVERT raised KeyError: "
                                       "'gone' - stopping; the stack is not at baseline (saved state: "
                                       f"{tmp_path / 'saved' / 'fs-07.json'})\n")
    env = _env({"fs-12": _fault(events, "fs-12", revert_raises=KeyError("gone")), "fs-19": _fault(events, "fs-19")})
    events.clear()
    assert pf.main(["--apply", "--only", "fs-12,fs-19", "--run", str(tmp_path), "--settle-minutes", "0"],
                   env=env) == 1
    assert events == ["inject fs-12", "revert fs-12"]
    assert capsys.readouterr().out == ("FAIL fs-12: REVERT raised KeyError: 'gone' - stopping; the stack is not at "
                                       f"baseline (saved state: {tmp_path / 'saved' / 'fs-12.json'})\n")


def test_a_stack_still_dirty_after_a_revert_stops_before_the_next_fault(tmp_path, capsys, monkeypatch):
    events: list = []
    monkeypatch.setattr(fs, "check_baseline", lambda c, t, areas: ["seen"])
    env = _env({"fs-12": _fault(events, "fs-12"), "fs-19": _fault(events, "fs-19")},
               baseline=lambda: ["cache flushing"] if "revert fs-12" in events else [])
    assert pf.main(["--apply", "--only", "fs-12,fs-19", "--run", str(tmp_path), "--settle-minutes", "0"],
                   env=env) == 1
    assert events == ["inject fs-12", "revert fs-12"]
    assert capsys.readouterr().out == ("FAIL fs-12: landed: seen; after revert ['cache flushing']\n"
                                       "stopping: the next fault would start from a dirty stack\n")


def test_revert_mode_reverts_each_named_fault_then_reports_the_baseline(tmp_path, capsys):
    events: list = []
    env = _env({"fs-12": _fault(events, "fs-12"), "fs-19": _fault(events, "fs-19")}, baseline=lambda: ["still red"])
    assert pf.main(["--revert", "--only", "fs-12,fs-19", "--run", str(tmp_path), "--settle-minutes", "0"],
                   env=env) == 1
    assert events == ["revert fs-12", "revert fs-19"]
    assert capsys.readouterr().out == ("revert fs-12: {'reverted': 'fs-12'}\nrevert fs-19: {'reverted': 'fs-19'}\n"
                                       "NOT AT BASELINE: ['still red']\n")


def test_revert_without_only_is_refused_before_anything_is_touched():
    with pytest.raises(SystemExit, match="--revert needs --only: say which fault to put back"):
        pf.main(["--revert"])
