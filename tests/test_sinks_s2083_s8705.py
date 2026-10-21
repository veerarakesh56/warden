"""The checks sit beside the writes and the command they guard (Sonar pythonsecurity:S2083/S8707 on runner._write_json,
S8705 on helios_gate.simulate; main's analysis, 2026-10-20). A path that enters from a command line is checked in
main(); these hold the ones built later, from a file the run reads back (a scenario id in manifest.json, a report path
in a record), and the command line handed to Helios."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import shutil
import stat
import uuid

import pytest
from scenarios import runner

ROOT = pathlib.Path(__file__).resolve().parents[1]
# Under the home directory, in none of the tools' folders, with a name no one else has: a regression writes only here.
OUTSIDE_DIR = pathlib.Path.home() / f".warden-test-outside-{uuid.uuid4().hex}"


@pytest.fixture(autouse=True)
def _nothing_left_outside():
    yield
    written = OUTSIDE_DIR.exists()
    shutil.rmtree(OUTSIDE_DIR, ignore_errors=True)
    assert not written, f"a test wrote into {OUTSIDE_DIR}"


def _gate():
    spec = importlib.util.spec_from_file_location("helios_gate_s8705", ROOT / "scripts" / "helios_gate.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- runner


def test_a_json_write_lands_only_where_the_tools_work(tmp_path):
    runner._write_json(tmp_path / "a" / "b.json", {"x": 1})
    assert json.loads((tmp_path / "a" / "b.json").read_text(encoding="utf-8")) == {"x": 1}
    target = OUTSIDE_DIR / "never.json"
    with pytest.raises(ValueError, match="lies outside"):
        runner._write_json(target, {"x": 1})


@pytest.mark.parametrize("name", ["../../escaped.json", "/etc/escaped.json", "../ground-truth2/x.json",
                                  "../ground-truth/x.json", "sub/x.json", "..", "."])
def test_a_scenario_file_name_read_back_from_a_file_stays_in_its_folder(tmp_path, name):
    folder = tmp_path / "ground-truth"
    with pytest.raises(SystemExit, match="not a scenario file name"):
        runner._in_folder(folder, name)


def test_a_plain_scenario_id_names_its_record(tmp_path):
    folder = tmp_path / "ground-truth"
    assert runner._in_folder(folder, "fs-27.json") == (folder / "fs-27.json").resolve()


def test_supersede_moves_no_report_a_record_points_outside_the_run(tmp_path):
    """The record's `report` is read back from disk: one leading out of the run is refused before anything moves."""
    gt = tmp_path / "ground-truth"
    gt.mkdir()
    victim = tmp_path.parent / f"victim-{uuid.uuid4().hex}.json"
    victim.write_text("{}", encoding="utf-8")
    try:
        record = {"scenario_id": "fs-1", "runs": [{"index": 1, "report": f"../{victim.name}"}]}
        (gt / "fs-1.json").write_text(json.dumps(record), encoding="utf-8")
        with pytest.raises(SystemExit, match="refused - it does not lie inside"):
            runner.supersede(tmp_path, "fs-1")
        assert victim.exists()
        assert (gt / "fs-1.json").exists()
    finally:
        victim.unlink(missing_ok=True)


def test_supersede_moves_only_a_report_never_the_manifest(tmp_path):
    """A record's `report` must lie under reports/: `manifest.json` (inside the run, but no report) stays put."""
    gt = tmp_path / "ground-truth"
    gt.mkdir()
    (tmp_path / "manifest.json").write_text("{}", encoding="utf-8")
    record = {"scenario_id": "fs-1", "runs": [{"index": 1, "report": "manifest.json"}]}
    (gt / "fs-1.json").write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(SystemExit, match="refused - it does not lie inside"):
        runner.supersede(tmp_path, "fs-1")
    assert (tmp_path / "manifest.json").exists()


def test_a_ground_truth_folder_that_links_out_of_the_run_is_refused_before_any_read(tmp_path):
    run, elsewhere = tmp_path / "run", tmp_path / "elsewhere"
    run.mkdir()
    elsewhere.mkdir()
    (elsewhere / "fs-1.json").write_text(json.dumps({"runs": []}), encoding="utf-8")
    (run / "ground-truth").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(SystemExit, match="refused - it does not lie inside"):
        runner.supersede(run, "fs-1")
    assert not (elsewhere / "superseded").exists()


# --------------------------------------------------------------------------- helios_gate


def _helios(folder: pathlib.Path, name: str = "helios", body: str = "") -> pathlib.Path:
    exe = folder / name
    exe.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    return exe


def _files(folder: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    doc, scenario = folder / "-plan.json", folder / "-lose.json"  # names that read as options when passed bare
    doc.write_text("{}", encoding="utf-8")
    scenario.write_text("{}", encoding="utf-8")
    return doc, scenario


@pytest.mark.skipif(os.name == "nt", reason="a POSIX shell script stands in for the Helios binary")
def test_helios_gets_its_binary_and_absolute_file_paths_only(tmp_path, monkeypatch):
    gate = _gate()
    exe = _helios(tmp_path)
    doc, scenario = _files(tmp_path)
    monkeypatch.chdir(tmp_path)
    argv = gate._helios_argv([str(exe)], pathlib.Path(doc.name), pathlib.Path(scenario.name))
    assert argv == [str(exe.resolve()), "simulate", str(doc.resolve()), "--scenario", str(scenario.resolve()), "--json"]
    assert all(pathlib.Path(a).is_absolute() for a in (argv[0], argv[2], argv[4]))


@pytest.mark.skipif(os.name == "nt", reason="a POSIX shell script stands in for the Helios binary")
def test_a_real_run_reads_the_failures_helios_prints(tmp_path):
    gate = _gate()
    exe = _helios(tmp_path, body="echo '{\"failures\": [{\"id\": \"aws_lb.app\"}]}'\nexit 1\n")
    doc, scenario = _files(tmp_path)
    assert gate.simulate([str(exe)], doc, scenario) == {"aws_lb.app"}


@pytest.mark.skipif(os.name == "nt", reason="a POSIX shell script stands in for the Helios binary")
def test_anything_but_the_helios_binary_is_refused_before_it_runs(tmp_path, monkeypatch):
    gate = _gate()
    doc, scenario = _files(tmp_path)
    plain = tmp_path / "plain" / "helios"
    plain.parent.mkdir()
    plain.write_text("", encoding="utf-8")  # not executable
    OUTSIDE_DIR.mkdir()
    try:
        outside = _helios(OUTSIDE_DIR)
        cases = {"another program": [str(_helios(tmp_path, "sh"))], "not executable": [str(plain)],
                 "outside the working places": [str(outside)], "with arguments": [str(_helios(tmp_path)), "-x"]}
        monkeypatch.setattr(gate.subprocess, "run", lambda *a, **k: pytest.fail("a program ran"))
        for why, helios in cases.items():
            verdict = gate.simulate(helios, doc, scenario)
            assert isinstance(verdict, tuple), why
            assert verdict[0] == "error", why
        assert gate.simulate([str(_helios(tmp_path))], tmp_path / "missing.json", scenario)[0] == "error"
    finally:
        shutil.rmtree(OUTSIDE_DIR, ignore_errors=True)
