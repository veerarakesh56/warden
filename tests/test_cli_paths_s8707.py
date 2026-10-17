"""Paths from a command line stay where WARDEN's tools work (Sonar pythonsecurity:S8707, S8706, S8705, S2083 and
S8703, 2026-10-16). An agent can drive these command lines: a path it was steered to - ~/.ssh, /etc, `..` out of a run
folder - is refused before anything is read, written or run, and a signed approval goes to no host the command line
names."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys
import uuid

import pytest

from warden import cli, paths

ROOT = pathlib.Path(__file__).resolve().parents[1]
# Under the home directory, in none of the tools' folders: where a steered path would lead (~/.ssh, ~/.aws). A folder
# of its own with a name no one else has, so a regression that writes there harms nothing, and the clean-up below can
# only ever remove what this run wrote.
OUTSIDE_DIR = pathlib.Path.home() / f".warden-test-outside-{uuid.uuid4().hex}"
OUTSIDE = OUTSIDE_DIR / "never-written"


@pytest.fixture(autouse=True)
def _nothing_left_outside():
    yield
    written = OUTSIDE_DIR.exists()
    shutil.rmtree(OUTSIDE_DIR, ignore_errors=True)
    assert not written, f"a test wrote into {OUTSIDE_DIR}"


def _script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_harness_has_the_same_rule_without_importing_the_tool():
    """The harness runs WARDEN's own rule, loaded from its file: one copy of it, and no `warden` package imported."""
    code = ("import sys; from scenarios import paths; "
            "assert paths.RULE.samefile('src/warden/paths.py'), paths.RULE; "
            "assert not any(m == 'warden' or m.startswith('warden.') for m in sys.modules), sorted(sys.modules)")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    done = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr


def test_a_path_in_the_working_directory_or_the_temp_folder_is_used_resolved(tmp_path):
    assert paths.inside("pyproject.toml") == (ROOT / "pyproject.toml").resolve()
    assert paths.inside(tmp_path / "x.json") == (tmp_path / "x.json").resolve()


def test_a_path_elsewhere_or_climbing_out_is_refused(tmp_path):
    for bad in (OUTSIDE, tmp_path / ".." / ".." / ".." / ".." / ".." / ".." / ".." / ".." / "etc" / "passwd"):
        with pytest.raises(ValueError, match="outside the places"):
            paths.inside(bad)


def test_a_symlink_out_of_the_working_places_is_refused(tmp_path):
    link = tmp_path / "out"
    try:
        os.symlink(pathlib.Path.home(), link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot create symlinks")
    with pytest.raises(ValueError, match="outside the places"):
        paths.inside(link / ".ssh" / "id_ed25519")


def test_a_filesystem_root_is_never_a_place(tmp_path):
    root = pathlib.Path(tmp_path.anchor)
    with pytest.raises(ValueError):
        paths.inside(OUTSIDE, [root])


def test_warden_run_reads_no_alert_and_writes_no_report_outside(capsys):
    assert cli.main(["run", "--alert", str(OUTSIDE)]) == 2
    assert "error: --alert" in capsys.readouterr().err
    assert cli.main(["run", "--incident", "inc-001", "--json", str(OUTSIDE)]) == 2
    assert "error: --json" in capsys.readouterr().err
    assert not OUTSIDE.exists()


def test_warden_audit_reads_keys_from_the_key_folder_only_and_no_database_outside(tmp_path, capsys):
    # A file that exists, outside the key folder: not read as a key.
    assert cli.main(["audit", "verify", "--db", str(tmp_path / "a.db"), "--public-key", str(ROOT / "pyproject.toml")]) == 2
    assert "key files are kept only there" in capsys.readouterr().err
    assert cli.main(["audit", "verify", "--db", str(OUTSIDE), "--public-key", str(tmp_path / "k.pub")]) == 2
    assert "error: --db" in capsys.readouterr().err


def test_an_approver_key_outside_the_key_folder_is_not_read():
    with pytest.raises(SystemExit, match="outside"):
        cli._approver_key(ROOT / "pyproject.toml")
    with pytest.raises(SystemExit, match="never-written|cannot find|No such file"):
        cli._approver_key(OUTSIDE)  # its folder does not exist


def test_the_scorer_writes_nothing_outside_its_run(tmp_path):
    from scenarios import score

    with pytest.raises(SystemExit, match="--suffix"):
        score.main(["--run", str(tmp_path), "--suffix", "../../escaped"])
    with pytest.raises(SystemExit, match="refused"):
        score.main(["--run", str(OUTSIDE)])
    with pytest.raises(SystemExit, match="refused"):
        score.main(["--run", str(tmp_path), "--rubric", str(OUTSIDE)])


def test_the_runner_runs_into_no_folder_outside():
    from scenarios import runner

    for flag in ("--out", "--resume"):
        with pytest.raises(SystemExit, match="refused"):
            runner.main(["--wave", "1", "--dry-run", flag, str(OUTSIDE)])


def test_a_record_naming_a_scenario_id_that_leaves_ground_truth_is_refused(tmp_path):
    from scenarios import fullstack_cli

    assert fullstack_cli._gt_path(tmp_path, "fs-01").parent == (tmp_path / "ground-truth").resolve()
    for sid in ("../../outside", "a/../../b"):
        with pytest.raises(fullstack_cli.StepError, match="not a scenario id"):
            fullstack_cli._gt_path(tmp_path, sid)


def test_the_helios_gate_reads_and_hands_helios_nothing_outside(tmp_path, monkeypatch):
    gate = _script("helios_gate")
    monkeypatch.setattr(gate, "simulate", lambda *a: pytest.fail("Helios ran"))
    for argv in (["--plan", str(OUTSIDE), "--out-dir", str(tmp_path)],
                 ["--plan", str(tmp_path / "p.json"), "--baseline", str(OUTSIDE), "--out-dir", str(tmp_path)],
                 ["--plan", str(tmp_path / "p.json"), "--out-dir", str(OUTSIDE)]):
        assert gate.main(["--helios", "helios", *argv]) == 1


def test_the_replay_and_the_proof_bundle_write_nothing_outside(tmp_path, monkeypatch):
    replay = _script("replay_gate")
    with pytest.raises(SystemExit, match="refused"):
        replay.main(["--reports", str(tmp_path), "--json", str(OUTSIDE)])
    bundle = _script("aws_proof_bundle")
    monkeypatch.setattr(sys, "argv", ["aws_proof_bundle.py", "--dir", str(OUTSIDE)])
    with pytest.raises(SystemExit, match="refused"):
        bundle.main()
    assert not OUTSIDE.exists()


def test_the_bench_approver_sends_to_no_domain_a_command_line_names(monkeypatch):
    bench = _script("bench_approve")
    sent = []
    monkeypatch.setattr(bench, "load_key", lambda: object())
    monkeypatch.setattr(bench, "_post", lambda domain, step, body: sent.append(domain) or (500, {}))
    with pytest.raises(SystemExit) as exc:
        bench.main(["--record", "latest", "--domain", "attacker.example"])
    assert exc.value.code == 2
    assert not sent
