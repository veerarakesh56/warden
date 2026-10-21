"""B37: mutation testing (mutmut) runs in Linux CI over exactly the safety modules, pinned, non-blocking at first.

tests/test_supply_chain.py holds the workflow to the rules every workflow keeps (runner image, pinned and
checksum-verified uv, one cache per job, the draft skip, a locked install); these hold what is particular to it."""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tomllib

import pytest
import yaml
from scripts import mutation_ci

ROOT = pathlib.Path(__file__).resolve().parents[1]

SAFETY = {"gate.py", "verifier.py", "catalog.py", "approvals.py", "autonomy.py", "bounds.py", "audit.py",
          "redaction.py"}
WORKFLOW = ROOT / ".github" / "workflows" / "mutation.yml"


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_only_the_safety_modules_are_mutated():
    modules = mutation_ci.safety_modules()
    assert {pathlib.PurePosixPath(m).name for m in modules} == SAFETY
    assert all(m.startswith("src/warden/") for m in modules)
    missing = {pathlib.PurePosixPath(m).name for m in modules if not (ROOT / m).is_file()}
    assert not missing, missing  # a renamed or deleted module must not drop out silently
    assert _pyproject()["tool"]["mutmut"]["source_paths"] == ["src/"]


def test_mutmut_is_one_exact_version_installed_from_the_lock():
    group = _pyproject()["dependency-groups"]["mutation"]
    assert len(group) == 1
    assert group[0].startswith("mutmut==")
    install = [st["run"] for st in _workflow()["jobs"]["mutmut"]["steps"] if st.get("name") == "Install (locked)"]
    assert len(install) == 1
    assert "--locked" in install[0]
    assert "--group mutation" in install[0]


def test_the_job_reports_and_does_not_block_yet():
    job = _workflow()["jobs"]["mutmut"]
    assert job["continue-on-error"] is True
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["timeout-minutes"] <= 360
    score = [st for st in job["steps"] if st.get("name") == "Score"]
    assert score
    assert score[0]["if"] == "always()"
    assert "GITHUB_STEP_SUMMARY" in score[0]["run"]
    assert "--min-score" not in score[0]["run"]  # the gate comes after the first full runs


def test_a_pull_request_that_changes_a_safety_module_or_the_setup_runs_it():
    on = _workflow()[True]
    paths = set(on["pull_request"]["paths"])
    assert set(mutation_ci.safety_modules()) <= paths
    assert mutation_ci.SETUP_FILES <= paths
    assert {"schedule", "workflow_dispatch"} <= set(on)


def test_the_copy_mutmut_tests_in_deselects_only_repository_checks():
    """The suite mutmut runs is the unit suite; what it leaves out is named, and none of it tests a safety module."""
    selection = _pyproject()["tool"]["mutmut"]["pytest_add_cli_args_test_selection"]
    assert selection[:2] == ["tests/", "--ignore=tests/integration"]
    deselected = [a.removeprefix("--deselect=") for a in selection[2:]]
    assert all(a.startswith("--deselect=tests/") for a in selection[2:])
    stems = {d.split("::")[0].removeprefix("tests/test_").removesuffix(".py") for d in deselected}
    assert not any(m.removesuffix(".py") in s for m in SAFETY for s in stems), stems
    assert len(deselected) <= 6, deselected


def test_every_deselected_test_exists():
    """A renamed test would leave its --deselect pointing at nothing, and the renamed test would run in mutmut's copy,
    where a repository check cannot hold: each deselected id names a test function in its file."""
    selection = _pyproject()["tool"]["mutmut"]["pytest_add_cli_args_test_selection"]
    for arg in selection[2:]:
        path, name = arg.removeprefix("--deselect=").split("::")
        assert f"def {name}(" in (ROOT / path).read_text(encoding="utf-8"), arg


@pytest.mark.parametrize(("changed", "expected"), [
    (["src/warden/gate.py"], ["warden.gate*"]),
    (["src/warden/audit.py", "README.md", "src/warden/redaction.py"], ["warden.audit*", "warden.redaction*"]),
    (["src/warden/gate.py", "pyproject.toml"], []),          # the setup changed: every module
    ([".github/workflows/mutation.yml"], []),
    (["docs/README.md"], []),                                # nothing to narrow to: every module
])
def test_targets(changed, expected):
    assert mutation_ci.targets(changed, mutation_ci.safety_modules()) == expected


def test_targets_from_the_command_line():
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "mutation_ci.py"), "targets"],
                         input="src/warden/bounds.py\nsrc/warden/llm.py\n", capture_output=True, text=True, check=True)
    assert out.stdout.split() == ["warden.bounds*"]


@pytest.mark.parametrize(("stats", "expected"), [
    ({"killed": 261, "survived": 40, "total": 301}, 261 / 301),
    ({"killed": 9, "survived": 0, "timeout": 1, "total": 10}, 0.9),   # a hung mutant is not a killed one
    ({"killed": 0, "survived": 0, "no_tests": 5, "total": 5}, None),  # nothing tested is not a score of 100%
])
def test_score(stats, expected):
    got = mutation_ci.score(stats)
    assert got == pytest.approx(expected) if expected is not None else got is None


def test_the_summary_and_the_optional_minimum(tmp_path, capsys):
    stats = tmp_path / "s.json"
    stats.write_text('{"killed": 261, "survived": 40, "total": 4245}', encoding="utf-8")
    assert mutation_ci.main(["summary", str(stats)]) == 0
    assert "86.7%" in capsys.readouterr().out
    assert mutation_ci.main(["summary", str(stats), "--min-score", "0.9"]) == 1
    assert mutation_ci.main(["summary", str(stats), "--min-score", "0.8"]) == 0
