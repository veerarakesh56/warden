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


# What mutmut 3.8.0 copies by itself (configuration.py: tests/, pyproject.toml and the lock files) and the source path.
MUTMUT_COPIES = {"src", "tests", "pyproject.toml", "uv.lock"}


def test_every_top_level_file_reaches_mutmuts_copy():
    """CI, PR 179: #170 added .sonarcloud.properties, which a test reads; it was not in also_copy, so mutmut's clean
    run failed and no mutant was tested. Every top-level path git tracks is copied - by also_copy or by mutmut.
    (In mutmut's own copy git lists nothing here, and the check has nothing to hold.)"""
    listed = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=False).stdout
    top = {line.split("/", 1)[0] for line in listed.splitlines() if line}
    copied = {a.rstrip("/") for a in _pyproject()["tool"]["mutmut"]["also_copy"]} | MUTMUT_COPIES
    assert top - copied == set(), top - copied


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


def test_one_matrix_job_per_safety_module():
    """PR 179: all modules in one job (~5,200 mutants) ran past the job's timeout; one job per module, each
    its own cache, and the matrix is exactly pyproject's list."""
    job = _workflow()["jobs"]["mutmut"]
    stems = [pathlib.PurePosixPath(m).stem for m in mutation_ci.safety_modules()]
    assert job["strategy"]["matrix"]["module"] == stems
    assert job["strategy"]["fail-fast"] is False
    uv = next(st for st in job["steps"] if str(st.get("uses", "")).startswith("astral-sh/setup-uv@"))
    assert "${{ matrix.module }}" in uv["with"]["cache-suffix"]
    mutate = next(st for st in job["steps"] if str(st.get("name", "")).startswith("Mutate"))
    assert 'mutation_ci.py narrow "$MODULE"' in mutate["run"]
    assert mutate["run"].rstrip().endswith("mutmut run")  # no name pattern: see test_narrowed
    assert "mutation_ci.py shard" in mutate["run"]


@pytest.mark.parametrize(("module", "changed", "runs"), [
    ("gate", [], True),                                         # schedule / by hand: every shard
    ("gate", ["src/warden/gate.py"], True),
    ("bounds", ["src/warden/gate.py"], False),                  # a pull request mutates only what it changed
    ("bounds", ["src/warden/gate.py", "uv.lock"], True),        # the setup changed: every shard
    ("bounds", ["README.md"], True),                            # no safety module changed: every shard
])
def test_shard_runs(module, changed, runs):
    assert mutation_ci.shard_runs(module, changed, mutation_ci.safety_modules()) is runs


def test_narrowed_leaves_one_module_and_nothing_else_changed():
    """PR 179: `mutmut run <pattern>` ran the clean tests by node id and broke on ids with newlines; each job
    instead narrows its own checkout's only_mutate to its module and runs plain `mutmut run`."""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    out = mutation_ci.narrowed(text, "bounds")
    assert mutation_ci.safety_modules_from(out) == ["src/warden/bounds.py"]
    before, after = tomllib.loads(text), tomllib.loads(out)
    after["tool"]["mutmut"]["only_mutate"] = before["tool"]["mutmut"]["only_mutate"]
    assert after == before
    with pytest.raises(ValueError, match="not a safety module"):
        mutation_ci.narrowed(text, "llm")


def test_warm_temporal_retries_with_a_growing_wait_then_gives_up():
    """PR 179: parallel jobs fetching Temporal's test server were answered 429; the fetch is retried."""
    waits, calls = [], []

    def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise RuntimeError("429 Too Many Requests")

    assert mutation_ci.warm_temporal(flaky, attempts=5, wait_s=10, sleep=waits.append) == 3
    assert waits == [10, 20]

    def down():
        raise RuntimeError("429 Too Many Requests")

    with pytest.raises(RuntimeError, match="after 2 attempts"):
        mutation_ci.warm_temporal(down, attempts=2, wait_s=1, sleep=waits.append)


def test_each_job_fetches_temporals_test_server_before_mutmut_runs():
    job = _workflow()["jobs"]["mutmut"]
    mutate = next(st for st in job["steps"] if str(st.get("name", "")).startswith("Mutate"))["run"]
    assert mutate.index("mutation_ci.py warm-temporal") < mutate.index("mutmut run")
    assert job["strategy"]["max-parallel"] <= 4


def test_shard_from_the_command_line():
    run = [sys.executable, str(ROOT / "scripts" / "mutation_ci.py"), "shard"]
    skip = subprocess.run([*run, "bounds"], input="src/warden/gate.py\n", capture_output=True, text=True, check=True)
    assert skip.stdout.strip() == "skip"
    every = subprocess.run([*run, "bounds"], input="\n", capture_output=True, text=True, check=True)
    assert every.stdout.strip() == "run"
    unknown = subprocess.run([*run, "llm"], input="", capture_output=True, text=True, check=False)
    assert unknown.returncode == 2


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


def test_no_mutation_data_is_said_unavailable_never_scored(tmp_path, capsys):
    """Review, PR 179: when mutmut stops before writing its stats, the job summary says so instead of the step
    failing with no report; under --min-score a missing result is a fail, never a pass."""
    missing = tmp_path / "mutmut-cicd-stats.json"
    assert mutation_ci.main(["summary", str(missing)]) == 0
    out = capsys.readouterr().out
    assert "Mutation score: **unavailable**" in out
    assert "%" not in out
    assert mutation_ci.main(["summary", str(missing), "--min-score", "0.8"]) == 1


def test_the_score_step_survives_a_failed_export():
    score = next(st["run"] for st in _workflow()["jobs"]["mutmut"]["steps"] if st.get("name") == "Score")
    assert "mutmut export-cicd-stats ||" in score
