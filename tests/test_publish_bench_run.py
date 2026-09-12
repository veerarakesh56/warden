"""Publishing a benchmark run must ship the rubric that run was graded under.

⛔ Why this file exists. `scenarios/scoring.yaml` is one file for every wave, so the day a later
wave adds a fault class, its hash stops matching every already-published run and re-scoring them
raises "THE RUBRIC CHANGED AFTER THIS RUN" - the loudest warning this project has, fired for a
change that never touched the entries those runs were graded by. A bundle that carries its own
rubric can always be re-scored exactly, and that property is worth a test rather than a habit.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import publish_bench_run as pub  # after the sys.path line above


def _head_rubric() -> tuple[str, bytes]:
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                            capture_output=True, text=True, check=True).stdout.strip()
    blob = subprocess.run(["git", "show", f"{commit}:scenarios/scoring.yaml"], cwd=ROOT,
                          capture_output=True, check=True).stdout
    return commit, blob


def _run_dir(tmp_path: pathlib.Path, manifest: dict) -> pathlib.Path:
    run = tmp_path / "wave9-fake"
    run.mkdir()
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return run


def test_the_bundle_carries_the_rubric_the_run_was_graded_under(tmp_path):
    commit, blob = _head_rubric()
    digest = hashlib.sha256(blob.replace(b"\r\n", b"\n")).hexdigest()
    run = _run_dir(tmp_path, {"git_commit": commit, "scoring_sha256": digest})
    staging = tmp_path / "staging"

    frozen = pub._freeze_grading_inputs(run, staging, account="")

    written = (staging / "grading" / "scoring.yaml").read_bytes()
    assert hashlib.sha256(written.replace(b"\r\n", b"\n")).hexdigest() == digest
    assert any("verified against the manifest" in line for line in frozen)


def test_a_rubric_that_is_not_the_one_the_run_recorded_is_refused(tmp_path):
    """⛔ The check that makes the frozen copy worth anything. Shipping whatever rubric happens to
    be around, under the name of the one the run used, is the substitution this guards against."""
    commit, _ = _head_rubric()
    run = _run_dir(tmp_path, {"git_commit": commit, "scoring_sha256": "0" * 64})

    with pytest.raises(SystemExit, match="not the one it was"):
        pub._freeze_grading_inputs(run, tmp_path / "staging", account="")


def test_publishing_without_a_recorded_commit_is_refused(tmp_path):
    run = _run_dir(tmp_path, {"scoring_sha256": "0" * 64})
    with pytest.raises(SystemExit, match="no git_commit"):
        pub._freeze_grading_inputs(run, tmp_path / "staging", account="")


def test_the_published_bundles_can_still_be_rescored_against_their_own_rubric():
    """The property, asserted against what is actually committed: every bundle in docs/bench has a
    frozen rubric whose hash matches its manifest. Without this a reader gets the drift banner and
    numbers they cannot reproduce."""
    bench = ROOT / "docs" / "bench"
    bundles = [p for p in bench.glob("wave*") if (p / "manifest.json").exists()]
    assert bundles, "no published bundles found - has docs/bench moved?"
    for bundle in bundles:
        manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        frozen = bundle / "grading" / "scoring.yaml"
        assert frozen.exists(), f"{bundle.name} has no frozen rubric"
        digest = hashlib.sha256(frozen.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        assert digest == manifest["scoring_sha256"], (
            f"{bundle.name}: the frozen rubric is not the one the run recorded"
        )
