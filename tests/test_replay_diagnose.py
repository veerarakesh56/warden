"""The diagnose replay: recorded evidence through today's pipeline, scored by the real scorer."""

from __future__ import annotations

import json
import pathlib
import sys

import pytest
from scenarios.score import score_run_dir

from warden.llm import LLMClient

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import replay_diagnose as rd  # after the sys.path line above

RUN = ROOT / "docs" / "bench" / "wave1-2026-09-11T155744Z"
pytestmark = pytest.mark.skipif(not RUN.exists(), reason="the published run is not in this checkout")


def test_a_mock_replay_scores_end_to_end(tmp_path):
    out = tmp_path / "replay"
    only = {"ecs-01-healthy-control", "ecs-03-oom-new-revision"}
    rd.replay(RUN, out, per_scenario=1, only=only, llm_factory=lambda: LLMClient(mock=True), log=lambda _: None)
    assert json.loads((out / "manifest.json").read_text())["replay"]["of"] == RUN.name
    scored = score_run_dir(out, out / "grading" / "scoring.yaml")
    assert {r["scenario_id"] for r in scored["rows"]} == only
    assert all(r["index"] == 1 and r["verdict"] for r in scored["rows"]), "one scored run per scenario"
    assert not scored["rubric_drift"]
    report = json.loads((out / "reports" / "ecs-03-oom-new-revision.1.json").read_text())
    assert report["cost"]["calls"] == 1 and report["audit"][-1]["node"] == "verify"


def test_a_failed_diagnosis_is_an_error_row_not_a_gap(tmp_path):
    def broken():
        raise RuntimeError("provider down")
    out = tmp_path / "replay"
    rd.replay(RUN, out, per_scenario=1, only={"ecs-01-healthy-control"}, llm_factory=broken, log=lambda _: None)
    [row] = score_run_dir(out, out / "grading" / "scoring.yaml")["rows"]
    assert row["diagnosis"] == "ERROR" and "provider down" in row["note"]


def test_refuses_to_write_inside_docs():
    assert rd.main(["--run", str(RUN), "--out", str(ROOT / "docs" / "bench" / "x")]) == 2
