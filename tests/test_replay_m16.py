"""Audit A-B-M16: a replay runs the production pipeline, tripwire included, and keeps the recorded run's ERROR rows.
The published run it replays is tracked in the repository, so nothing here is skipped."""

from __future__ import annotations

import json
import pathlib
import sys

from scenarios.score import score_run_dir

from warden.llm import LLMClient

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import replay_diagnose as rd  # after the sys.path line above

RUN = ROOT / "docs" / "bench" / "wave1-2026-09-11T155744Z"


def test_the_tripwire_runs_in_a_replay_as_in_production(tmp_path):
    """Audit A-B-M16: a replay skipped the tripwire, so it could never show P16."""
    out = tmp_path / "replay"
    rd.replay(RUN, out, per_scenario=1, only={"ecs-03-oom-new-revision"}, llm_factory=lambda: LLMClient(mock=True),
              log=lambda _: None)
    report = json.loads((out / "reports" / "ecs-03-oom-new-revision.1.json").read_text())
    assert [s["node"] for s in report["audit"]][:2] == ["redact", "tripwire"], report["audit"]


def test_a_run_that_failed_in_the_recorded_wave_stays_an_error_row(tmp_path):
    """Audit A-B-M16: runs with no report were dropped, and the replay's denominators were not the run's."""
    src = tmp_path / "src"
    import shutil
    shutil.copytree(RUN, src)
    gt_path = src / "ground-truth" / "ecs-01-healthy-control.json"
    gt = json.loads(gt_path.read_text(encoding="utf-8"))
    gt["runs"][0] = {**gt["runs"][0], "report_written": False, "exit_code": 1, "stderr_tail": "worker died"}
    gt_path.write_text(json.dumps(gt), encoding="utf-8")
    out = tmp_path / "replay"
    rd.replay(src, out, per_scenario=1, only={"ecs-01-healthy-control"}, llm_factory=lambda: LLMClient(mock=True),
              log=lambda _: None)
    [row] = score_run_dir(out, out / "grading" / "scoring.yaml")["rows"]
    assert row["diagnosis"] == "ERROR", row

