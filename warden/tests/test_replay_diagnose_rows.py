"""warden/scripts/replay_diagnose.py: one recorded run is one row. A log that fails after the report was written makes that
run's row an ERROR row - never a success row and an ERROR row both, which counted the run twice (audit A-B-M16:
the denominators must be the recorded run's)."""

from __future__ import annotations

import json
import pathlib
import sys

from warden.llm import LLMClient

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "warden" / "scripts"))
import replay_diagnose as rd  # after the sys.path line above

RUN = ROOT / "warden" / "tests" / "fixtures" / "bench" / "wave1-2026-09-11T155744Z"
SCENARIO = "ecs-01-healthy-control"


def test_a_log_that_raises_after_the_write_leaves_one_error_row(tmp_path):
    said: list[str] = []

    def log(line):
        said.append(line)
        if len(said) == 1:
            raise OSError("console gone")

    out = tmp_path / "replay"
    rd.replay(RUN, out, per_scenario=1, only={SCENARIO}, llm_factory=lambda: LLMClient(mock=True), log=log)
    runs = json.loads((out / "ground-truth" / f"{SCENARIO}.json").read_text(encoding="utf-8"))["runs"]
    assert [(r["exit_code"], r["report_written"], r["stderr_tail"]) for r in runs] == [(1, False, "console gone")]
    assert (out / runs[0]["report"]).is_file()
    assert said[1] == f"{SCENARIO}.{runs[0]['index']}: ERROR console gone"
