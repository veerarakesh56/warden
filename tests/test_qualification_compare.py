"""scripts/qualification_compare.py: the old model beside the candidate on the same replay set, per incident and in
total, from stored results only - no model is called. The stored results here are the committed live runs
(tests/fixtures/bench), which have the layout a qualification run writes, and hand-made incident tables."""

from __future__ import annotations

import json
import pathlib
import shutil
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualification_compare as cmp  # after the sys.path line above

BENCH = ROOT / "tests" / "fixtures" / "bench"
RIGHT, WRONG = "right", "wrong"


def _incident(outcome: str, escalated: bool = False, usd: float | None = 0.01) -> dict:
    return {"outcome": outcome, "escalated": escalated, "usd": usd, "latency_s": None}


def test_the_stored_runs_are_read_per_incident_as_the_scorer_grades_them():
    found = cmp.incidents(BENCH)
    assert len(found) == 90, "14 + 10 + 6 scenarios, three runs each (docs/BENCHMARKS.md)"
    rights = sum(1 for i in found.values() if i["outcome"] == RIGHT)
    assert rights == 20 + 17 + 12, "the published CORRECT counts of waves 1-3"
    assert sum(1 for i in found.values() if i["outcome"] == "not graded") == 3 + 1 + 0
    assert all(i["usd"] is not None for i in found.values()), "each report records its cost"


def test_each_incident_says_what_moved_between_old_and_new():
    old = {
        "label": "old: a",
        "totals": {"correct": 2},
        "incidents": {
            "x.1": _incident(RIGHT),
            "y.1": _incident(WRONG),
            "z.1": _incident(WRONG, escalated=True),
        },
    }
    new = {
        "label": "new: b",
        "totals": {"correct": 2},
        "incidents": {
            "x.1": _incident(WRONG),
            "y.1": _incident(RIGHT),
            "z.1": _incident(WRONG, escalated=True),
        },
    }
    text = cmp.render(old, new, "below the bar: NOT qualified")
    rows = {
        ln.split("|")[1].strip(): ln
        for ln in text.splitlines()
        if ln.startswith("| ") and "." in ln[:8]
    }
    assert rows["x.1"].rstrip().endswith("| broke |")
    assert rows["y.1"].rstrip().endswith("| fixed |")
    assert rows["z.1"].rstrip().endswith("|  |"), "unchanged"
    assert "wrong, escalated" in rows["z.1"]
    assert text.rstrip().endswith(
        "Verdict for new: b against the bar: below the bar: NOT qualified"
    )


def test_totals_cost_and_latency_are_shown_and_missing_ones_said_so():
    old = cmp.side(
        "old: a", {"correct": 17, "wrong_and_allowed": 0, "spent_usd": 0.42, "prompt": "ab" * 32}
    )
    new = {"label": "new: b", "totals": {"correct": 19, "wrong_and_allowed": 0}, "incidents": None}
    text = cmp.render(old, new, "verdict")
    assert "| correct | 17 | 19 |" in text
    assert "| spent usd | $0.42 | not recorded |" in text
    assert "| latency | not recorded | not recorded |" in text
    assert "totals only" in text


def test_the_old_side_is_the_recorded_row_with_no_model_call():
    doc = yaml.safe_load(
        (ROOT / "src" / "warden" / "data" / "providers.yaml").read_text(encoding="utf-8")
    )
    old = cmp.old_side(doc, "anthropic", None)
    row = cmp.current_row(doc, "anthropic")
    assert old is not None
    assert old["totals"] is row
    assert old["incidents"] is None
    pinned = doc["prompt"]["sha"]
    assert ("pinned prompt" in old["label"]) is (row.get("prompt") == pinned)


def test_an_earlier_run_directory_is_the_old_side_per_incident(tmp_path):
    run = tmp_path / "old-run"
    for name in cmp.runs():
        shutil.copytree(BENCH / name, run / name)
    (run / "qualification.json").write_text(
        json.dumps({"model": "m-old", "correct": 49}), encoding="utf-8"
    )
    old = cmp.old_side({}, None, run / "qualification.json")
    assert old["label"] == "old: m-old"
    assert len(old["incidents"]) == 90


def test_an_old_run_without_its_result_is_an_error_not_an_empty_column(tmp_path):
    missing = tmp_path / "empty-run"
    missing.mkdir()
    with pytest.raises(ValueError, match="qualification.json"):
        cmp.old_side({}, None, missing)
