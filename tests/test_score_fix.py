"""The Wave 4 additions to the scorer: `log_contains`, and the Fix score - and proof that neither
moves a single number of a published wave.

⛔ The rubric is one file for every wave and its hash is in every manifest. Wave 4 only APPENDS
fault classes, so each published bundle must still grade exactly as its frozen
`grading/scoring.yaml` grades it, and must render no Fix section at all.
"""

from __future__ import annotations

import json
import pathlib
import shutil

import pytest
import yaml
from scenarios import score

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUNDLES = sorted(p for p in (ROOT / "docs" / "bench").glob("wave*") if (p / "manifest.json").exists())


# --------------------------------------------------------------------------- log_contains


@pytest.mark.parametrize("assertion,logs,passes", [
    ({"kind": "log_contains", "value": "State=Disabled"}, ["ESM x <- q State=Disabled BatchSize=5"], True),
    ({"kind": "log_contains", "value": "State=Disabled"}, ["ESM x <- q State=Enabled"], False),
    ({"kind": "log_contains", "any_of": ["ImagePullBackOff", "ErrImagePull"]}, ["EVENT ErrImagePull"], True),
    ({"kind": "log_contains", "any_of": ["ImagePullBackOff", "ErrImagePull"]}, [], False),
])
def test_log_contains(assertion, logs, passes):
    ok, failures = score.check_evidence([assertion], {"logs": logs})
    assert ok is passes
    assert bool(failures) is not passes


# --------------------------------------------------------------------------- the fix row


def _run_dir(tmp_path: pathlib.Path, run_extra: dict, fault="fs-27-eventbridge-rule-disabled",
             fault_class="eventbridge_rule_disabled") -> pathlib.Path:
    report = {"alert": {"started_at": "2026-09-26T10:00:00+00:00"},
              "context": {"logs": [], "metrics": {"rule_enabled": 0.0}},
              "proposal": {"action": "escalate_to_human"}, "verdict": {"status": "escalated"},
              "root_cause": {"confidence": 0.7}}
    (tmp_path / "reports").mkdir(parents=True)
    (tmp_path / "reports" / f"{fault}.1.json").write_text(json.dumps(report))
    gt = {"scenario_id": fault, "fault_class": fault_class, "status": "ok",
          "started_at": "2026-09-26T09:50:00+00:00", "ended_at": "2026-09-26T10:05:00+00:00",
          "runs": [{"index": 1, "exit_code": 0, "report_written": True,
                    "report": f"reports/{fault}.1.json", "at": "2026-09-26T10:00:01+00:00", **run_extra}]}
    (tmp_path / "ground-truth").mkdir()
    (tmp_path / "ground-truth" / f"{fault}.json").write_text(json.dumps(gt))
    (tmp_path / "manifest.json").write_text(json.dumps({"wave": 4, "repeat": 1}))
    return tmp_path


@pytest.mark.parametrize("outcome", score.FIX_OUTCOMES)
def test_every_fix_outcome_is_counted(tmp_path, outcome):
    run = _run_dir(tmp_path, {"fix": {"outcome": outcome}, "alarm": {"never_fired": False}})
    scored = score.score_run_dir(run)
    row = scored["rows"][0]
    assert row["fix"] == outcome and row["diagnosis"] == score.CORRECT
    summary = score.summarise(scored)
    assert summary["fix_counts"] == {outcome: 1}
    assert "## 8. Fix" in score.render_markdown(scored, summary)


def test_an_unknown_fix_outcome_is_an_error_not_a_guess(tmp_path):
    run = _run_dir(tmp_path, {"fix": {"outcome": "probably_fixed"}})
    with pytest.raises(score.ScoringError, match="unknown fix outcome"):
        score.score_run_dir(run)


def test_an_alarm_that_never_fired_is_said_in_the_results(tmp_path):
    run = _run_dir(tmp_path, {"fix": {"outcome": "not_fixed"}, "alarm": {"never_fired": True}})
    scored = score.score_run_dir(run)
    summary = score.summarise(scored)
    assert summary["alarm_never_fired"] == 1
    assert "never fired" in score.render_markdown(scored, summary)


def test_a_run_without_a_fix_record_gets_no_fix_fields(tmp_path):
    run = _run_dir(tmp_path, {})
    scored = score.score_run_dir(run)
    assert "fix" not in scored["rows"][0]
    summary = score.summarise(scored)
    assert "fix_counts" not in summary
    assert "## 8. Fix" not in score.render_markdown(scored, summary)


# --------------------------------------------------------------------------- published waves


@pytest.mark.skipif(not BUNDLES, reason="no published bundles in this checkout")
@pytest.mark.parametrize("bundle", BUNDLES, ids=lambda p: p.name)
def test_a_published_wave_scores_exactly_as_before(bundle, tmp_path):
    """Graded under its frozen rubric: no fix fields, no Fix section, and the same diagnoses as the
    ones it published."""
    run = tmp_path / bundle.name
    shutil.copytree(bundle, run)
    frozen = run / "grading" / "scoring.yaml"
    scored = score.score_run_dir(run, rubric_path=frozen)
    summary = score.summarise(scored)
    assert not [r for r in scored["rows"] if "fix" in r]
    assert "fix_counts" not in summary
    assert "## 8. Fix" not in score.render_markdown(scored, summary)

    # The published results.json of the first Wave 1 run is its CORRECTED grading (it is published
    # under both rubrics, see docs/bench/README.md), so the diagnoses are compared under today's
    # rubric - which test_the_wave_4_rubric_only_appended shows grades every old class unchanged.
    today = score.score_run_dir(run)
    published = json.loads((bundle / "results.json").read_text(encoding="utf-8"))
    key = lambda r: (r["scenario_id"], r["index"])
    assert ({key(r): r["diagnosis"] for r in today["rows"]}
            == {key(r): r["diagnosis"] for r in published["rows"]})
    assert {key(r): r["gate"] for r in today["rows"]} == {key(r): r["gate"] for r in published["rows"]}


@pytest.mark.skipif(not BUNDLES, reason="no published bundles in this checkout")
@pytest.mark.parametrize("bundle", BUNDLES, ids=lambda p: p.name)
def test_the_wave_4_rubric_only_appended(bundle):
    """Every fault class a published wave was graded under is untouched in today's rubric, so the
    Wave 4 additions cannot move one of its grades - only its drift banner (the file hash)."""
    frozen = yaml.safe_load((bundle / "grading" / "scoring.yaml").read_text(encoding="utf-8"))
    now = yaml.safe_load(score.SCORING.read_text(encoding="utf-8"))
    for name, entry in frozen["fault_classes"].items():
        assert now["fault_classes"][name] == entry, f"{name} changed after {bundle.name} was published"
    assert now["gate"] == frozen["gate"]
    assert now["action_kinds"] == frozen["action_kinds"]
