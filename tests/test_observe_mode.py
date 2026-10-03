"""Audit A-P-8: an observe mode for new policies. A policy in observe mode is evaluated on every verdict and recorded
- in the verdict, the report and the replay score - and never changes what is decided. Its first use is audit Q2's
candidate rule (a "nothing to do" over an error rate), measured before it is ever enforced."""

from __future__ import annotations

from scenarios import score

from test_verifier import _alert, _ctx, _prop, _rc
from warden.models import ActionKind, VerdictStatus
from warden.reporting import build_report
from warden.verifier import _enforce, verify


def test_an_observed_policy_is_recorded_and_changes_nothing():
    args = (_alert(), _ctx(metrics={"error_rate": 0.31, "p99_latency_ms": 2140.0}), _rc(confidence=0.95),
            _prop(action=ActionKind.no_action))
    observed, enforced = verify(*args), _enforce(*args)
    assert observed.observed and observed.observed[0].startswith("P25-NO-ACTION-OVER-ERROR-RATE: ")
    assert "error_rate" in observed.observed[0]
    assert observed.model_copy(update={"observed": []}) == enforced  # the decision is exactly the enforced one
    assert "P25-NO-ACTION-OVER-ERROR-RATE" not in observed.policy_ids


def test_it_is_silent_below_its_threshold_and_for_other_actions():
    quiet = verify(_alert(), _ctx(metrics={"error_rate": 0.01, "x": 1.0}), _rc(confidence=0.95),
                   _prop(action=ActionKind.no_action))
    acting = verify(_alert(), _ctx(metrics={"error_rate": 0.31, "x": 1.0}), _rc(), _prop())
    assert not any(o.startswith("P25") for o in quiet.observed + acting.observed)


def test_the_report_shows_it_as_observed_only():
    args = (_alert(), _ctx(metrics={"error_rate": 0.31, "p99_latency_ms": 2140.0}), _rc(confidence=0.95),
            _prop(action=ActionKind.no_action))
    v = verify(*args)
    md = build_report(args[0], root_cause=args[2], proposal=args[3], verdict=v, context=args[1]).markdown
    assert "Observed only, not enforced" in md and "P25-NO-ACTION-OVER-ERROR-RATE" in md


def test_a_replay_score_counts_where_it_would_have_fired_by_diagnosis(tmp_path):
    import json
    import pathlib
    import shutil

    src = max(p for p in (pathlib.Path(score.__file__).parents[1] / "docs" / "bench").glob("wave*")
              if (p / "manifest.json").exists())
    bundle = pathlib.Path(shutil.copytree(src, tmp_path / src.name))
    first = min((bundle / "reports").glob("*.json"))
    report = json.loads(first.read_text(encoding="utf-8"))
    report["verdict"]["observed"] = ["P25-X: would have escalated"]
    first.write_text(json.dumps(report), encoding="utf-8")
    scored = score.score_run_dir(bundle, rubric_path=bundle / "grading" / "scoring.yaml")
    row = next(r for r in scored["rows"] if r.get("observed"))
    summary = score.summarise(scored)
    assert summary["observed"] == {"P25-X": {row["diagnosis"]: 1}}
    assert VerdictStatus(row["verdict"])  # graded from the unchanged verdict
