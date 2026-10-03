"""Requirement R15 found it: a model that never answered (quota, outage, no access) was scored on the gate's
rules-only fallback - Gemini 3.1 Pro, refused 30 of 30 times for want of billing, came out "7 correct, 0 errors".
A row the gate stopped with P0-MODEL-UNAVAILABLE is counted as unanswered, and one unanswered row fails the run."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("qualify_provider_u", ROOT / "scripts" / "qualify_provider.py")
qualify = importlib.util.module_from_spec(_spec)
sys.modules["qualify_provider_u"] = qualify
_spec.loader.exec_module(qualify)


def _fake_scoring(monkeypatch, rows):
    sys.path.insert(0, str(ROOT))
    from scenarios import score

    monkeypatch.setattr(qualify, "RUNS", ["r1"])
    monkeypatch.setattr(score, "score_run_dir", lambda *a, **kw: {"rows": rows})
    monkeypatch.setattr(score, "summarise", lambda scored: {
        "diagnosis_counts": {"CORRECT": 20}, "runs": len(rows), "headline_wrong_and_allowed": 0, "errors": 0,
        "escalated": 0, "act_abstain": {}})


def test_rows_the_model_never_answered_are_counted(tmp_path, monkeypatch):
    rows = [{"policy_ids": ["P0-MODEL-UNAVAILABLE"], "diagnosis": "SAFE-BUT-UNHELPFUL", "gate": "refused", "action": "x"},
            {"policy_ids": ["P5"], "diagnosis": "CORRECT", "gate": "allowed", "action": "x"}]
    _fake_scoring(monkeypatch, rows)
    assert qualify.tally(tmp_path)["unanswered"] == 1


def test_one_unanswered_incident_fails_an_otherwise_passing_run(tmp_path, monkeypatch, capsys):
    rows = [{"policy_ids": ["P0-MODEL-UNAVAILABLE"], "diagnosis": "CORRECT", "gate": "refused", "action": "x"}]
    _fake_scoring(monkeypatch, rows)
    (tmp_path / "qualification.json").write_text(json.dumps({"provider": "gemini", "model": "m"}), encoding="utf-8")
    assert qualify.main(["--out", str(tmp_path), "--score-only"]) == 1
    out = capsys.readouterr().out
    assert "NOT MEASURED: the model did not answer 1 of 1" in out and '"passed": false' in out
    _fake_scoring(monkeypatch, [{**rows[0], "policy_ids": []}])
    assert qualify.main(["--out", str(tmp_path), "--score-only"]) == 0
