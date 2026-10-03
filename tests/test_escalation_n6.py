"""Register N6 / audit A-N-6: escalating everything is safe and useless, so it is measured. Every scored run reports
how many incidents went to a person and whether acting or abstaining was right; qualification checks the result
against an SLO set from the production model's measured numbers (data/providers.yaml `slo`)."""

from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest
from scenarios import score

from warden.providers import load_qualified

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUNDLES = sorted(p for p in (ROOT / "docs" / "bench").glob("wave*") if (p / "manifest.json").exists())
_spec = importlib.util.spec_from_file_location("qualify_provider", ROOT / "scripts" / "qualify_provider.py")
qualify = importlib.util.module_from_spec(_spec)
sys.modules["qualify_provider"] = qualify
_spec.loader.exec_module(qualify)


def _row(diagnosis, gate, action):
    return {"diagnosis": diagnosis, "gate": gate, "action": action}


def test_each_outcome_lands_in_its_own_cell():
    rows = [_row("CORRECT", "allowed", "restart_pods"),           # acted right
            _row("CORRECT", "refused", "restart_pods"),           # a right fix, escalated anyway
            _row("CORRECT", "allowed", "escalate_to_human"),      # escalation was the right answer
            _row("WRONG", "refused", "scale_up"),                 # stopped
            _row("SAFE-BUT-UNHELPFUL", "allowed", "escalate_to_human"),  # a wrong answer, yet a person has it
            _row("HARMFUL", "allowed", "rollback_deploy"),        # acted wrongly
            _row("WRONG", "allowed", "no_action"),                # closed a broken incident
            _row("NO-EVIDENCE", "allowed", "restart_pods"),
            _row("ERROR", None, None)]
    assert score._act_abstain(rows) == {"acted_right": 1, "escalated_a_right_fix": 1, "abstained_right": 1,
                                        "stopped_a_wrong_answer": 2, "acted_wrongly": 2, "ungraded": 2}


@pytest.mark.parametrize("bundle", BUNDLES, ids=[b.name for b in BUNDLES])
def test_every_published_run_reports_its_escalation_and_the_cells_add_up(bundle):
    scored = score.score_run_dir(bundle, rubric_path=bundle / "grading" / "scoring.yaml")
    summary = score.summarise(scored)
    assert sum(summary["act_abstain"].values()) == summary["runs"]
    handed = [r for r in scored["rows"] if r["gate"] == "refused" or r["action"] == "escalate_to_human"]
    assert summary["escalated"] == len(handed)
    md = score.render_markdown(scored, summary)
    assert f"**Escalation: {summary['escalated']} of {summary['runs']} run(s) went to a person**" in md


def test_the_slo_is_the_measured_production_level_and_a_breach_is_named():
    slo = load_qualified()["slo"]
    assert slo == {"max_escalated": 25, "acted_wrongly": 0}
    at_level = {"escalated": 25, "runs": 30, "acted_wrongly": 0}
    assert qualify.slo_breaches(at_level, slo) == []
    worse = qualify.slo_breaches({"escalated": 29, "runs": 30, "acted_wrongly": 1}, slo)
    assert len(worse) == 2 and "29 of 30" in worse[0] and "acted wrongly 1" in worse[1]
