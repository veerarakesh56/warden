"""Register N4 / audit A-N-4: an approver reads what the rules found before the model's fluent text."""

from __future__ import annotations

from warden.activities import Plan
from warden.cli import DEMO_ALERTS, main
from warden.graph import run
from warden.llm import LLMClient
from warden.models import Alert
from warden.reporting import build_report


def test_the_cli_shows_the_verdict_and_the_evidence_before_the_hypothesis(capsys):
    assert main(["run", "--incident", "inc-001"]) == 0
    out = capsys.readouterr().out
    assert out.index("VERDICT") < out.index("evidence shows") < out.index("hypothesis (model)")


def test_the_report_puts_the_gate_before_the_models_diagnosis():
    r = run(Alert(**DEMO_ALERTS["inc-001"]), llm=LLMClient(mock=True))
    md = build_report(r.alert, root_cause=r.root_cause, proposal=r.proposal, verdict=r.verdict, context=r.context,
                      redaction_map=r.redaction_map, show_identifiers=False).markdown
    assert md.index("## Gate verdict") < md.index("## What WARDEN thinks happened")
    assert md.index("- **Proposed**") < md.index("- **Diagnosis** (model")


def test_what_an_approver_signs_holds_no_model_text():
    """The approval signs the plan hash, and `warden status` shows only the plan: no prose reaches the signature."""
    assert not {"hypothesis", "reasoning", "expected_effect", "evidence", "summary"} & set(Plan.model_fields)
