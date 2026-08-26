"""The command line.

Coverage measurement put this module at 22% - 43 of 55 statements untested - which is the worst
possible place for a gap: `warden demo` is the first thing anyone who clones this repo runs. Every
other module was tested through its API while the actual entry point was not exercised at all.
"""

import pytest

from warden.cli import DEMO_ALERTS, main


def test_demo_runs_and_prints_every_incident(capsys):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    for incident in DEMO_ALERTS:
        assert incident in out, f"{incident} missing from demo output"


def test_demo_output_carries_the_safety_claim(capsys):
    """The closing line is the project's whole thesis. If it silently disappeared, nobody would notice."""
    main(["demo"])
    out = capsys.readouterr().out
    assert "No action was executed" in out
    assert "a human executes" in out


def test_demo_produces_the_expected_spread_of_verdicts(capsys):
    """Guards the packaging bug that made every incident return AUTO_SAFE inside the container.

    Fixtures used to be resolved relative to the repo root, which breaks once pip-installed: every
    context tool failed, evidence came back empty, and all four incidents returned AUTO_SAFE with
    exit code 0. CI only checked the exit code and stayed green.
    """
    main(["demo"])
    out = capsys.readouterr().out
    assert "APPROVED_FOR_HUMAN" in out
    assert "ESCALATED" in out
    assert out.count("AUTO_SAFE") == 1, "exactly one incident should be inert - fixtures missing?"
    assert "P6-BLAST-RADIUS" in out


def test_run_single_incident(capsys):
    assert main(["run", "--incident", "inc-002"]) == 0
    out = capsys.readouterr().out
    assert "inc-002" in out
    assert "PodOOMKilled" in out
    assert "scale_up" in out


def test_verbose_prints_the_audit_trail(capsys):
    main(["run", "--incident", "inc-001", "--verbose"])
    out = capsys.readouterr().out
    assert "audit trail" in out
    for node in ("ingest", "gather", "redact", "analyse", "propose", "verify"):
        assert f'"node": "{node}"' in out, f"{node} missing from the audit trail"


def test_output_never_leaks_a_raw_identifier(capsys):
    """inc-001's alert summary contains a real email and tenant id in the fixture."""
    main(["run", "--incident", "inc-001"])
    out = capsys.readouterr().out
    assert "priya.nair@corp.io" not in out
    assert "acme-42" not in out


def test_cost_is_always_reported(capsys):
    main(["run", "--incident", "inc-003"])
    assert "cost" in capsys.readouterr().out


def test_unknown_incident_exits_with_a_useful_message():
    with pytest.raises(SystemExit) as exc:
        main(["run", "--incident", "inc-999"])
    assert "inc-999" in str(exc.value)
    assert "inc-001" in str(exc.value), "the error should list what IS available"


def test_budget_flag_is_wired_through():
    """--max-usd must actually reach the client, not just be accepted by argparse."""
    from warden.llm import BudgetExceeded

    with pytest.raises(BudgetExceeded):
        main(["run", "--incident", "inc-001", "--max-usd", "0.0001"])


def test_no_subcommand_is_rejected():
    with pytest.raises(SystemExit):
        main([])


def test_run_report_flag_prints_the_report_and_safety_line(capsys):
    assert main(["run", "--incident", "inc-002", "--report"]) == 0
    out = capsys.readouterr().out
    assert "WARDEN incident report" in out
    assert "Promotion" in out
    assert "Nothing was executed against production" in out


def test_run_in_staging_with_approval_dry_runs(capsys):
    assert main([
        "run", "--incident", "inc-002", "--environment", "staging",
        "--principal", "role:oncall", "--approve",
    ]) == 0
    out = capsys.readouterr().out
    assert "dry_run" in out
    assert "would scale_up" in out


def test_run_in_prod_never_auto_remediates(capsys):
    assert main([
        "run", "--incident", "inc-002",
        "--principal", "role:oncall", "--approve",
    ]) == 0
    out = capsys.readouterr().out
    assert "not_auto_remediable" in out


def test_run_with_unauthorized_principal_is_reported(capsys):
    assert main([
        "run", "--incident", "inc-002", "--environment", "staging",
        "--principal", "role:intern", "--approve",
    ]) == 0
    out = capsys.readouterr().out
    assert "unauthorized" in out
