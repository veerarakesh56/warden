"""The CLI commands as split into helpers for SonarCloud: the paths no other local test reaches without a
Temporal server - each one a plant check found unguarded."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import audit, catalog, cli, intake, runtime
from warden.cli import DEMO_ALERTS
from warden.models import Alert


def _signed_log(tmp_path, *, rows: int):
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "audit.db"
    log = audit.AuditLog(path, key=key, checkpoint_every=100)
    for i in range(rows):
        log.append("inc-1", "step", {"n": i})
    log.checkpoint()
    log.close()
    pub = tmp_path / "audit.pub"
    from cryptography.hazmat.primitives import serialization

    pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
    return path, pub


def test_audit_show_of_an_incident_with_no_rows_exits_1(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDEN_AUDIT_DSN", raising=False)
    monkeypatch.setenv("WARDEN_KEY_DIR", str(tmp_path))
    db, pub = _signed_log(tmp_path, rows=2)
    assert cli.main(["audit", "show", "inc-none", "--db", str(db), "--public-key", str(pub)]) == 1


def test_audit_show_of_an_incident_with_rows_exits_0(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("WARDEN_AUDIT_DSN", raising=False)
    monkeypatch.setenv("WARDEN_KEY_DIR", str(tmp_path))
    db, pub = _signed_log(tmp_path, rows=2)
    assert cli.main(["audit", "show", "inc-1", "--db", str(db), "--public-key", str(pub)]) == 0
    assert "incident inc-1: 2 row(s); the chain is intact" in capsys.readouterr().out


def _no_temporal(monkeypatch):
    async def connect():
        return object()

    monkeypatch.setattr(runtime, "connect", connect)


def test_intake_hands_the_event_and_the_audit_to_intake(tmp_path, monkeypatch, capsys):
    _no_temporal(monkeypatch)
    the_audit = object()
    monkeypatch.setattr(runtime, "open_audit", lambda: the_audit)
    seen = []

    async def submit(client, event, log):
        seen.append(log)
        return SimpleNamespace(action="start", workflow_id="inc-1", reason="new")

    monkeypatch.setattr(intake, "submit", submit)
    event = intake.AlarmEvent(rule="HighErrorRate", state="ALARM", transitioned_at=datetime(2026, 10, 15, tzinfo=UTC),
                              alert=Alert(**DEMO_ALERTS["inc-001"]))
    path = tmp_path / "event.json"
    path.write_text(event.model_dump_json(), encoding="utf-8")
    assert cli.main(["intake", str(path)]) == 0
    assert seen == [the_audit]


def test_status_shows_every_refusal_of_the_plan(monkeypatch, capsys):
    _no_temporal(monkeypatch)
    plan = SimpleNamespace(entry="scale", params={}, snapshot={}, tier="T1", target="orders", plan_hash="h1",
                           problems=["the target changed"])

    async def status(client, workflow_id):
        return "awaiting_approval", plan

    monkeypatch.setattr(runtime, "status", status)
    monkeypatch.setattr(catalog, "change_of", lambda entry, params, snapshot: [])
    assert cli.main(["status", "rem-1"]) == 0
    assert "  refused: the target changed" in capsys.readouterr().out


def test_killswitch_link_without_the_pages_domain_says_so(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("WARDEN_APPROVAL_RP_ID", raising=False)
    assert cli.main(["killswitch", "link", "--approver", "owner", "--key", str(tmp_path / "k.pem")]) == 1
    assert "WARDEN_APPROVAL_RP_ID is not set" in capsys.readouterr().err


def test_resetting_a_switch_that_is_off_signs_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("WARDEN_APPROVAL_RP_ID", raising=False)
    log = audit.AuditLog(tmp_path / "audit.db", key=Ed25519PrivateKey.generate())
    monkeypatch.setattr(runtime, "open_audit", lambda: log)
    try:
        code = cli.main(["killswitch", "reset", "--approver", "owner", "--key", str(tmp_path / "k.pem"), "--trips", "0"])
    finally:
        log.close()
    assert code == 0
    assert "the kill switch is not on" in capsys.readouterr().out


def test_autonomy_runs_the_autonomy_command(monkeypatch):
    async def autonomy(args):
        return 7

    monkeypatch.setattr(cli, "_autonomy_command", autonomy)
    assert cli.main(["autonomy", "status", "--environment", "dev"]) == 7


def test_link_loads_the_configuration_a_label_needs(monkeypatch):
    loaded = []
    monkeypatch.setattr(cli, "_load_environment", lambda command, zone=None: loaded.append(command))
    monkeypatch.setattr(cli, "_link_command", lambda args: 0)
    assert cli.main(["link", "inc-1", "inc-2", "--as", "caused-by", "--approver", "owner", "--key", "k.pem"]) == 0
    assert loaded == ["label"]


def test_the_json_report_carries_no_control_character(tmp_path):
    bell = chr(7)  # the redaction leaves it; only the control-character strip removes it
    report = SimpleNamespace(model_dump=lambda mode: {"note": f"ring {bell} twice"}, redaction_map={})
    path = cli._write_json_report(report, str(tmp_path / "report.json"))
    assert json.loads(path.read_text(encoding="utf-8")) == {"note": "ring  twice"}


def test_the_json_report_is_written_where_asked(tmp_path):
    report = SimpleNamespace(model_dump=lambda mode: {"note": "fine"}, redaction_map={})
    assert cli._write_json_report(report, str(tmp_path / "report.json")) == (tmp_path / "report.json").resolve()


def test_a_browser_that_cannot_be_opened_is_said_on_stderr(monkeypatch, capsys):
    monkeypatch.setattr("webbrowser.open", lambda url: False)
    cli._opened("https://example.invalid/x")
    assert "error: no browser could be opened on this machine" in capsys.readouterr().err


def test_a_label_with_an_empty_key_is_refused():
    """As on main: `--label =v` names no label, so it stops the command."""
    with pytest.raises(SystemExit, match="--label must be K=V, got '=v'"):
        cli._with_labels({}, ["=v"])


@pytest.mark.parametrize("none", [None, b""])
def test_keygen_without_a_passphrase_writes_no_key(none, tmp_path, monkeypatch):
    """No passphrase - nothing typed (b""), or a None from the prompt - is refused unless --unencrypted, as on
    main: a None must never mean "write it in the clear"."""
    monkeypatch.delenv("WARDEN_AUDIT_KEY_PASSPHRASE", raising=False)
    monkeypatch.setattr(cli, "_typed_passphrase", lambda: none)
    priv = tmp_path / "k.pem"
    cli.main(["audit", "keygen", "--private", str(priv), "--public", str(tmp_path / "k.pub")])
    assert not priv.exists()


@pytest.mark.parametrize("none", [None, b""])
def test_keygen_without_a_passphrase_exits_1(none, tmp_path, monkeypatch):
    monkeypatch.delenv("WARDEN_AUDIT_KEY_PASSPHRASE", raising=False)
    monkeypatch.setattr(cli, "_typed_passphrase", lambda: none)
    code = cli.main(["audit", "keygen", "--private", str(tmp_path / "k.pem"), "--public", str(tmp_path / "k.pub")])
    assert code == 1


def test_keygen_unencrypted_still_writes_a_key_with_no_passphrase(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDEN_AUDIT_KEY_PASSPHRASE", raising=False)
    monkeypatch.setattr(cli, "_typed_passphrase", lambda: None)
    priv = tmp_path / "k.pem"
    cli.main(["audit", "keygen", "--private", str(priv), "--public", str(tmp_path / "k.pub"), "--unencrypted"])
    assert priv.exists()
