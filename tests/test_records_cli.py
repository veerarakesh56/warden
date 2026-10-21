"""`warden records list|show` (owner update 3, U3-6): WARDEN's records for an operator's terminal - read only, with
the records page's redaction (an approver by name, never the list's id) and every value the pipeline masks masked."""

from __future__ import annotations

import ast
import hashlib
import json
import pathlib
import sqlite3
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_approval_page import setup as page_setup  # noqa: F401 - the fixture, used by name below
from warden import audit, cli, records_cli, runtime_base, settings

ROOT = pathlib.Path(__file__).resolve().parents[1]
INC = "50ac32d0fe243384-20261021T071413Z"
OTHER_INC = "50ac32d0fe243384-20261020T071413Z"
# A canary e-mail and address, built from parts (tests/fakes.py's rule): neither may ever reach the terminal.
EMAIL = "priya.nair" + "@" + "corp.example"
ADDRESS = "10.20" + ".30.40"
ESC = "\x1b"
BELL = "\x07"  # a control character JSON escapes, and `jq -r` would print live again


def _named(policy):
    policy = policy.model_copy(deep=True)
    policy.approvers["owner"].name = "Asha Rao"
    return policy


def _audit(path: pathlib.Path) -> pathlib.Path:
    log = audit.AuditLog(path, key=Ed25519PrivateKey.generate(), checkpoint_every=3)
    at = datetime(2026, 10, 21, 7, 14, tzinfo=UTC).isoformat()
    for inc in (OTHER_INC, INC):
        log.append(inc, "incident.ingest", {"node": "ingest", "alert_id": inc, "env": "dev"})
        log.append(inc, "incident.alert", {"alert": {
            "alert_id": inc, "name": "TickSilent", "severity": "high", "service": "tick", "environment": "dev",
            "summary": f"no ticks for {EMAIL} from {ADDRESS} <EMAIL_1> {ESC}[2J{BELL}",
            "labels": {"alarm": "warden-dev-lab-tick-silent"}}})
    log.append(INC, "incident.diagnose", {"node": "diagnose", "hypothesis": f"The schedule was switched off by {EMAIL}",
                                          "action": "revert_change", "target": "rule/tick", "confidence": 0.8})
    log.append(INC, "incident.verify", {"node": "verify", "status": "approved_for_human", "policies": []})
    log.append(INC, "incident.report", {"markdown": f"# WARDEN incident report\n## Cause\n- seen from {ADDRESS}"})
    log.append(INC, "incident.evidence", {"prompt": f"log line: user {EMAIL} failed"})
    log.append(INC, "remediation.plan", {"workflow_id": "rem-dev-1", "entry": "events_enable_rule", "tier": "T1",
                                         "target": "rule/tick", "plan_hash": "h"})
    log.append(INC, "approval.refused", {"problems": ["owner signed a different plan"]})
    log.append(INC, "approval.accepted", {"workflow_id": "rem-dev-1", "approver": "owner", "method": "passkey",
                                          "note": f"ok, ask {EMAIL}", "hasty": False, "latency_s": 42})
    log.append(INC, "record.link", {"incident": INC, "other": OTHER_INC, "type": "recurrence-of", "approver": "owner",
                                    "note": "same rule", "removed": False, "at": at, "signature": "00"})
    log.append(INC, "workflow.end", {"workflow_id": "rem-dev-1", "status": "recovered",
                                     "reasons": ["denied by owner: not now"]})
    log.close()
    return path


@pytest.fixture
def reader(page_setup, tmp_path, monkeypatch):  # noqa: F811 - the fixture imported above
    db = _audit(tmp_path / "audit.db")
    monkeypatch.delenv("WARDEN_AUDIT_DSN", raising=False)
    monkeypatch.delenv("WARDEN_ENV", raising=False)
    monkeypatch.setenv("WARDEN_AUDIT_DB", str(db))
    monkeypatch.setenv("WARDEN_DISPLAY_ZONE", "Asia/Kolkata")
    policy = _named(page_setup[0].policy)
    monkeypatch.setattr(runtime_base, "approver_policy", lambda: policy)
    return db


def _run(capsys, *argv: str) -> tuple[int, str, str]:
    code = cli.main(["records", *argv])
    out = capsys.readouterr()
    return code, out.out, out.err


def _clean(text: str) -> None:
    """Nothing the pipeline masks, no approver list id, no control character."""
    assert EMAIL not in text
    assert ADDRESS not in text
    assert ESC not in text
    assert BELL not in text
    assert "\\u00" not in text.lower()  # not even escaped in JSON
    assert "owner" not in text.replace("WARDEN", ""), text


# ------------------------------------------------------------------ what it shows


def test_list_shows_each_incident_newest_first_masked_in_text_and_json(reader, capsys):
    code, out, _ = _run(capsys, "list")
    assert code == 0
    assert out.index(INC) < out.index(OTHER_INC)
    assert "Fixed and held" in out
    assert "dev/tick" in out
    assert "2 shown of 2 matching" in out
    assert "IST" in out
    _clean(out)
    code, out, _ = _run(capsys, "list", "--json", "--status", "Fixed and held")
    data = json.loads(out)
    assert code == 0
    assert [i["id"] for i in data["incidents"]] == [INC]
    assert data["matched"] == 1
    assert data["total"] == 2
    _clean(out)


def test_show_is_the_whole_record_with_approvers_by_name_and_masked_values(reader, capsys):
    code, out, _ = _run(capsys, "show", INC)
    assert code == 0, out
    for said in ("Approved by Asha Rao with their passkey", "Denied by Asha Rao", "An approval was refused: Asha Rao",
                 "Linked: this incident is a recurrence of " + OTHER_INC + " - linked by Asha Rao",
                 "events_enable_rule on rule/tick - risk T1", "Every step on the record:", "Complete findings:",
                 "Signed record: audit head ", "<EMAIL_"):
        assert said in out, said
    assert "The evidence WARDEN read" not in out
    assert "Signed record: Signed" not in out  # evidence: --evidence
    _clean(out)
    code, out, _ = _run(capsys, "show", INC, "--json", "--evidence")
    data = json.loads(out)
    assert code == 0
    assert data["id"] == INC
    assert data["decisions"][0]["who"] == "Asha Rao"
    assert data["links"][0]["with"] == OTHER_INC
    assert data["evidence"].startswith("log line: user <EMAIL_")
    _clean(out)


def test_new_placeholders_continue_after_the_records_own(reader, capsys):
    """The alert already says `<EMAIL_1>` (a value the pipeline masked): the raw e-mail beside it is another value,
    so it must not read as the same one."""
    _, out, _ = _run(capsys, "show", INC, "--json")
    says = json.loads(out)["alert_says"]
    assert "<EMAIL_1>" in says
    assert "<EMAIL_2>" in says
    assert "<IPV4_1>" in says


def test_an_unknown_or_a_discussion_id_or_a_bad_filter_shows_nothing(reader, capsys):
    for incident in ("no-such", "discuss-" + INC, "../x", "a" * 121):
        code, out, err = _run(capsys, "show", incident)
        assert (code, out) == (1, ""), incident
        assert "no incident" in err, incident
    for argv in (("--since", "2026-13-01"), ("--status", "Nope"), ("--since", "2026-10-21", "--until", "2026-10-20"),
                 ("--limit", "0"), ("--limit", "501"), ("--env", "Bad Env")):
        code, out, _ = _run(capsys, "list", *argv)
        assert (code, out) == (2, ""), argv


def test_without_the_approver_list_nothing_is_shown(reader, capsys, monkeypatch):
    """Without it a refusal's text would name an approver by the list's id."""
    def unreadable():
        raise RuntimeError("no list")

    monkeypatch.setattr(runtime_base, "approver_policy", unreadable)
    code, out, err = _run(capsys, "show", INC)
    assert code == 2
    assert out == ""
    assert "approver list could not be read" in err


# ------------------------------------------------------------------ read only


def test_reading_the_records_never_changes_the_audit_file(reader, capsys):
    before = hashlib.sha256(reader.read_bytes()).hexdigest()
    for argv in (("list",), ("list", "--json"), ("show", INC), ("show", INC, "--json", "--evidence")):
        assert _run(capsys, *argv)[0] == 0
    assert hashlib.sha256(reader.read_bytes()).hexdigest() == before
    assert not list(reader.parent.glob("audit.db-*"))  # no journal or WAL file either


def test_the_reader_has_no_write_path(reader):
    log = records_cli.open_read_only()
    try:
        for name in ("append", "append_unless", "checkpoint", "anchor", "key"):
            assert not hasattr(log, name), name
        with pytest.raises(PermissionError):
            log.store.run("INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?, ?)", (999, "", "", "", "{}", "", ""))
        with pytest.raises(PermissionError):
            log.store.run("  delete from entries")
        with pytest.raises(sqlite3.OperationalError, match="readonly"):  # and SQLite itself refuses
            log.store.db.execute("INSERT INTO checkpoints VALUES (1, 'h', 's')")
        assert log.entries(INC)[0]["kind"] == "incident.ingest"
    finally:
        log.close()


def test_a_missing_audit_file_is_not_created(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDEN_AUDIT_DSN", raising=False)
    monkeypatch.setenv("WARDEN_AUDIT_DB", str(tmp_path / "none.db"))
    with pytest.raises(FileNotFoundError):
        records_cli.open_read_only()
    assert not (tmp_path / "none.db").exists()


def test_a_postgresql_session_is_read_only_before_its_first_query(monkeypatch):
    said = []

    class Connection:
        def execute(self, sql, params=()):
            said.append(sql)

            class Cursor:
                description = None
                rowcount = 0

            return Cursor()

    monkeypatch.setenv("WARDEN_AUDIT_DSN", "postgresql://reader@audit.invalid/warden")
    monkeypatch.setattr(audit, "_pg_connect", lambda dsn: Connection())
    log = records_cli.open_read_only()
    log.signed_through()
    assert said[0] == "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY"
    assert said[1].startswith("SELECT")
    monkeypatch.setenv("WARDEN_AUDIT_DSN", "sqlite:///x")
    with pytest.raises(RuntimeError):
        records_cli.open_read_only()


def test_the_command_loads_only_the_audit_dsn_from_the_store():
    assert settings.loadable_for("records") == frozenset({"WARDEN_AUDIT_DSN"})
    assert "WARDEN_AUDIT_KEY_PASSPHRASE" not in settings.loadable_for("records")  # it signs nothing
    assert "WARDEN_SLACK_BOT_TOKEN" in settings.loadable_for("usage")  # the others are unchanged


def test_the_reader_never_reaches_the_vault_or_the_reveal_path():
    """A masked value is revealed on the records page, signed in and recorded - never through the CLI."""
    tree = ast.parse((ROOT / "src/warden/records_cli.py").read_text(encoding="utf-8"))
    names = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import | ast.ImportFrom) for a in n.names}
    names |= {n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not names & {"vault", "reveal", "warden.vault", "warden.reveal"}
    assert not any("restore" == getattr(n, "attr", "") for n in ast.walk(tree))


def test_an_alerts_own_fields_are_masked_too(reader, capsys, tmp_path, monkeypatch):
    """An alert's environment and severity are what its sender wrote (CodeRabbit, PR 147): masked like the rest."""
    log = audit.AuditLog(reader, key=Ed25519PrivateKey.generate())
    other = "50ac32d0fe243384-20261021T081413Z"
    log.append(other, "incident.ingest", {"node": "ingest", "alert_id": other, "env": EMAIL})
    log.append(other, "incident.alert", {"alert": {"alert_id": other, "name": "X", "severity": ADDRESS,
                                                   "environment": EMAIL, "service": "tick", "summary": "s"}})
    log.close()
    for argv in (("list",), ("list", "--json"), ("show", other), ("show", other, "--json")):
        code, out, _ = _run(capsys, *argv)
        assert code == 0
        _clean(out)


def test_a_huge_placeholder_number_is_seeded_once_not_counted_up_to():
    """CodeRabbit, PR 147: `<EMAIL_1000000000>` in an alert's text seeded every number up to it before printing."""
    from warden import records_cli

    said = records_cli.masked({"summary": "<EMAIL_1000000000> wrote to ops@example.com"})["summary"]
    assert said.startswith("<EMAIL_1000000000> wrote to <EMAIL_")
    assert "ops@example.com" not in said


def test_a_new_placeholder_never_reuses_a_number_the_record_already_holds():
    from warden import records_cli

    said = records_cli.masked({"summary": "<EMAIL_2> and ops@example.com"})["summary"]
    assert said == "<EMAIL_2> and <EMAIL_3>"
