"""The fs-01 re-diagnosis's report reached the channel as "The report was held back by the outbound
gate." - and nothing on its record or in the log said where, so the cause could only be guessed. A withheld text now
says where it was withheld - line, section and kind, never the value - on the incident's record and in the log."""

from __future__ import annotations

import logging

from fakes import AWS_ACCESS_KEY_ID
from test_chatops import _CaptureSink
from warden import chatops
from warden.gate import where_withheld
from warden.reporting import Report

KEY = AWS_ACCESS_KEY_ID


def test_where_names_the_line_the_section_and_the_kind_never_the_value():
    text = f"# Incident\n\n## Evidence\nall fine\n## Config\nkey {KEY} in the config\n"
    where = where_withheld(text)
    assert where == [{"line": 6, "section": "Config", "kinds": where[0]["kinds"]}]
    assert where[0]["kinds"]
    assert KEY not in str(where)


def test_a_heading_that_carries_a_secret_is_not_named():
    where = where_withheld(f"## {KEY}\nkey {KEY}\n")
    assert all(w["section"] == "(a heading that is itself withheld)" for w in where)
    assert KEY not in str(where)


def test_a_clean_text_has_nowhere():
    assert where_withheld("# Incident\nall fine\n") == []


def test_a_withheld_message_logs_where_without_the_value(caplog):
    sink = _CaptureSink()
    report = Report(markdown=f"# Incident\n## Config\nkey {KEY}\n", data={"alert": {"id": "inc-7"}}, promotion=())
    with caplog.at_level(logging.WARNING, logger="warden.incident"):
        chatops.notify(report, sinks=[sink])
    said = [r.getMessage() for r in caplog.records if "withheld by the outbound gate" in r.getMessage()]
    assert len(said) == 1
    assert "inc-7" in said[0]
    assert "'section': 'Config'" in said[0]
    assert KEY not in said[0]


def test_a_withheld_report_says_where_on_the_incidents_record(tmp_path, monkeypatch):
    from warden import audit, history
    from warden.activities import IncidentActivities
    from warden.cli import DEMO_ALERTS
    from warden.llm import LLMClient
    from warden.models import Alert

    monkeypatch.setattr(chatops, "notify", lambda report, sinks=None, threads=None: [])
    # The report carries a value the redactor missed - what G5 is for (the live case's value is not known): here in
    # the line said under the title, which the report puts in before the gate reads it.
    monkeypatch.setattr(history, "again", lambda before: f"key {KEY}")
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    acts = IncidentActivities(audit=log, llm_factory=lambda: LLMClient(mock=True))
    alert = Alert(**DEMO_ALERTS["inc-002"])
    pack = acts.prepare(alert)
    diagnosed = acts.diagnose(pack)
    acts.notify(pack, diagnosed, acts.verify(pack, diagnosed), mode="none")
    row = log.entries(alert.alert_id, kinds=("incident.report",))[-1]["body"]
    assert row["markdown"] == "The report was held back by the outbound gate."
    assert row["gate_reasons"]
    assert row["withheld"]
    assert row["withheld"][0]["kinds"]
    assert KEY not in str(row)
