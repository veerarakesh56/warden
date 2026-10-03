"""Audit row CW3: environmental impact was not measured. WARDEN measures its own share - model calls and tokens per
incident and per day, from its audit (`warden usage`) - and the account's emissions come from AWS's Customer Carbon
Footprint Tool (docs/governance/ENVIRONMENT.md)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from warden import audit
from warden.cli import main, usage_by_day


def _spend(log, incident, calls, tin, tout, usd):
    log.append(incident, "incident.llm_spend", {"calls": calls, "input_tokens": tin, "output_tokens": tout, "usd": usd})


def test_model_use_is_summed_per_day_and_counts_incidents_once(tmp_path):
    log = audit.AuditLog(tmp_path / "a.db")
    _spend(log, "inc-1", 1, 6000, 900, 0.03)
    _spend(log, "inc-1", 1, 5000, 800, 0.02)  # a second call for the same incident
    _spend(log, "inc-2", 1, 7000, 1000, 0.04)
    log.append("inc-3", "incident.gather", {"x": 1})  # other rows are not use
    [day] = usage_by_day(log, datetime.now(UTC) - timedelta(days=1))
    assert (day["incidents"], day["calls"], day["input_tokens"], day["output_tokens"]) == (2, 3, 18000, 2700)
    assert round(day["usd"], 2) == 0.09 and day["day"] == datetime.now(UTC).date().isoformat()


def test_the_command_prints_it(tmp_path, monkeypatch, capsys):
    db = tmp_path / "a.db"
    log = audit.AuditLog(db)
    _spend(log, "inc-1", 2, 12000, 1700, 0.05)
    log.close()
    monkeypatch.setenv("WARDEN_AUDIT_DB", str(db))
    monkeypatch.delenv("WARDEN_ENV", raising=False)
    assert main(["usage", "--days", "7"]) == 0
    out = capsys.readouterr().out
    assert "incidents    1" in out and "calls     2" in out and "12000" in out and "USD 0.0500" in out
