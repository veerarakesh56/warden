"""Owner requirement R4: every time WARDEN shows is in UTC and in the install's display zone (IST here)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from warden import environments
from warden.cli import DEMO_ALERTS
from warden.environments import both_times
from warden.graph import run
from warden.llm import LLMClient
from warden.models import Alert
from warden.reporting import build_report


@pytest.fixture(autouse=True)
def _configured_zone(monkeypatch):
    monkeypatch.delenv("WARDEN_DISPLAY_ZONE", raising=False)


def test_a_time_is_shown_in_utc_and_in_ist():
    assert both_times(datetime(2026, 10, 3, 1, 0, tzinfo=UTC)) == "2026-10-03 01:00:00Z (06:30 IST)"
    assert both_times(datetime(2026, 10, 2, 20, 0, tzinfo=UTC)) == "2026-10-02 20:00:00Z (2026-10-03 01:30 IST)"


def test_the_zone_is_the_installs_and_its_daylight_saving_is_its_own(monkeypatch):
    monkeypatch.setenv("WARDEN_DISPLAY_ZONE", "America/New_York")
    assert both_times(datetime(2026, 11, 1, 5, 30, tzinfo=UTC)) == "2026-11-01 05:30:00Z (01:30 EDT)"
    assert both_times(datetime(2026, 11, 1, 7, 0, tzinfo=UTC)) == "2026-11-01 07:00:00Z (02:00 EST)"
    monkeypatch.setenv("WARDEN_DISPLAY_ZONE", "UTC")
    assert both_times(datetime(2026, 10, 3, 1, 0, tzinfo=UTC)) == "2026-10-03 01:00:00Z"
    monkeypatch.setenv("WARDEN_DISPLAY_ZONE", "Mars/Olympus")
    with pytest.raises(environments.EnvironmentPolicyError):
        both_times(datetime(2026, 10, 3, tzinfo=UTC))


def test_the_report_and_so_slack_show_both():
    r = run(Alert(**DEMO_ALERTS["inc-001"]), llm=LLMClient(mock=True))
    md = build_report(r.alert, root_cause=r.root_cause, proposal=r.proposal, verdict=r.verdict, context=r.context,
                      redaction_map=r.redaction_map, show_identifiers=False).markdown
    header = next(line for line in md.splitlines() if line.startswith("Severity"))
    assert "Z (" in header and "IST)" in header, header
    timeline = md.split("## Timeline", 1)[1].split("\n## ", 1)[0]
    assert timeline.count("IST)") >= 1 and "Z (" in timeline, timeline
