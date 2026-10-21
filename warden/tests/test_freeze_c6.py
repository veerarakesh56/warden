"""Register C6: no remediation is applied inside a change freeze (P19-FREEZE), at the gate and right before apply."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from temporalio.exceptions import ApplicationError

from test_apply_reverifies import _acts, _approve
from test_remediation_workflow import REQ
from warden import freeze
from warden.activities import FixRequest


def _file(tmp_path, *windows):
    import json

    path = tmp_path / "freeze.yaml"
    path.write_text("windows: " + json.dumps(list(windows)), encoding="utf-8")
    return str(path)


def _around_now(zone="Asia/Kolkata", environments=("dev",)):
    from zoneinfo import ZoneInfo

    local = datetime.now(UTC).astimezone(ZoneInfo(zone)).replace(tzinfo=None)
    return {"name": "release", "environments": list(environments), "zone": zone,
            "start": (local - timedelta(hours=1)).isoformat(timespec="minutes"),
            "end": (local + timedelta(hours=1)).isoformat(timespec="minutes")}


def test_a_window_covers_only_its_environments_and_its_hours(tmp_path):
    path = _file(tmp_path, _around_now())
    now = datetime.now(UTC)
    assert freeze.active("dev", now, path=path)[0].startswith("P19-FREEZE: dev is in the change freeze 'release'")
    assert freeze.active("prod", now, path=path) == []
    assert freeze.active("dev", now + timedelta(hours=3), path=path) == []


def test_a_window_across_a_daylight_saving_change_ends_when_it_says():
    """New York falls back at 02:00 on 2026-11-01: 03:00 that morning is 08:00 UTC, not 07:00."""
    window = {"name": "night", "environments": ["dev"], "zone": "America/New_York",
              "start": "2026-11-01T00:30", "end": "2026-11-01T03:00"}
    import json
    import pathlib
    import tempfile

    path = pathlib.Path(tempfile.mkdtemp()) / "freeze.yaml"
    path.write_text("windows: " + json.dumps([window]), encoding="utf-8")
    assert freeze.active("dev", datetime(2026, 11, 1, 7, 30, tzinfo=UTC), path=str(path))
    assert freeze.active("dev", datetime(2026, 11, 1, 8, 30, tzinfo=UTC), path=str(path)) == []
    assert freeze.active("dev", datetime(2026, 11, 1, 4, 0, tzinfo=UTC), path=str(path)) == []


@pytest.mark.parametrize("bad", [{"name": "x", "environments": ["dev"], "zone": "Mars/Olympus",
                                  "start": "2026-01-01T00:00", "end": "2027-01-01T00:00"},
                                 {"name": "y", "environments": ["dev"], "zone": "UTC", "start": "soon"}])
def test_a_window_that_cannot_be_read_refuses_the_change(tmp_path, bad):
    assert "cannot be read" in freeze.active("prod", datetime.now(UTC), path=_file(tmp_path, bad))[0]


def test_the_gate_refuses_a_plan_in_a_freeze(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_FREEZE_FILE", _file(tmp_path, _around_now()))
    acts, _, _ = _acts()
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert any(r.startswith("P19-FREEZE") for r in acts.gate(plan, REQ["service"]))


def test_a_freeze_that_starts_after_the_approval_stops_the_apply(tmp_path, monkeypatch):
    acts, platform, owner = _acts()
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert acts.gate(plan, REQ["service"]) == []
    assert _approve(acts, owner, plan, "rem-1").enough
    assert acts.precheck(plan) == []
    monkeypatch.setenv("WARDEN_FREEZE_FILE", _file(tmp_path, _around_now()))
    with pytest.raises(ApplicationError):
        acts.apply(plan, REQ["service"])
    assert platform.applied == []
