"""Audit A-B-L14: a start time must be a real date and time with its zone."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from warden.cli import main
from warden.models import Alert, Severity


def _alert(started_at):
    return Alert(alert_id="a", name="n", severity=Severity.high, service="s", environment="dev", summary="x",
                 started_at=started_at)


@pytest.mark.parametrize("value", ["2026-13-45T99:99:99Z", "2026-02-30T10:00:00Z", "2026-09-01T10:00:00"])
def test_an_impossible_or_zoneless_start_time_is_refused(value):
    with pytest.raises(ValidationError):
        _alert(value)


@pytest.mark.parametrize("value", ["", "2026-09-01T10:00:00Z", "2026-09-01T15:30:00+05:30", "2026-09-01 10:00:00.5+00:00"])
def test_a_zoned_start_time_or_none_is_accepted(value):
    assert _alert(value).started_at == value


def test_the_cli_refuses_a_zoneless_start_time(capsys):
    assert main(["run", "--incident", "inc-002", "--started-at", "2026-09-01T10:00:00"]) == 2
    assert "needs a zone" in capsys.readouterr().err
