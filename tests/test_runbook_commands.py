"""Audit A-P-6: the runbook for incidents WARDEN itself causes names only commands that exist. Every `warden ...`
line in it is parsed by the real command line - stopped after parsing, so nothing runs - and must be accepted."""

from __future__ import annotations

import pathlib
import re
import shlex

import pytest

from warden import cli

RUNBOOK = pathlib.Path(__file__).resolve().parents[1] / "docs" / "RUNBOOK-WARDEN-INCIDENT.md"


class _Parsed(BaseException):  # not an Exception: main() must not swallow it
    pass


def _commands() -> list[str]:
    text = RUNBOOK.read_text(encoding="utf-8")
    blocks = re.findall(r"```\n(.*?)```", text, re.DOTALL)
    return [line.strip() for b in blocks for line in b.splitlines() if line.strip().startswith("warden ")]


def test_the_runbook_has_the_commands_an_on_call_engineer_needs():
    joined = "\n".join(_commands())
    for needed in ("warden killswitch on", "warden killswitch status", "warden audit verify", "warden audit show",
                   "warden status", "warden killswitch reset"):
        assert needed in joined, needed
    text = RUNBOOK.read_text(encoding="utf-8")
    for phase in ("Preparation", "Detection and analysis", "Containment, eradication and recovery",
                  "After the incident"):
        assert phase in text, phase


@pytest.mark.parametrize("command", _commands())
def test_every_command_in_the_runbook_parses(command, monkeypatch):
    def stop(self, args=None, namespace=None):
        parsed = original(self, args, namespace)
        raise _Parsed(parsed)

    original = cli._Parser.parse_args
    monkeypatch.setattr(cli._Parser, "parse_args", stop)
    argv = [a if not (a.startswith("<") and a.endswith(">")) else "x" for a in shlex.split(command)[1:]]
    argv = ["3" if prev == "--trips" else a for prev, a in zip(["", *argv[:-1]], argv, strict=True)]
    with pytest.raises(_Parsed):
        cli.main(argv)


def test_a_runbook_with_no_fix_command_does_not_say_wardens_actions_cannot_change_the_platform():
    """Live, 2026-10-12: above WARDEN's own plan to enable a rule, the runbook said "No action in WARDEN's closed set
    changes eventbridge directly". What is true is that the runbook prints no such command."""
    from warden import runbook
    from warden.models import ActionKind, Alert, Severity

    alert = Alert(alert_id="a", name="n", service="s", environment="dev", severity=Severity.high, summary="",
                  started_at="2026-10-12T17:18:59+00:00", labels={"eventbridge_rule": "warden-dev-lab-tick"})
    rb = runbook.Runbook(platform="eventbridge")
    runbook._reads_only(rb, alert, "eventbridge", ActionKind.revert_change)
    assert "closed set" not in rb.note and rb.note.startswith("This runbook prints no command that changes eventbridge")
    assert "comes as a fix plan to approve" in rb.note
