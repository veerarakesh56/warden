"""Registers H4, H5 and audit rows CW1-CW5: the governance documents exist, say what their rows require, cite only
register rows that exist, name only `warden` commands the command line accepts, and give every RACI activity exactly
one accountable role."""

from __future__ import annotations

import pathlib
import re
import shlex

import pytest

from warden import cli

ROOT = pathlib.Path(__file__).resolve().parents[1]
GOV = ROOT / "docs" / "governance"
REQUIRED = {
    "AI-POLICY.md": ["## Purpose and scope", "## Principles", "## Prohibited uses", "## Change control", "## Review"],
    "RACI.md": ["accountable", "| Activity |"],
    "GAME-DAY.md": ["## When", "## How", "## What counts", "## Record", "warden killswitch on"],
    "IMPACT-ASSESSMENT.md": ["## Who is affected", "## Benefits", "## Harms, and what holds each",
                             "## Regulatory position"],
    "CONCERNS.md": ["## How", "## What happens", "warden-concern", "SECURITY.md"],
    "TECHNICAL-DOCUMENTATION.md": ["## Annex IV, part by part", "## Instructions for use"],
    "ENVIRONMENT.md": ["## What WARDEN measures itself", "## What the account reports", "warden usage"],
}
ROW = re.compile(r"^\| ([A-Z][A-Za-z0-9-]*) \|", re.MULTILINE)


def _text(name: str) -> str:
    return (GOV / name).read_text(encoding="utf-8")


def test_every_governance_document_says_what_its_row_requires():
    for name, needed in REQUIRED.items():
        text = _text(name)
        for part in needed:
            assert part in text, (name, part)
    assert (ROOT / "SECURITY.md").read_text(encoding="utf-8").startswith("# Security policy")


def test_every_raci_activity_has_exactly_one_accountable_role():
    rows = [r for r in _text("RACI.md").splitlines() if r.startswith("| ") and not r.startswith(("| Activity", "|---"))]
    assert len(rows) >= 10
    for row in rows:
        cells = [c.strip() for c in row.strip("|").split("|")]
        assert cells[1:].count("A") == 1, row


def test_every_register_row_cited_exists():
    ids = {i for f in ("FAILURE-MODES.md", "AUDIT-2026-09-28.md", "REQUIREMENTS-TRACE.md")
           for i in ROW.findall((ROOT / "docs" / f).read_text(encoding="utf-8"))}
    for name in REQUIRED:
        cited = set(re.findall(r"(?<![\w-])(R\d+-O\d+|A-P-\d+|CW\d+|[BCEHMNOQRS]\d{1,2}b?)\b", _text(name)))
        assert cited - ids == set(), (name, sorted(cited - ids))


class _Parsed(BaseException):
    pass


def _commands() -> list[str]:
    blocks = [b for name in REQUIRED for b in re.findall(r"```\n(.*?)```", _text(name), re.DOTALL)]
    return [line.strip() for b in blocks for line in b.splitlines() if line.strip().startswith("warden ")]


@pytest.mark.parametrize("command", _commands())
def test_every_command_in_them_parses(command, monkeypatch):
    original = cli._Parser.parse_args

    def stop(self, args=None, namespace=None):
        raise _Parsed(original(self, args, namespace))

    monkeypatch.setattr(cli._Parser, "parse_args", stop)
    argv = [a if not (a.startswith("<") and a.endswith(">")) else "x" for a in shlex.split(command)[1:]]
    argv = ["3" if prev == "--trips" else a for prev, a in zip(["", *argv[:-1]], argv, strict=True)]
    with pytest.raises(_Parsed):
        cli.main(argv)
