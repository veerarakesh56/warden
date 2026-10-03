"""Requirement R45: every researched AI failure mode is covered. The research's failure classes are held to the
register's coverage table: no class missing or renamed, and every row the table names exists in the register."""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAP = ROOT / "docs" / "research" / "2026-09-28" / "failure-mode-solution-map.md"
REGISTER = ROOT / "docs" / "FAILURE-MODES.md"


def _classes() -> dict[int, str]:
    text = MAP.read_text(encoding="utf-8")
    body = text[text.index("## Solutions per failure mode"):text.index("## Top 20")]
    return {int(n): name.rstrip(":") for n, name in re.findall(r"^(\d+)\. \*\*(.+?)\*\*", body, re.MULTILINE)}


def _coverage() -> dict[int, tuple[str, str]]:
    text = REGISTER.read_text(encoding="utf-8")
    body = text[text.index("## Research coverage"):]
    body = body[:body.index("\n## ", 1)]
    return {int(n): (name.strip(), rows.strip()) for n, name, rows in
            re.findall(r"^- \*\*(\d+)\. (.+?)\*\*: (.+)$", body, re.MULTILINE)}


def _register_ids() -> set[str]:
    text = REGISTER.read_text(encoding="utf-8")
    return set(re.findall(r"^\| ([A-Z][A-Za-z0-9]*) \|", text, re.MULTILINE))


def test_every_researched_failure_class_has_a_coverage_line():
    classes, covered = _classes(), _coverage()
    assert len(classes) >= 21, classes
    assert sorted(covered) == sorted(classes), set(classes) ^ set(covered)
    for n, name in classes.items():
        assert covered[n][0] == name, (n, name, covered[n][0])


def test_every_covering_row_exists_and_every_line_is_covered_or_reasoned():
    ids = _register_ids()
    for n, (name, rows) in _coverage().items():
        cited = re.findall(r"\b([A-Z]{1,2}\d+[a-z]?)\b", rows.split("n/a:")[0])
        assert cited or "n/a:" in rows, f"class {n} ({name}) is neither covered nor reasoned"
        if "n/a:" in rows:
            assert len(rows.split("n/a:", 1)[1].strip()) > 20, f"class {n}: an n/a needs its reason"
        for row in cited:
            assert row in ids, f"class {n} ({name}) cites {row}, which is not a register row"
