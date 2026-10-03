"""Audit A-P-9: the compliance crosswalk names only register rows that exist, covers each framework part it claims,
and every gap it finds is a register row of its own (CW1-CW5)."""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = (ROOT / "docs" / "COMPLIANCE-CROSSWALK.md").read_text(encoding="utf-8")
ROW = re.compile(r"^\| ([A-Z][A-Za-z0-9-]*) \|", re.MULTILINE)


def _ids() -> set[str]:
    return {i for f in ("FAILURE-MODES.md", "AUDIT-2026-09-28.md", "REQUIREMENTS-TRACE.md")
            for i in ROW.findall((ROOT / "docs" / f).read_text(encoding="utf-8"))}


def test_every_row_the_crosswalk_cites_exists():
    body = DOC[:DOC.index("## Sources")]
    cited = set(re.findall(r"\b(A-P-\d+|CW\d+|[BCEHMNOQRS]\d{1,2}b?)\b", body))
    missing = cited - _ids()
    assert missing == set(), f"cited but not in any register: {sorted(missing)}"


def test_each_framework_part_is_covered():
    for part in ("GOVERN 1", "GOVERN 6", "MAP 5", "MEASURE 1", "MANAGE 4", "A.2", "A.10"):
        assert part in DOC, part
    for n in range(1, 11):
        assert f"ASI{n:02d}" in DOC, n
    for article in range(9, 16):
        assert re.search(rf"^\| {article} ", DOC, re.MULTILINE), article
    assert "Not legal advice" in DOC and "2 December 2027" in DOC


def test_every_gap_found_is_a_register_row():
    gaps = set(re.findall(r"\bCW\d+\b", DOC))
    assert gaps >= {"CW1", "CW2", "CW3", "CW4", "CW5"}
    assert gaps <= _ids()
