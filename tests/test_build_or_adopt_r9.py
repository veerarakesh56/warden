"""Requirements R9 and R57: ready-made tools are preferred, and every component WARDEN built says why. Held to the
code: a new module without a line in DESIGN-DECISIONS section 17 fails here, so "built" is never silent."""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _section() -> str:
    text = (ROOT / "docs" / "DESIGN-DECISIONS.md").read_text(encoding="utf-8")
    start = text.index("## 17. Built or adopted")
    end = text.find("\n## ", start + 1)
    return text[start:end if end != -1 else None]


def test_every_module_is_named_as_adopted_or_built():
    section = _section()
    named = set(re.findall(r"`([a-z0-9_]+\.py)`", section))
    modules = {p.name for p in (ROOT / "src" / "warden").glob("*.py") if p.name != "__init__.py"}
    assert modules - named == set(), f"modules with no build-or-adopt line: {sorted(modules - named)}"
    assert named - modules == set(), f"lines for modules that no longer exist: {sorted(named - modules)}"


def test_the_decisions_cite_their_dated_research_and_answer_r57():
    section = _section()
    for note in re.findall(r"`(docs/research/[^`]+\.md)`", section):
        assert (ROOT / note).is_file(), note
    assert "docs/research/2026-10-03/build-or-adopt.md" in section
    assert "docs/research/2026-10-03/aws-mcp-servers.md" in section
    assert "(R57): not adopted" in section
