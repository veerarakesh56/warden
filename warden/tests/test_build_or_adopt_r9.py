"""Ready-made tools are preferred, and every component WARDEN built says why. Held to the
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


def test_the_decisions_cite_no_unpublished_notes_and_answer_the_mcp_question():
    """The dated research notes are not published, so no decision may point a reader at one; the decision on the AWS
    MCP servers is still stated."""
    text = (ROOT / "docs" / "DESIGN-DECISIONS.md").read_text(encoding="utf-8")
    assert "docs/research/" not in text
    assert "AWS MCP servers or the Agent Toolkit: not adopted" in _section()
