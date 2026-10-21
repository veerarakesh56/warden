"""The course docs keep their required sections: USE-CASE.md has Problem, Users, Success
criteria and Risks; the runbook has How to run, Monitoring, Known limitations and Escalation; and every page they link
inside the repository exists."""

from __future__ import annotations

import pathlib
import re
from urllib.parse import unquote

import pytest
from markdown_it import MarkdownIt

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

REQUIRED = {
    "USE-CASE.md": ("Problem", "Users", "Success criteria", "Risks"),
    "RUNBOOK.md": ("How to run", "Monitoring", "Known limitations", "Escalation"),
}


def _h2(name: str) -> list[str]:
    return re.findall(r"^## (.+?)\s*$", (DOCS / name).read_text(encoding="utf-8"), re.MULTILINE)


@pytest.mark.parametrize(("name", "headings"), sorted(REQUIRED.items()))
def test_the_required_h2_headings_are_there_in_order(name, headings):
    found = [h for h in _h2(name) if h in headings]
    assert found == list(headings), f"{name}: H2 headings {_h2(name)}"


def test_the_runbook_says_production_is_rules_only_until_requalified():
    text = (DOCS / "RUNBOOK.md").read_text(encoding="utf-8")
    limits = text.split("## Known limitations", 1)[1].split("\n## ", 1)[0]
    assert re.search(r"[Pp]roduction is rules-only until a model is qualified again", limits)
    assert "providers.yaml" in limits


def _link_targets(text: str) -> list[str]:
    """Every link and image target, parsed as CommonMark with tables (markdown-it-py, a declared dependency): inline
    links, reference-style links resolved through their definitions, and every definition, used or not."""
    md = MarkdownIt("commonmark").enable("table")
    env: dict = {}
    stack = md.parse(text, env)
    found = [str(ref["href"]) for ref in env.get("references", {}).values()]
    while stack:
        token = stack.pop()
        stack.extend(token.children or [])
        if token.type in ("link_open", "image"):
            found.append(str(token.attrGet("href") or token.attrGet("src") or ""))
    return found


def _missing_local(text: str) -> tuple[list[str], list[str]]:
    """The local targets (outside links and in-page anchors dropped), and those with no file under docs/."""
    local = [
        unquote(t.split("#", 1)[0])
        for t in _link_targets(text)
        if not t.startswith(("http://", "https://", "mailto:", "#"))
    ]
    return local, [t for t in local if t and not (DOCS / t).resolve().exists()]


def test_the_link_check_sees_inline_reference_and_table_links():
    text = (
        "[a](RUNBOOK.md) and [b][ref]\n\n| x |\n|---|\n| [d](gone-from-a-table.md) |\n\n"
        "[ref]: gone-by-reference.md\n[unused]: gone-unused.md\n"
    )
    _, missing = _missing_local(text)
    assert sorted(set(missing)) == [
        "gone-by-reference.md",
        "gone-from-a-table.md",
        "gone-unused.md",
    ]


@pytest.mark.parametrize("name", ["USE-CASE.md", "RUNBOOK.md", "COST.md", "DEMO.md"])
def test_every_relative_link_resolves(name):
    local, missing = _missing_local((DOCS / name).read_text(encoding="utf-8"))
    assert local
    assert missing == []


def test_the_readme_lists_the_course_docs():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for name in ("RUNBOOK.md", "USE-CASE.md", "COST.md", "DEMO.md"):
        assert f"(docs/{name})" in readme, name
