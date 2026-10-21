"""The course docs keep their required sections (FDE course, 2026-10-21): USE-CASE.md has Problem, Users, Success
criteria and Risks; the runbook has How to run, Monitoring, Known limitations and Escalation; and every page they link
inside the repository exists."""

from __future__ import annotations

import pathlib
import re

import pytest

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


@pytest.mark.parametrize("name", ["USE-CASE.md", "RUNBOOK.md", "COST.md", "DEMO.md"])
def test_every_relative_link_resolves(name):
    text = (DOCS / name).read_text(encoding="utf-8")
    targets = [
        t.split("#", 1)[0]
        for t in re.findall(r"\]\(([^)\s]+)\)", text)
        if not t.startswith(("http://", "https://", "#"))
    ]
    missing = [t for t in targets if t and not (DOCS / t).resolve().exists()]
    assert targets
    assert missing == []


def test_the_readme_lists_the_course_docs():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for name in ("RUNBOOK.md", "USE-CASE.md", "COST.md", "DEMO.md"):
        assert f"(docs/{name})" in readme, name
