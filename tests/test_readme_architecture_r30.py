"""Requirement R30: the README's whole-system diagram is drawn from the code. Every module, file and activity it
names exists; every activity both workflows run is on it; the sections it does not redraw say they predate v2."""

from __future__ import annotations

import pathlib
import re

from warden import activities

ROOT = pathlib.Path(__file__).resolve().parents[1]
README = ROOT / "README.md"


def _section() -> str:
    text = README.read_text(encoding="utf-8")
    return text[text.index("### 0. The whole system on one page"):text.index("### 1. One incident, end to end")]


def test_every_module_the_diagram_names_exists():
    named = [n for block in re.findall(r"<i>(.*?)</i>", _section()) for n in re.split(r",\s*", block)]
    assert len(named) > 30
    missing = []
    for n in named:
        n = n.strip()
        if n.startswith("warden ") or (ROOT / n).exists():  # a command of the warden CLI, or a path
            continue
        stem = n[:-3] if n.endswith(".py") else n.split(".")[0]
        if not (ROOT / "src" / "warden" / f"{stem}.py").exists():
            missing.append(n)
    assert missing == []


def test_every_activity_is_on_the_diagram_and_every_command_on_it_is_real():
    section = _section()
    defined = {name for cls in (activities.IncidentActivities, activities.RemediationActivities)
               for name, f in vars(cls).items() if hasattr(f, "__temporal_activity_definition")}
    assert len(defined) >= 14
    for name in defined:
        assert re.search(rf"\b{name}\b", section), name
    for cmd in re.findall(r"warden ([a-z]+)", section):
        assert f'add_parser("{cmd}"' in (ROOT / "src" / "warden" / "cli.py").read_text(encoding="utf-8"), cmd


def test_the_older_sections_say_they_predate_v2():
    text = README.read_text(encoding="utf-8")
    banner = text[text.index("## Architecture"):text.index("### 0. The whole system on one page")]
    assert "Section 0 is drawn from the v2 code" in banner and "Sections 1-10 predate v2" in banner
