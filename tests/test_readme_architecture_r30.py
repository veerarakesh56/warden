"""The whole-system diagram (docs/diagrams/system-modules.drawio, shown in the README and in docs/ARCHITECTURE.md) is
drawn from the code. Every module, file and activity it names exists, every activity the workflows run is on it, and
every command it names is one of the CLI's. Cells for open pull requests (ids starting "pr") name modules that live on
their branch; each says "open PR #n" and "not built"."""

from __future__ import annotations

import html
import pathlib
import re
import xml.etree.ElementTree as ET

from warden import activities

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "diagrams" / "system-modules.drawio"
CLASSES = (activities.IncidentActivities, activities.RemediationActivities, activities.DiscussActivities)


def _cells() -> list[ET.Element]:
    return ET.parse(SOURCE).getroot().findall(".//mxCell")


def _built() -> list[ET.Element]:
    """Every cell but the open pull requests' and the legend's."""
    return [c for c in _cells() if not c.get("id", "").startswith(("pr", "lg-"))]


def _plain(value: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", " ", re.sub(r"<br\s*/?>", "\n", value or "")))


def _defined() -> set[str]:
    return {name for cls in CLASSES for name, f in vars(cls).items() if hasattr(f, "__temporal_activity_definition")}


def test_every_module_the_diagram_names_exists():
    named = [n.strip() for c in _built() for block in re.findall(r"<i>(.*?)</i>", c.get("value", ""))
             for n in re.split(r",\s*", block)]
    assert len(named) > 40
    missing = []
    for n in named:
        if (ROOT / n).exists():  # a path: src/warden/data/, platforms/aws.py under src/warden is caught below
            continue
        stem = n[:-3] if n.endswith(".py") else n.split(".")[0]
        if not (ROOT / "src" / "warden" / f"{stem}.py").exists():
            missing.append(n)
    assert missing == []


def test_every_activity_is_on_the_diagram():
    text = "\n".join(_plain(c.get("value", "")) for c in _built())
    defined = _defined()
    assert len(defined) >= 30
    assert sorted(name for name in defined if not re.search(rf"\b{name}\b", text)) == []


def test_every_activity_box_names_real_activities():
    defined = _defined()
    boxes = [c for c in _built() if re.fullmatch(r"a-[a-z-]+", c.get("id", ""))]
    assert len(boxes) > 20
    for cell in boxes:
        title = re.search(r"<b[^>]*>(.*?)</b>", cell.get("value", "")).group(1)
        for name in re.split(r",\s*", re.sub(r"^\d+\s+", "", html.unescape(title))):
            assert name in defined, (cell.get("id"), name)


def test_every_command_it_names_is_the_cli_s():
    cli = (ROOT / "src" / "warden" / "cli.py").read_text(encoding="utf-8")
    commands = {cmd for c in _built() for cmd in re.findall(r"\bwarden ([a-z]+)\b", _plain(c.get("value", "")))}
    assert commands
    for cmd in commands:
        assert f'add_parser("{cmd}"' in cli, cmd


def test_open_pull_requests_are_marked():
    prs = [c for c in _cells() if c.get("id", "").startswith("pr") and c.get("vertex") == "1"
           and not c.get("id", "").endswith(("-i", "-w"))]
    assert prs
    for cell in prs:
        value = _plain(cell.get("value", ""))
        assert re.search(r"open PR #\d+", value), cell.get("id")
        assert "not built" in value, cell.get("id")


def test_the_readme_and_the_architecture_page_show_it():
    for page, link in ((ROOT / "README.md", "docs/diagrams/system-modules.svg"),
                       (ROOT / "docs" / "ARCHITECTURE.md", "diagrams/system-modules.svg")):
        text = page.read_text(encoding="utf-8")
        assert f"]({link})]({link})" in text, page.name  # the SVG shown, a click opens it full size
        assert "```mermaid" not in text, page.name
