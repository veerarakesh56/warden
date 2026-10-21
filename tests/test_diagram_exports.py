"""Every diagram in docs/diagrams is a draw.io source with an SVG and a PNG export per page, and every SVG is an export
of its source as it is now, on a white page.

An SVG is matched to its source by name: `<name>.svg` is the one page of `<name>.drawio`, `<name>-<n>.svg` page n of a
source with several pages. It holds exactly the source page's cells (draw.io writes each cell's id as data-cell-id), so
a source changed without exporting again fails here. It was exported with --theme light: a white background, and no
colours that change in a dark theme. Every label it shows is its source cell's label as it is now.
"""

from __future__ import annotations

import html
import pathlib
import re
import xml.etree.ElementTree as ET

import pytest

DIAGRAMS = pathlib.Path(__file__).resolve().parents[1] / "docs" / "diagrams"
SVGS = sorted(DIAGRAMS.glob("*.svg"))


def _pages(source: pathlib.Path) -> list[ET.Element]:
    return ET.parse(source).getroot().findall("./diagram")


def _source_page(svg: pathlib.Path) -> ET.Element:
    single = DIAGRAMS / f"{svg.stem}.drawio"
    if single.exists():
        pages = _pages(single)
        assert len(pages) == 1, f"{single.name} has {len(pages)} pages: export them as {svg.stem}-<n>.svg"
        return pages[0]
    name, number = re.fullmatch(r"(.+)-(\d+)", svg.stem).groups()
    return _pages(DIAGRAMS / f"{name}.drawio")[int(number) - 1]


def _head(svg: pathlib.Path) -> str:
    text = svg.read_text(encoding="utf-8")
    return text[:text.index("<g")]


def test_there_is_a_diagram_for_every_export_and_an_export_for_every_page():
    assert len(SVGS) >= 7
    for source in DIAGRAMS.glob("*.drawio"):
        pages = _pages(source)
        names = [f"{source.stem}.svg"] if len(pages) == 1 else [f"{source.stem}-{i}.svg" for i in range(1, len(pages) + 1)]
        for name in names:
            assert (DIAGRAMS / name).exists(), name
            assert (DIAGRAMS / name).with_suffix(".png").exists(), name


@pytest.mark.parametrize("svg", SVGS, ids=[s.name for s in SVGS])
def test_the_svg_has_a_white_background(svg):
    head = _head(svg)
    assert "background-color: #FFFFFF" in head
    assert '<rect fill="#FFFFFF" width="100%" height="100%"' in head


@pytest.mark.parametrize("svg", SVGS, ids=[s.name for s in SVGS])
def test_the_svg_keeps_its_colours_in_a_dark_theme(svg):
    assert "color-scheme: light" in _head(svg)  # --theme light


@pytest.mark.parametrize("svg", SVGS, ids=[s.name for s in SVGS])
def test_the_svg_is_an_export_of_its_source_as_it_is_now(svg):
    page = _source_page(svg)
    assert page.find("./mxGraphModel").get("background") == "#FFFFFF"
    exported = set(re.findall(r'data-cell-id="([^"]+)"', svg.read_text(encoding="utf-8")))
    assert exported == {c.get("id") for c in page.iter("mxCell")} | {o.get("id") for o in page.iter("object")}


@pytest.mark.parametrize("svg", SVGS, ids=[s.name for s in SVGS])
def test_every_cell_of_the_source_has_an_id_of_its_own(svg):
    ids = [c.get("id") for c in _source_page(svg).iter("mxCell")] + [o.get("id") for o in _source_page(svg).iter("object")]
    assert sorted({i for i in ids if ids.count(i) > 1}) == []  # draw.io renumbers a repeated id when it exports


# draw.io ends every SVG with a link shown only by viewers without foreignObject support; it belongs to no cell.
_FALLBACK = '<switch><g requiredFeatures="http://www.w3.org/TR/SVG11/feature#Extensibility"/><a '


def _words(markup: str) -> str:
    """A label's text with markup and every space removed: draw.io re-flows labels into lines when it exports."""
    text = re.sub(r"<br\s*/?>", " ", markup or "")
    return re.sub(r"\s+", "", html.unescape(re.sub(r"<[^>]+>", " ", text)))


@pytest.mark.parametrize("svg", SVGS, ids=[s.name for s in SVGS])
def test_every_label_of_the_source_is_the_one_its_svg_shows(svg):
    """The same cell ids are not enough: a label edited in the source and not exported again still has its id."""
    text = svg.read_text(encoding="utf-8")
    assert text.count(_FALLBACK) == 1
    text = text[:text.index(_FALLBACK)]
    page = _source_page(svg)
    cells = [(c.get("id"), c.get("value")) for c in page.iter("mxCell")] + \
        [(o.get("id"), o.get("label")) for o in page.iter("object")]
    stale = []
    for cell_id, label in cells:
        if not _words(label):
            continue
        shown = re.search(rf'<g data-cell-id="{re.escape(cell_id)}">(.*?)(?=<g data-cell-id="|$)', text, re.DOTALL)
        if shown is None or _words(shown.group(1)) != _words(label):
            stale.append(cell_id)
    assert stale == []
