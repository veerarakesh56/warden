"""The security review pack (docs/SECURITY-REVIEW.md) and the egress page (docs/DATA-EGRESS.md) send a client's
security team to other documents: every link must land - a file that exists, a heading that exists - and every
statement about the model provider must link Anthropic's own page, dated."""

from __future__ import annotations

import pathlib
import re

import pytest

from test_community_files import _EMAIL, _broken_links

ROOT = pathlib.Path(__file__).resolve().parents[1]
REVIEW, EGRESS = "docs/SECURITY-REVIEW.md", "docs/DATA-EGRESS.md"
PAGES = (REVIEW, EGRESS)
PROVIDER_HEADING = "## The model provider"
OFFICIAL = re.compile(r"https://(?:www\.)?(?:[a-z]+\.)?(?:anthropic\.com|claude\.com)/")
_ANCHORED = re.compile(r"\]\(([^)\s#]*)#([^)\s]+)\)")
# A reference definition with an anchor: `[label]: FILE.md#heading` (or `<FILE.md#heading>`).
_ANCHORED_REFERENCE = re.compile(r"^ {0,3}\[[^\]]+\]:\s*<?([^\s>#]*)#([^\s>]+)>?", re.MULTILINE)
_URL = re.compile(r"\]\((https?://[^)\s]+)\)")


def _text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _slug(heading: str) -> str:
    """GitHub's anchor for a heading: lower case, punctuation dropped, spaces to hyphens."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def _anchors(path: pathlib.Path) -> set[str]:
    return {
        _slug(line.lstrip("#"))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith("#")
    }


def _broken_anchors(text: str, page: pathlib.Path) -> list[str]:
    """Every `file.md#anchor` (or `#anchor` on the page itself) whose heading does not exist."""
    broken = []
    for target, anchor in _ANCHORED.findall(text) + _ANCHORED_REFERENCE.findall(text):
        path = (page.parent / target).resolve() if target else page
        if target.startswith("http") or path.suffix != ".md":
            continue
        if anchor not in _anchors(path):
            broken.append(f"{target}#{anchor}")
    return broken


def _provider_section(text: str) -> str:
    start = text.index(PROVIDER_HEADING)
    end = text.find("\n## ", start + len(PROVIDER_HEADING))
    return text[start : end if end != -1 else len(text)]


@pytest.mark.parametrize("rel", PAGES)
def test_the_page_exists_and_holds_no_email_address(rel):
    text = _text(rel)
    assert text.strip(), rel
    assert not _EMAIL.findall(text), rel


@pytest.mark.parametrize("rel", PAGES)
def test_every_relative_link_resolves(rel):
    assert not _broken_links(_text(rel), (ROOT / rel).parent), rel


@pytest.mark.parametrize("rel", PAGES)
def test_every_anchor_names_a_heading_that_exists(rel):
    assert not _broken_anchors(_text(rel), ROOT / rel), rel


def test_a_wrong_anchor_is_caught():
    page = ROOT / REVIEW
    assert _broken_anchors("[a](ARCHITECTURE.md#no-such-heading)", page) == [
        "ARCHITECTURE.md#no-such-heading"
    ]
    assert _broken_anchors("[a](#nowhere)", page) == ["#nowhere"]


def test_a_wrong_anchor_in_a_reference_definition_is_caught():
    page = ROOT / REVIEW
    text = "see [the layers][src]\n\n[src]: ARCHITECTURE.md#no-such-heading\n"
    assert _broken_anchors(text, page) == ["ARCHITECTURE.md#no-such-heading"]


def _claims(section: str) -> list[str]:
    """The provider table's claim rows: every table row but the header and its separator."""
    rows = [line for line in section.splitlines() if line.startswith("|")]
    return rows[2:]


def _unsourced(section: str) -> list[str]:
    """Each claim row that links no official Anthropic page, and each link anywhere in the section that is not one."""
    bare = [
        row for row in _claims(section) if not any(OFFICIAL.match(u) for u in _URL.findall(row))
    ]
    return bare + [u for u in _URL.findall(section) if not OFFICIAL.match(u)]


def test_every_provider_claim_links_an_official_anthropic_page():
    section = _provider_section(_text(EGRESS))
    assert _claims(section), "the provider section holds no claim"
    assert _unsourced(section) == []


def test_the_provider_research_is_dated_before_its_first_claim():
    section = _provider_section(_text(EGRESS))
    before_claims = section.split("\n|", 1)[0]
    assert re.search(r"\b20\d\d-\d\d-\d\d\b", before_claims), "the research is not dated"


def test_a_claim_row_without_its_own_source_is_caught():
    section = (
        "| Question | Says | Source |\n|---|---|---|\n"
        "| a | x | [p](https://www.anthropic.com/legal/commercial-terms) |\n| b | y | none |\n"
    )
    assert _unsourced(section) == ["| b | y | none |"]


@pytest.mark.parametrize(
    "url",
    [
        "https://example.org/terms",
        "http://www.anthropic.com/legal/commercial-terms",
        "https://anthropic.com.evil.example/",
    ],
)
def test_a_link_that_is_not_anthropics_own_page_is_refused(url):
    assert not OFFICIAL.match(url)


def test_the_review_pack_stays_one_page():
    assert len(_text(REVIEW).splitlines()) <= 80
