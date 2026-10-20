"""B33: the files a stranger reads before taking part - how to contribute, the code of conduct, how to report a
security problem, what WARDEN keeps - exist, say how to reach the owner only through GitHub (never an email
address), and link only to files that exist."""

from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FILES = ("CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md", "docs/DATA-RETENTION.md",
         ".github/pull_request_template.md", ".github/ISSUE_TEMPLATE/bug_report.md",
         ".github/ISSUE_TEMPLATE/feature_request.md")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_LINK = re.compile(r"\]\(([^)\s]+)\)")
_REFERENCE_LINK = re.compile(r"^ {0,3}\[[^\]]+\]:\s*<?([^\s>]+)>?", re.MULTILINE)  # [name]: target


def _text(rel: str) -> str:
    path = ROOT / rel
    return path.read_text(encoding="utf-8") if path.is_file() else ""


@pytest.mark.parametrize("rel", FILES)
def test_the_file_exists_and_holds_no_email_address(rel):
    text = _text(rel)
    assert text.strip(), f"{rel} is missing or empty"
    assert not _EMAIL.findall(text), (rel, _EMAIL.findall(text))


_REFERENCE_USE = re.compile(r"\]\[([^\]]*)\]")  # [text][label], or [label][] with the text as label
_REFERENCE_FULL = re.compile(r"\[([^\]]+)\]\[\]")
_REFERENCE_LABEL = re.compile(r"^ {0,3}\[([^\]]+)\]:", re.MULTILINE)


def _broken_links(text: str, base: pathlib.Path) -> list[str]:
    """Every link target that does not resolve to a file inside the repository, every external link that is not
    https, and every reference use whose label has no definition."""
    broken = []
    for target in _LINK.findall(text) + _REFERENCE_LINK.findall(text):
        if target.startswith(("https://", "#")):
            continue
        path = (base / target.split("#", 1)[0]).resolve()
        # http://, an absolute path, a `..` or a symlink out of the repository: none is a repository link.
        if target.startswith("http://") or not path.is_relative_to(ROOT.resolve()) or not path.exists():
            broken.append(target)
    defined = {label.strip().lower() for label in _REFERENCE_LABEL.findall(text)}
    used = [u.lower() for u in _REFERENCE_USE.findall(text) if u] + [u.lower() for u in _REFERENCE_FULL.findall(text)]
    broken += [f"[{u}] (no definition)" for u in used if u.strip() not in defined]
    return broken


@pytest.mark.parametrize("rel", FILES)
def test_every_relative_link_resolves(rel):
    assert not _broken_links(_text(rel), (ROOT / rel).parent), rel


@pytest.mark.parametrize("text", ["[a](http://example.org)", "[a](../../../etc/hostname)", "[a](/etc/hostname)",
                                  "[a](docs/NOPE.md)", "see [details][missing]", "see [nowhere][]",
                                  "[x]: http://example.org"])
def test_a_link_outside_the_repository_insecure_or_undefined_is_broken(text):
    assert _broken_links(text, ROOT)


def test_good_links_pass():
    text = "[a](SECURITY.md) [b](https://example.org) [c][home] [home][]\n\n[home]: https://example.org\n"
    assert _broken_links(text, ROOT) == []


def test_the_code_of_conduct_is_the_contributor_covenant_2_1_with_a_github_contact():
    text = _text("CODE_OF_CONDUCT.md")
    assert text.startswith("# Contributor Covenant Code of Conduct")
    assert "version 2.1" in text
    assert "https://www.contributor-covenant.org/version/2/1/code_of_conduct.html" in text
    assert "[INSERT CONTACT METHOD]" not in text
    assert "[SECURITY.md](SECURITY.md)" in text  # reports go through GitHub, as security reports do


def test_security_reports_go_through_github_private_reporting():
    text = _text("SECURITY.md")
    assert "private vulnerability reporting" in text
    assert "Report a vulnerability" in text
    assert "public issue" in text  # and the fallback asks only for a private channel
