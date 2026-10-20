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


def _text(rel: str) -> str:
    path = ROOT / rel
    return path.read_text(encoding="utf-8") if path.is_file() else ""


@pytest.mark.parametrize("rel", FILES)
def test_the_file_exists_and_holds_no_email_address(rel):
    text = _text(rel)
    assert text.strip(), f"{rel} is missing or empty"
    assert not _EMAIL.findall(text), (rel, _EMAIL.findall(text))


@pytest.mark.parametrize("rel", FILES)
def test_every_relative_link_resolves(rel):
    base = (ROOT / rel).parent
    broken = []
    for target in _LINK.findall(_text(rel)):
        if target.startswith(("https://", "#")):
            continue
        assert not target.startswith("http://"), (rel, target)  # an external link is https
        path = target.split("#", 1)[0]
        if not (base / path).exists():
            broken.append(target)
    assert not broken, (rel, broken)


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
