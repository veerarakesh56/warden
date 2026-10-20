"""B5: docs/THREAT-MODEL.md claims a mitigation only with the file and the test that prove it. A cited test must exist
and not be skipped (judged as the register judges its evidence), a cited file or link must exist, and every threat
row says which of the three statuses it has - "planned" protects nothing, and a row that says "built and tested"
without a test is refused."""

from __future__ import annotations

import pathlib
import re

import pytest

from test_register import _skipped

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "THREAT-MODEL.md"
_TEST = re.compile(r"(tests/[\w/]+\.py)(?:::(test_\w+))?")
_LINK = re.compile(r"\]\(([^)\s#]+)(?:#[^)]*)?\)")
STATUSES = ("built and tested", "built, not proven live", "planned", "built", "partly built")


def _text() -> str:
    return DOC.read_text(encoding="utf-8") if DOC.is_file() else ""


def _threat_rows() -> list[list[str]]:
    """The rows of section 3's tables that carry a Status column."""
    section = _text().split("## 3. Threats and mitigations", 1)[-1].split("## 4.", 1)[0]
    out = []
    header: list[str] = []
    for line in section.splitlines():
        if not line.startswith("|") or re.fullmatch(r"\|[-| ]+\|", line):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        if cells[0] == "STRIDE":
            header = cells
        elif header and "Status" in header:
            out.append(cells)
    return out


def test_the_threat_model_covers_every_trust_boundary_and_the_planned_code_path():
    text = _text()
    for boundary in ("TB1", "TB2", "TB3", "TB4", "TB5", "TB6", "TB7", "TB8", "TB9", "TB10"):
        assert f"### {boundary}:" in text, boundary
    for word in ("Spoofing", "Tampering", "Repudiation", "Information disclosure", "Denial of service",
                 "Elevation of privilege"):
        assert word in text, word
    code_path = text.split("### TB10", 1)[-1].split("## 4.", 1)[0]
    for topic in ("GitHub App", "Prompt injection through findings", "Supply chain", "Privilege", "planned"):
        assert topic in code_path, topic


@pytest.mark.parametrize("ref", sorted({m.group(0) for m in _TEST.finditer(_text())}))
def test_every_cited_test_exists_and_is_not_skipped(ref):
    file, _, func = ref.partition("::")
    path = ROOT / file
    assert path.is_file(), ref
    if func:
        src = path.read_text(encoding="utf-8")
        m = re.search(rf"^((?:@.*\n)*)def {func}\(", src, re.MULTILINE)
        assert m, f"{ref} does not exist"
        assert not _skipped(file, src, m), f"{ref} is skipped (or may be, in CI)"


def test_every_link_resolves():
    broken = [t for t in _LINK.findall(_text()) if not t.startswith("https://") and not (DOC.parent / t).exists()]
    assert not broken, broken


def test_every_threat_row_has_a_status_and_a_tested_claim_cites_a_test():
    rows = _threat_rows()
    assert len(rows) > 30, len(rows)  # a table the reader skipped would pass vacuously
    bad = []
    for cells in rows:
        status = cells[-1].replace("**", "")
        if not status.startswith(STATUSES):
            bad.append(("no known status", cells[1][:60], status))
        if status.startswith("built and tested") and not _TEST.search(cells[-2]):
            bad.append(("tested without a test", cells[1][:60]))
    assert not bad, bad
