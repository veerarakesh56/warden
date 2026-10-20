"""B5: docs/THREAT-MODEL.md claims a mitigation only with the file and the test that prove it. A cited test must exist
and not be skipped (judged as the register judges its evidence), a cited file or link must exist, and every threat
row says which of the three statuses it has - "planned" protects nothing, and a row that says "built and tested"
without a test is refused."""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

from test_register import _SAFE_DECORATORS, _skipped

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "THREAT-MODEL.md"
_TEST = re.compile(r"(tests/[\w/]+\.py)::(test_\w+)")
# A test file named without its test: it would pass the file check and skip the existence and skip checks.
_BARE_TEST_FILE = re.compile(r"tests/[\w/]+\.py(?!::test_)")
# A repository path in inline code, e.g. `docs/safety-pins.sha256`: it must exist, as a link must.
_CODE_PATH = re.compile(r"`((?:docs|src|tests|terraform|iam|scripts|\.github)/[\w./-]+)`")
_LINK = re.compile(r"\]\(([^)\s#]+)(?:#[^)]*)?\)")
_IMPLEMENTATION_ROOTS = ("src", "terraform", "iam", "scripts", ".github", "k8s")
STATUSES = ("built and tested", "built, not proven live", "planned")  # the three the document states


def _text() -> str:
    return DOC.read_text(encoding="utf-8") if DOC.is_file() else ""


def _implements(cell: str) -> bool:
    """The cell links a file that exists under code or infrastructure, judged by where its link really resolves: a
    `../src/../README.md` is not code (PR 82 review). Each cell on its own, so no link is made across a boundary."""
    for target in _LINK.findall(cell):
        path = (DOC.parent / target).resolve()
        rel = path.relative_to(ROOT.resolve()) if path.is_relative_to(ROOT.resolve()) else None
        if rel is not None and rel.parts and rel.parts[0] in _IMPLEMENTATION_ROOTS and path.exists():
            return True
    return False


def test_an_implementation_link_counts_only_where_it_really_resolves():
    assert _implements("[gate.py](../src/warden/gate.py)")
    assert not _implements("[readme](../src/../README.md)")
    assert not _implements("[nothing](../src/warden/nope.py)")
    assert not _implements("see [x]")
    assert not _implements("(../src/warden/gate.py)")  # half a link, as two cells joined made one


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
            assert len(cells) == len(header) == 5, cells  # STRIDE, Threat, Mitigation, Evidence, Status
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
    src = path.read_text(encoding="utf-8")
    assert not _is_skipped(file, src, func), f"{ref} is skipped (or may be, in CI)"


def _is_skipped(file: str, src: str, func: str) -> bool:
    """The register's judgement, with the decorators read by the parser: a decorator over several lines, or a comment
    or blank line before `def`, hid them from a line pattern (PR 82 review)."""
    node = next((n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef) and n.name == func), None)
    assert node is not None, f"{file}::{func} does not exist"
    names = [ast.unparse(d.func if isinstance(d, ast.Call) else d) for d in node.decorator_list]
    if any(name not in _SAFE_DECORATORS for name in names):
        return True
    body = re.search(r"^()def " + re.escape(func) + r"\(", src, re.MULTILINE)  # its body, module marks and imports
    return _skipped(file, src, body)


@pytest.mark.parametrize("src", [
    "import pytest\n\n@pytest.mark.skipif(\n    True,\n    reason='x',\n)\ndef test_a():\n    pass\n",
    "import pytest\n\n@pytest.mark.skip\n# a comment\n\ndef test_a():\n    pass\n",
    "import pytest\n\ndef test_a():\n    pytest.skip('later')\n",
])
def test_a_skip_hidden_by_a_multi_line_decorator_or_a_comment_is_still_caught(src):
    assert _is_skipped("tests/x.py", src, "test_a")


def test_a_parametrized_test_is_not_taken_for_a_skipped_one():
    src = "import pytest\n\n@pytest.mark.parametrize(\n    'x', [1],\n)\ndef test_a(x):\n    pass\n"
    assert not _is_skipped("tests/x.py", src, "test_a")


def test_every_test_citation_names_its_test():
    """In the threat tables a test file is cited only with its test (the page links its own guard file, above)."""
    evidence = " ".join(cells[-2] for cells in _threat_rows())
    assert not _BARE_TEST_FILE.findall(evidence), _BARE_TEST_FILE.findall(evidence)


def test_every_link_and_every_path_in_inline_code_resolves():
    broken = [t for t in _LINK.findall(_text()) if not t.startswith("https://") and not (DOC.parent / t).exists()]
    broken += [t for t in _CODE_PATH.findall(_text()) if not (ROOT / t).exists()]
    assert not broken, broken


def test_every_threat_row_has_a_status_and_a_tested_claim_cites_a_test():
    rows = _threat_rows()
    assert len(rows) > 30, len(rows)  # a table the reader skipped would pass vacuously
    bad = []
    for cells in rows:
        status = cells[-1]
        if status not in STATUSES:
            bad.append(("no known status", cells[1][:60], status))
        if status != "planned" and not any(_implements(cell) for cell in cells[2:4]):
            bad.append(("built without the file that implements it", cells[1][:60]))
        if status == "built and tested" and not _TEST.search(cells[-2]):
            bad.append(("tested without a test", cells[1][:60]))
    assert not bad, bad
