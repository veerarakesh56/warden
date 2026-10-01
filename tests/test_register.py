"""Nothing is "done" without evidence (owner, 2026-09-28).

On 2026-09-28 v0.10.0 was announced as "Phase 2 done" while 21 of the 22 register rows for that phase
were still open. This test makes that impossible to repeat. It reads every register table (the
failure-mode register, the audit, the requirements trace) and fails when:
- a row claims DONE-local but cites no test, or a test that does not exist, or one that is skipped;
- a row claims DONE-live without naming the window;
- a row is DEFERRED without the owner's recorded agreement;
- a row is still open although its work group is at or before CURRENT_GROUP.
"""

from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
REGISTERS = ("docs/FAILURE-MODES.md", "docs/AUDIT-2026-09-28.md", "docs/REQUIREMENTS-TRACE.md")
ORDER = ("G0", "W0-now", "G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8")
CURRENT_GROUP = "G0"  # advance only when every row of the group is closed
STATUSES = {"OPEN", "DONE-local", "DONE-live", "DEFERRED", "WITHHELD"}
CLOSED = {"DONE-local", "DONE-live", "DEFERRED"}
# A real window of the plan, and the date it ran. `\bW[\w-]+` let "Worked on my machine" and an invented
# "W-research" through (second independent review, 2026-09-30).
WINDOWS = ("W-T", "W0-now", "W0", "W-B", "W1", "W2", "W3")
# The cell must START with the window and the date it ran (third review, 2026-09-30: "not W0 ...",
# "W1 is planned for 2027-02-01" and "W3 9999-99-99" all passed a search anywhere in the cell).
WINDOW = re.compile(r"^(?:" + "|".join(re.escape(w) for w in WINDOWS) + r") (\d{4}-\d{2}-\d{2})\b")
TEST_REF = re.compile(r"(tests/[\w/]+\.py)::(test_\w+)")
# A citation of either form: `tests/x.py::test_a`, or the shorthand `::test_b` for the file cited last.
_ANY_REF = re.compile(r"(tests/[\w/]+\.py)?(?<![\w.])::(test_\w+)|(tests/[\w/]+\.py)::(test_\w+)")
# A citation the cell itself says does NOT cover the row: "NOT covered: tests/...", "no test: ...".
_NEGATION = re.compile(r"\b(?:not|no|without|missing|lacks?|gap)\b[^.;]{0,40}$", re.IGNORECASE)
# Decorators that never skip a test. Any other one - an alias imported from a helper module - might.
_SAFE_DECORATORS = frozenset({"pytest.mark.parametrize", "pytest.mark.asyncio", "pytest.mark.timeout",
                              "pytest.mark.filterwarnings"})


def _cells(line: str) -> list[str]:
    """A table line's cells. `\\|` is a pipe inside a cell, as GitHub reads it."""
    return [c.strip() for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]


_DELIMITER = re.compile(r"\s*\|?\s*:?-+:?\s*(\|\s*:?-*:?\s*)*\|?\s*")


def rows(text: str, malformed: list[str] | None = None) -> list[dict[str, str]]:
    """Every row of every markdown table, read as GitHub reads tables: a header line, a delimiter line, then
    every following non-blank line - with or without a leading pipe, indented or not - until a blank line or a
    heading or quote (sixth review, 2026-10-01: only lines starting with `|` were read, so a row GitHub showed
    could be invisible here). In the registers every table is a register table: one without Group and Status
    columns, and a row whose cells do not match its header, are reported in `malformed` (fifth review: an
    unescaped `||` split a cell and the row was dropped without a word)."""
    out: list[dict[str, str]] = []
    # Lines end only at a line feed, and blank means spaces and tabs only, as in GitHub's renderer: splitlines() and
    # str.strip() also break on U+2028, U+0085, VT, FF and the separators, and called an NBSP line blank - one such
    # character after a row hid every later row (seventh review, 2026-10-01). The registers carry none at all
    # (test_the_registers_hold_no_invisible_line_breaks); this keeps the parser honest if one gets in.
    lines = text.replace("\r\n", "\n").split("\n")
    header: list[str] | None = None
    i = 0
    while i < len(lines):
        line = lines[i]
        if header is None:
            if "|" in line and i + 1 < len(lines) and _DELIMITER.fullmatch(lines[i + 1]):
                header = _cells(line)
                if not ("Group" in header and "Status" in header) and malformed is not None:
                    malformed.append(f"a table without Group and Status columns: {line.strip()[:60]}")
                i += 2
                continue
            i += 1
            continue
        if not line.strip(" \t") or _ENDS_TABLE.match(line):
            header = None
            i += 1
            continue
        cells = _cells(line)
        if "Group" in header and "Status" in header:
            if len(cells) == len(header):
                out.append(dict(zip(header, cells, strict=True)))
            elif malformed is not None:
                malformed.append(line.strip()[:80])
        i += 1
    return out


# What ends a table: an ATX heading (`#` to `######` then a space or the end) or a block quote. `#X-2 | ...` is a
# row in GitHub's renderer, not a heading.
_ENDS_TABLE = re.compile(r" {0,3}(?:#{1,6}(?:[ \t]|$)|>)")


def all_rows() -> list[tuple[str, dict[str, str]]]:
    found = []
    for rel in REGISTERS:
        path = ROOT / rel
        assert path.exists(), f"{rel} is missing"
        found += [(rel, r) for r in rows(path.read_text(encoding="utf-8"))]
    return found


# Module-level skips that CI does NOT hit, each with its reason. Anything else skipping is refused.
SKIP_OK = {
    "tests/test_fullstack_infra.py": "skips only when terraform/fullstack is absent; it is in this repository",
    "tests/test_providers.py": ("skips (module and in-test importorskip) only without a provider extra; CI's unit job "
                                "installs them: uv sync --locked --extra dev --extra all-providers ..."),
}


def _skipped(file: str, src: str, m: re.Match) -> bool:
    """Skipped - or expected to fail - directly, through any decorator that is not known never to skip,
    by a module-level `pytestmark` (one line or many), or by `importorskip`, `skip(` or `xfail(` in its
    body or at module level. Third review (2026-09-30): an alias, a module mark and an importorskip in
    the body all passed a check for the word "skip" above the function; fourth review: a module-level
    importorskip, a multi-line pytestmark list, `from pytest import mark`, a helper-module alias and
    xfail still did."""
    decorators = re.findall(r"^@([\w.]+)", m.group(1), re.MULTILINE)
    if any(d not in _SAFE_DECORATORS for d in decorators):
        return True
    body = src[m.end():]
    nxt = re.search(r"^(?:def |class |@)", body, re.MULTILINE)
    body = body[:nxt.start() if nxt else len(body)]
    if re.search(r"\bskip\(|\bxfail\(", body):
        return True
    if file in SKIP_OK:   # its importorskip is excused, with the reason given there; nothing else is
        return False
    if "importorskip(" in body:
        return True
    module_mark = re.search(r"^pytestmark\s*=.*(?:\n[ \t\])].*)*", src, re.MULTILINE)
    if module_mark and re.search(r"skip|xfail", module_mark.group(0)):
        return True
    return bool(re.search(r"^\S.*(?:importorskip\(|\bskip\(|\bxfail\()", src, re.MULTILINE))


def cited_tests() -> set[tuple[str, str]]:
    """(file, test) for every test a DONE-local row cites as evidence (negated citations excluded)."""
    cited: set[tuple[str, str]] = set()
    for _, row in all_rows():
        if row["Status"] != "DONE-local":
            continue
        evidence, last = row.get("Evidence", ""), None
        for ref in _ANY_REF.finditer(evidence):
            file = ref.group(1) or ref.group(3) or last
            last = file
            if file and not _NEGATION.search(evidence[max(0, ref.start() - 60):ref.start()]):
                cited.add((file, ref.group(2) or ref.group(4)))
    return cited


def _real_window(evidence: str) -> bool:
    import datetime as dt

    m = WINDOW.match(evidence.strip())
    if not m:
        return False
    try:
        day = dt.date.fromisoformat(m.group(1))
    except ValueError:
        return False
    return day <= dt.datetime.now(dt.UTC).date()


def _agreed(evidence: str) -> bool:
    """The cell STARTS with the agreement and its real, past date (fourth review, 2026-09-30: "NOT
    owner-agreed ...", "owner-agreed 9999-99-99" and planned dates passed a search anywhere)."""
    import datetime as dt

    m = re.match(r"owner-agreed (\d{4}-\d{2}-\d{2})\b", evidence.strip())
    try:
        return bool(m) and dt.date.fromisoformat(m.group(1)) <= dt.datetime.now(dt.UTC).date()
    except ValueError:
        return False


def problems(rel: str, row: dict[str, str], current: str = CURRENT_GROUP) -> list[str]:
    rid = next(iter(row.values()))
    status, group, evidence = row["Status"], row["Group"], row.get("Evidence", "")
    where = f"{rel} {rid}"
    if status not in STATUSES:
        return [f"{where}: unknown status {status!r}"]
    if group not in ORDER:
        return [f"{where}: unknown group {group!r}"]
    found = []
    if status == "DONE-local":
        refs, last = [], None
        for ref in _ANY_REF.finditer(evidence):
            file = ref.group(1) or ref.group(3) or last
            func = ref.group(2) or ref.group(4)
            last = file
            if file is None:
                found.append(f"{where}: ::{func} names no file")
            elif _NEGATION.search(evidence[max(0, ref.start() - 60):ref.start()]):
                found.append(f"{where}: {file}::{func} is cited as NOT covering the row")
            else:
                refs.append((file, func))
        if not refs:
            found.append(f"{where}: DONE-local cites no test")
        for file, func in refs:
            path = ROOT / file
            src = path.read_text(encoding="utf-8") if path.exists() else ""
            m = re.search(rf"^((?:@.*\n)*)def {func}\(", src, re.MULTILINE)
            if not m:
                found.append(f"{where}: cited test {file}::{func} does not exist")
            elif _skipped(file, src, m):
                found.append(f"{where}: cited test {file}::{func} is skipped (or may be, in CI)")
    if status == "DONE-live" and not _real_window(evidence):
        found.append(f"{where}: DONE-live must name the window")
    if status == "DEFERRED" and not _agreed(evidence):
        found.append(f"{where}: DEFERRED must start with 'owner-agreed YYYY-MM-DD', a real past date")
    if status not in CLOSED and ORDER.index(group) <= ORDER.index(current):
        found.append(f"{where}: still {status} but group {group} is at or before {current}")
    return found


def test_every_register_row_is_backed_by_evidence():
    found = [p for rel, row in all_rows() for p in problems(rel, row)]
    assert not found, "\n".join(found)


def test_no_register_row_is_dropped_for_its_shape():
    malformed: list[str] = []
    for rel in REGISTERS:
        rows((ROOT / rel).read_text(encoding="utf-8"), malformed)
    assert not malformed, malformed


def test_a_row_split_by_a_pipe_is_reported_not_dropped():
    table = "| ID | Group | Status | Evidence |\n|---|---|---|---|\n| X | G1 | OPEN | `a||b` |\n"
    malformed: list[str] = []
    assert rows(table, malformed) == [] and malformed
    escaped = table.replace("a||b", "a\\|\\|b")
    assert rows(escaped)[0]["Evidence"] == "`a\\|\\|b`"


def test_the_registers_are_parsed_at_all():
    parsed = all_rows()
    assert len(parsed) > 150, len(parsed)  # a table the parser silently skips would pass vacuously
    assert {rel for rel, _ in parsed} == set(REGISTERS)


@pytest.mark.parametrize("row,expect", [
    ({"#": "X", "Group": "G1", "Status": "DONE-local", "Evidence": "tests/test_register.py::test_nope"},
     "does not exist"),
    ({"#": "X", "Group": "G1", "Status": "DONE-local", "Evidence": "trust me"}, "cites no test"),
    ({"#": "X", "Group": "G1", "Status": "DEFERRED", "Evidence": "later"}, "owner-agreed"),
    ({"#": "X", "Group": "G1", "Status": "DONE-live", "Evidence": "it worked"}, "name the window"),
    ({"#": "X", "Group": "G1", "Status": "DONE-live", "Evidence": "Worked on my machine 2026-09-30"}, "name the window"),
    ({"#": "X", "Group": "G1", "Status": "DONE-live", "Evidence": "W-research 2026-09-28"}, "name the window"),
    ({"#": "X", "Group": "G1", "Status": "DONE-live", "Evidence": "W1 with no date"}, "name the window"),
    ({"#": "X", "Group": "G1", "Status": "DONE-live", "Evidence": "W1 is planned for 2027-02-01, not run yet"},
     "name the window"),
    ({"#": "X", "Group": "G1", "Status": "DONE-live", "Evidence": "not W0 - see review 2026-09-30"}, "name the window"),
    ({"#": "X", "Group": "G1", "Status": "DONE-live", "Evidence": "W3 9999-99-99"}, "name the window"),
    ({"#": "X", "Group": "G1", "Status": "DONE-live", "Evidence": "window W2 (G6) 2026-13-45"}, "name the window"),
    ({"#": "X", "Group": "G1", "Status": "DONE-live", "Evidence": "W1 2099-01-01: from the future"}, "name the window"),
    ({"#": "X", "Group": "G0", "Status": "OPEN", "Evidence": ""}, "at or before"),
    ({"#": "X", "Group": "G0", "Status": "done", "Evidence": ""}, "unknown status"),
])
def test_a_claim_without_evidence_is_caught(row, expect):
    """Plant check built in: each way of faking "done" is refused."""
    assert any(expect in p for p in problems("x.md", row, current="G0"))


def test_an_open_row_in_a_later_group_is_allowed():
    assert problems("x.md", {"#": "X", "Group": "G5", "Status": "OPEN", "Evidence": ""}, current="G0") == []



def test_a_real_window_and_a_past_date_pass():
    assert problems("x.md", {"#": "X", "Group": "G1", "Status": "DONE-live",
                             "Evidence": "W-T 2026-09-28: namespace active"}, current="G0") == []


@pytest.mark.parametrize("src", [
    "import pytest\nneeds_pg = pytest.mark.skipif(True, reason='x')\n\n@needs_pg\ndef test_a():\n    pass\n",
    "import pytest\npytestmark = pytest.mark.skipif(True, reason='x')\n\ndef test_a():\n    pass\n",
    "import pytest\n\ndef test_a():\n    pytest.importorskip('psycopg')\n",
])
def test_a_test_skipped_by_alias_module_mark_or_importorskip_is_not_evidence(src):
    """Third review (2026-09-30): each of these passed a check for the word "skip" above the function."""
    m = re.search(r"^((?:@.*\n)*)def test_a\(", src, re.MULTILINE)
    assert _skipped("tests/x.py", src, m)
    plain = "import pytest\n\ndef test_a():\n    pass\n"
    assert not _skipped("tests/x.py", plain, re.search(r"^((?:@.*\n)*)def test_a\(", plain, re.MULTILINE))


@pytest.mark.parametrize("src", [
    "import pytest\nopt = pytest.importorskip('psycopg')\n\ndef test_a():\n    pass\n",
    "import pytest\npytestmark = [\n    pytest.mark.skipif(True, reason='x'),\n]\n\ndef test_a():\n    pass\n",
    "from pytest import mark\nneeds = mark.skipif(True, reason='x')\n\n@needs\ndef test_a():\n    pass\n",
    "from helpers import needs_pg\n\n@needs_pg\ndef test_a():\n    pass\n",
    "import pytest\n\n@pytest.mark.xfail\ndef test_a():\n    pass\n",
    "import pytest\n\ndef test_a():\n    pytest.xfail('later')\n",
])
def test_a_module_level_multi_line_aliased_or_xfail_skip_is_not_evidence(src):
    """Fourth review (2026-09-30, D #3): each of these passed the third review's guard."""
    m = re.search(r"^((?:@.*\n)*)def test_a\(", src, re.MULTILINE)
    assert _skipped("tests/x.py", src, m)


def test_a_parametrized_test_is_still_evidence():
    src = "import pytest\n\n@pytest.mark.parametrize('x', [1])\ndef test_a(x):\n    pass\n"
    assert not _skipped("tests/x.py", src, re.search(r"^((?:@.*\n)*)def test_a\(", src, re.MULTILINE))


@pytest.mark.parametrize(("evidence", "expect"), [
    ("NOT covered: tests/test_register.py::test_the_registers_are_parsed_at_all", "NOT covering"),
    ("no test yet - tests/test_register.py::test_the_registers_are_parsed_at_all", "NOT covering"),
    ("::test_the_registers_are_parsed_at_all", "names no file"),
    ("tests/test_register.py::test_the_registers_are_parsed_at_all, ::test_nothing_here", "does not exist"),
])
def test_a_negated_or_dangling_citation_is_not_evidence(evidence, expect):
    row = {"#": "X", "Group": "G1", "Status": "DONE-local", "Evidence": evidence}
    assert any(expect in p for p in problems("r", row, current="G0")), problems("r", row, current="G0")


@pytest.mark.parametrize("evidence", ["NOT owner-agreed 2026-09-01", "owner-agreed 9999-99-99",
                                      "owner-agreed 2099-01-01", "later; owner-agreed 2026-09-01"])
def test_a_deferral_needs_a_real_past_agreement_first(evidence):
    row = {"#": "X", "Group": "G1", "Status": "DEFERRED", "Evidence": evidence}
    assert any("owner-agreed" in p for p in problems("r", row, current="G0"))


def test_a_skip_allowed_in_ci_is_still_installed_there():
    """SKIP_OK's reason for test_providers.py holds only while CI's unit job installs the extras."""
    ci = (ROOT / ".github/workflows/ci-tool.yml").read_text(encoding="utf-8")
    assert re.search(r"uv sync --locked --extra dev --extra all-providers", ci), "CI no longer installs the provider extras"


def test_rows_github_shows_are_read_whatever_their_pipes():
    """Sixth review (2026-10-01): an indented row, a row with no leading pipe and a renamed header all
    rendered on GitHub and were invisible to the guard."""
    table = ("| ID | Finding | Group | Status | Evidence |\n|---|---|---|---|---|\n"
             "| X-1 | a | G1 | OPEN | e |\n  | X-2 | b | G1 | OPEN | e |\nX-3 | c | G0 | OPEN | e |\n"
             "X-4 | d | G1 | done | e\n\nafter the table\n")
    bad: list[str] = []
    assert [r["ID"] for r in rows(table, bad)] == ["X-1", "X-2", "X-3", "X-4"] and bad == []
    renamed = "| ID | Finding | Group | State | Evidence |\n|---|---|---|---|---|\n| X-5 | e | G0 | OPEN | e |\n"
    rows(renamed, bad)
    assert bad and "without Group and Status" in bad[0]


def test_rows_end_where_githubs_tables_end():
    """Seventh review (2026-10-01): an invisible line break or an NBSP line ended the table here while GitHub kept
    showing the rows after it; a `#` row without a space did too."""
    head = "| ID | Group | Status | Evidence |\n|---|---|---|---|\n| A-1 | G1 | DONE-local | x |"
    for sep in ("\u2028", "\u0085", "\x0b", "\x0c", "\x1c", "\x1e"):
        got = rows(head + sep + "\n| A-2 | G1 | OPEN | y |")
        assert "A-2" in [r["ID"] for r in got], (repr(sep), got)  # the row after it is still read
    assert [r["ID"] for r in rows(head + "\n#X-2 | G1 | OPEN | y |")] == ["A-1", "#X-2"]
    assert [r["ID"] for r in rows(head + "\n## Next\n| A-3 | G1 | OPEN | z |")] == ["A-1"]  # a real heading ends it
    malformed: list[str] = []
    rows(head + "\n\u00a0\n| A-2 | G1 | OPEN | y |", malformed)  # an NBSP line is a row, not a blank: reported
    assert malformed


def test_the_registers_hold_no_invisible_line_breaks():
    """No C0 control but tab and line feed, no C1, no U+2028/U+2029, no NBSP-family line in any register: each hid
    rows from this parser while GitHub showed them (seventh review)."""
    bad = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029]")
    for rel in REGISTERS:
        text = (ROOT / rel).read_text(encoding="utf-8").replace("\r\n", "\n")
        found = [(n, repr(m.group())) for n, line in enumerate(text.split("\n"), 1) for m in bad.finditer(line)]
        assert not found, (rel, found[:5])


def test_the_registers_hold_no_table_the_parser_cannot_read():
    """Eighth review (2026-10-01): GitHub shows a table inside a block quote and a raw HTML table; rows() reads
    neither - planted on the real AUDIT, a quoted row set to DONE-local with Evidence "trust me" passed every check."""
    for rel in REGISTERS:
        text = (ROOT / rel).read_text(encoding="utf-8").replace("\r\n", "\n")
        quoted = [n for n, line in enumerate(text.split("\n"), 1) if _unread_table_line(line)]
        html = [n for n, line in enumerate(text.split("\n"), 1) if re.search(r"<(?:table|tr|td|th)\b", line, re.IGNORECASE)]
        assert not quoted and not html, (rel, quoted[:5], html[:5])


def _unread_table_line(line: str) -> bool:
    """A table line behind a quote or a list marker: GitHub shows it, rows() reads none. Any indent and any list
    markers before the quote (ninth review: `1.  > | ID |`, `-   > `, `- - > ` and the item's `    > |` lines all
    rendered); and a list line holding a table row."""
    return bool((re.match(r"\s*(?:(?:[-+*]|\d{1,9}[.)])\s+)*>", line) and "|" in line)
                or re.match(r"\s*(?:[-+*]|\d{1,9}[.)])\s+[^\n]*\|[^\n]*\|", line))


@pytest.mark.parametrize("line", ["> | ID | Status |", "   > | a |", "1.  > | ID | Status |", "    > | R1 | DONE-local |",
                                  "-   > | a |", "10. > | a |", "- - > | a |", "- | ID | Status |"])
def test_a_table_behind_a_quote_or_a_list_marker_is_refused(line):
    """Ninth review: the ban matched ` {0,3}>` only - a quoted table inside a list item, shown by GitHub with a
    DONE-local "trust me" row, was read by nobody."""
    assert _unread_table_line(line)


@pytest.mark.parametrize("line", ["| R1 | x | G1 | DONE-local | t |", "   | R1 | x |", "- a list item, no table",
                                  "Prose with a | pipe."])
def test_a_plain_table_row_or_prose_is_not_refused(line):
    assert not _unread_table_line(line)
