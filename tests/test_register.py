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


def rows(text: str) -> list[dict[str, str]]:
    """Every row of every markdown table that has Group and Status columns."""
    out: list[dict[str, str]] = []
    header: list[str] | None = None
    for line in text.splitlines():
        if not line.startswith("|"):
            header = None
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if header is None:
            header = cells
            continue
        if set(line.replace("|", "").strip()) <= set("-: "):
            continue
        if "Group" in header and "Status" in header and len(cells) == len(header):
            out.append(dict(zip(header, cells, strict=True)))
    return out


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
}


def _skipped(file: str, src: str, m: re.Match) -> bool:
    """Skipped directly, through a decorator alias defined in the module (`needs_pg = pytest.mark.skipif`),
    by a module-level `pytestmark` skip, or by a runtime `pytest.importorskip` in its body (third review,
    2026-09-30: all three passed a check for the literal word "skip" above the function)."""
    decorators = m.group(1)
    aliases = set(re.findall(r"^(\w+)\s*=\s*pytest\.mark\.skip", src, re.MULTILINE))
    if "skip" in decorators or any(re.search(rf"@{a}\b", decorators) for a in aliases):
        return True
    body = src[m.end():]
    nxt = re.search(r"^(?:def |class |@)", body, re.MULTILINE)
    if "importorskip(" in body[:nxt.start() if nxt else len(body)]:
        return True
    return bool(re.search(r"^pytestmark\s*=.*skip", src, re.MULTILINE)) and file not in SKIP_OK


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
        refs = TEST_REF.findall(evidence)
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
    if status == "DEFERRED" and not re.search(r"owner-agreed \d{4}-\d{2}-\d{2}", evidence):
        found.append(f"{where}: DEFERRED needs 'owner-agreed YYYY-MM-DD'")
    if status not in CLOSED and ORDER.index(group) <= ORDER.index(current):
        found.append(f"{where}: still {status} but group {group} is at or before {current}")
    return found


def test_every_register_row_is_backed_by_evidence():
    found = [p for rel, row in all_rows() for p in problems(rel, row)]
    assert not found, "\n".join(found)


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
