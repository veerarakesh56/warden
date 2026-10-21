"""How WARDEN narrowed it down (register G10-57): each cause the model rules out comes with why and its citations,
checked like the hypothesis's; the report lays them out, and a reason it cannot check is shown as unchecked.

The report narrows to the real root cause. Qualified (providers.yaml): 22/30, 0 wrong-and-allowed."""

from __future__ import annotations

from warden import evidence
from warden.cli import DEMO_ALERTS
from warden.grounding import ruled_out_checked
from warden.models import Alert, Citation, RootCause, RuledOut
from warden.reporting import build_report
from warden.tools import FixtureBackend, gather


def _context():
    return gather(Alert(**DEMO_ALERTS["inc-002"]), FixtureBackend())


def test_an_older_answer_in_plain_words_is_still_read():
    rc = RootCause(hypothesis="h", confidence=0.5, ruled_out=["infrastructure saturation"])
    assert rc.ruled_out == [RuledOut(cause="infrastructure saturation", why="", citations=[])]


def test_a_reason_is_checked_against_the_evidence_and_an_invented_one_is_not():
    items = evidence.view(_context())
    item_id, item = next((k, v) for k, v in items.items() if k.startswith("M"))
    real = RuledOut(cause="a bad deploy", why="nothing was deployed",
                    citations=[Citation(id=item_id, quote=item.text[:24])])
    made_up = RuledOut(cause="a bad deploy", why="nothing was deployed", citations=[Citation(id="Z9", quote="no such quote here")])
    assert ruled_out_checked(real, items)
    assert not ruled_out_checked(made_up, items)
    assert not ruled_out_checked(RuledOut(cause="x"), items)  # no citation: nothing to check


def test_the_report_lays_out_what_was_found_ruled_out_and_left():
    ctx = _context()
    items = evidence.view(ctx)
    item_id, item = next((k, v) for k, v in items.items() if k.startswith("M"))
    rc = RootCause(hypothesis="Pods are OOM-killed under memory pressure.", confidence=0.7,
                   citations=[Citation(id=item_id, quote=item.text[:24])],
                   ruled_out=[RuledOut(cause="a bad deploy", why="no deploy in the window",
                                       citations=[Citation(id=item_id, quote=item.text[:24])]),
                              RuledOut(cause="node failure", why="nodes healthy",
                                       citations=[Citation(id="Z9", quote="not in any item")])])
    md = build_report(Alert(**DEMO_ALERTS["inc-002"]), root_cause=rc, context=ctx).markdown
    section = md[md.index("## How WARDEN narrowed it down"):]
    section = section[:section.index("\n## ", 5)] if "\n## " in section[5:] else section
    assert "- **Fixed checks found:**" in section
    assert f"- **Ruled out:** a bad deploy - no deploy in the window _(checked against {item_id})_" in section
    assert "- **Ruled out:** node failure - nodes healthy _(its reason could not be checked against the evidence)_" in section
    assert f"- **Left:** Pods are OOM-killed under memory pressure. _(cited: {item_id})_" in section
    assert md.index("## What WARDEN thinks happened") < md.index("## How WARDEN narrowed it down")
