"""What each kind of row adds to an incident's record (records.record, one reader per kind): the branches
no other test pinned."""

from __future__ import annotations

from datetime import UTC, datetime

from warden import records

INC = "inc-s19-readers"
AT = datetime(2026, 10, 21, 9, 0, tzinfo=UTC)


class _Log:
    def __init__(self, *rows: tuple[str, dict]) -> None:
        self.rows = [{"kind": kind, "body": body, "at": AT, "seq": i} for i, (kind, body) in enumerate(rows, 1)]

    def entries(self, incident=None, **_):
        return list(self.rows)


def _record(*rows: tuple[str, dict]) -> records.Record:
    r = records.record(_Log(*rows), INC, light=True)
    assert r is not None
    return r


def test_the_alerts_own_environment_wins_over_the_ingest_rows():
    r = _record(("incident.alert", {"alert": {"environment": "prod"}}), ("incident.ingest", {"env": "dev"}))
    assert r.environment == "prod"


def test_the_ingest_row_names_the_environment_when_the_alert_did_not():
    assert _record(("incident.ingest", {"env": "dev"})).environment == "dev"


def test_an_injection_check_that_did_not_finish_is_flagged():
    r = _record(("incident.tripwire", {"status": "timeout"}))
    assert r.flags == ["The injection check did not finish (timeout): the incident went to a person."]


def test_a_plan_looked_for_and_not_made_says_why():
    r = _record(("incident.plan_fix", {"planned": False, "why": "nothing in the catalogue fits"}))
    assert r.no_plan == "nothing in the catalogue fits"


def test_a_plan_that_was_made_is_not_a_missing_plan():
    assert _record(("incident.plan_fix", {"planned": True, "why": "fits"})).no_plan == ""


def test_an_ai_approval_says_it_is_an_ai_and_its_level():
    r = _record(("approval.accepted", {"ai": True, "autonomy": "L2", "approver": "eldane"}))
    assert r.decisions[0]["how"] == "own signing key - an AI approval at autonomy level L2"


def test_an_eldane_review_with_no_answer_adds_no_decision():
    assert _record(("eldane.verdict", {"agree": None})).decisions == []


def test_an_eldane_review_that_agrees_is_a_decision():
    assert _record(("eldane.verdict", {"agree": True})).decisions[0]["what"] == "Agreed with the plan"


def test_a_change_asked_for_by_an_approver_is_not_flagged():
    assert _record(("discuss.answer", {"asks_for_change": True, "approver": True})).flags == []


def test_a_change_asked_for_by_someone_else_is_flagged():
    assert len(_record(("discuss.answer", {"asks_for_change": True, "approver": False})).flags) == 1


def test_a_run_that_ended_with_a_status_not_in_the_table_says_it_in_words():
    r = _record(("workflow.end", {"status": "timed_out"}))
    assert (r.status, r.kind) == ("Timed out", "info")


def test_each_question_in_the_discussion_is_counted():
    assert _record(("discuss.turn", {}), ("discuss.turn", {}), ("incident.ingest", {"env": "dev"})).asked == 2


# The pages' own helpers (records.list_page, incident_page, _section).

def test_a_flagged_incident_says_so_on_its_row():
    r = _record(("incident.tripwire", {"flagged": ["L3"]}))
    assert '<span class="badge bad">Flagged</span>' in records.list_page([r])


def test_quiet_steps_are_not_listed_among_the_steps():
    page = records.incident_page(_record(("incident.ingest", {"env": "dev"}), ("chatops.thread", {"ts": "1"})))
    assert "chatops.thread" not in page


def test_a_code_block_closes_the_list_before_it():
    assert records._section(["- a", "```", "code", "```"]) == '<ul><li>a</li></ul><pre class="code">code</pre>'


def test_a_list_items_second_line_stays_in_the_list():
    assert records._section(["- a", "  more"]) == '<ul><li>a</li><li class="more-line">more</li></ul>'


def test_the_safety_check_names_the_policies_that_held_it():
    r = _record(("incident.verify", {"status": "escalated", "policies": ["P1", "P2"]}))
    assert ("Safety check", "escalated (P1, P2)") in records._summary_facts(r)
