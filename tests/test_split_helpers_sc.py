"""The helpers activities.py, history.py and intake.py were split into (Sonar maintainability, 2026-10-21), each
checked on its own: what it decides, said as the code before the split said it. Most of these paths are otherwise
covered only by the Temporal workflow tests, which need Temporal's test server."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from warden import activities, changes, eldane, history, intake
from warden.activities import (
    HELD_BACK,
    FixOutcome,
    IncidentActivities,
    RemediationActivities,
    _approver_problems,
    _End,
    _hold_back,
    _replan_refusal,
    _said_after,
)

AT = datetime(2026, 10, 21, 10, 0, tzinfo=UTC)


class _Log:
    """An audit log that keeps what is appended and answers entries() from a fixed list."""

    def __init__(self, rows=()):
        self.rows, self.appended, self.checkpoints = list(rows), [], 0

    def entries(self, *_a, **_k):
        return list(self.rows)

    def append(self, correlation, kind, body):
        self.appended.append((correlation, kind, body))

    def head(self, _incident):
        return "0" * 64

    def checkpoint(self):
        self.checkpoints += 1


def _policy(**kw):
    return SimpleNamespace(approvers={"alice": None}, said=lambda n: f"the person {n}", people=lambda: (),
                           required={"T1": 1}, **kw)


def _plan(**kw):
    base = {"incident_id": "inc-1", "workflow_id": "rem-1", "entry": "not_in_the_catalogue", "target": "dev/orders",
            "environment": "dev", "params": {}, "plan_hash": "h", "tier": "T1"}
    return SimpleNamespace(**{**base, **kw})


def test_a_person_taking_over_is_told_how_to_reset_the_kill_switch():
    assert "`warden killswitch link --approver YOU --key YOUR.pem`" in _said_after("apply_failed", [])


def test_an_end_no_person_takes_over_says_nothing_after():
    assert _said_after("expired", []) == ""


def test_an_outcome_names_who_approved():
    assert _said_after("rolled_back", ["alice"]) == " Approved by alice."


def test_words_the_gate_lets_go_stay():
    assert _hold_back("WARDEN's plan was approved. Their note: fine", " Their note: fine") == (
        "WARDEN's plan was approved. Their note: fine")


def test_a_replan_is_refused_to_someone_not_an_approver():
    assert _replan_refusal(approver=False, rows=[{}], recent=[]) == "not an approver"


def test_a_replan_needs_an_alarm_on_the_record():
    assert _replan_refusal(approver=True, rows=[], recent=[]) == "no alarm on the record"


def test_a_replan_is_once_an_hour():
    assert _replan_refusal(approver=True, rows=[{}], recent=[{"body": {"started": "inc-2"}}]) == (
        "asked again within the hour")


def test_a_replan_that_may_start():
    assert _replan_refusal(approver=True, rows=[{}], recent=[{"body": {"started": ""}}]) == ""


def test_someone_not_on_the_list_may_not_approve():
    assert _approver_problems(_plan(), "bob", None) == ["'bob' is not an approver"]


def test_an_approver_of_another_tier_may_not_approve():
    assert _approver_problems(_plan(tier="T3"), "alice", SimpleNamespace(tiers=["T1"])) == ["alice may not approve T3"]


def test_a_denials_reason_names_the_person_not_the_list_id():
    me = SimpleNamespace(policy=_policy())
    assert RemediationActivities._reasons_said(me, ["denied by alice: not now"]) == ["denied by the person alice: not now"]


def test_a_denial_is_said_with_who_when_and_their_reason():
    me = SimpleNamespace(policy=_policy())
    end = _End(status="denied", whole=["denied by alice: not now"], at=AT)
    said, words = RemediationActivities._denial_said(me, _plan(), "orders", ["denied by alice: not now"], end)
    assert said.startswith("WARDEN's plan `not_in_the_catalogue` on `orders` was denied by the person alice (with "
                           "their passkey) at ")
    assert words.startswith(" Their reason: ")


def test_a_denial_with_no_time_on_the_record_is_said_plainly():
    me = SimpleNamespace(policy=_policy())
    end = _End(status="denied", whole=["denied by alice"], at=None)
    assert RemediationActivities._denial_said(me, _plan(), "orders", ["denied by alice"], end) is None


def test_the_end_row_keeps_its_first_three_reasons_whole():
    log = _Log([{"body": {"workflow_id": "rem-1", "run_id": "", "status": "denied", "reasons": ["a", "b", "c", "d"]},
                 "at": AT}])
    end = RemediationActivities._end_row(SimpleNamespace(audit=log), _plan())
    assert end == _End(status="denied", whole=["a", "b", "c"], at=AT)


def _composer(did):
    return SimpleNamespace(_approvals_given=lambda _p: [], _approvers_said=lambda _g: did, _notes_said=lambda _g: "",
                           _plan_said=lambda *_a, **_k: "Said.", _denial_said=lambda *_a: None,
                           _said_beside=lambda _p, _w: "", _reasons_said=lambda w: w)


def test_an_approval_nobody_on_the_record_gave_is_not_said():
    assert RemediationActivities._compose(_composer([]), _plan(), "approved", None) is None


def test_an_approval_on_the_record_is_said():
    assert RemediationActivities._compose(_composer(["alice"]), _plan(), "approved", None) == ("Said.", [])


def test_an_autonomous_approval_carries_eldanes_review(monkeypatch):
    monkeypatch.setattr(eldane, "said", lambda *_a: " Eldane's review.")
    assert RemediationActivities._said_beside(SimpleNamespace(audit=None), _plan(), "autonomous") == " Eldane's review."


def _recording(rows):
    acts = SimpleNamespace(audit=_Log(rows), policy=_policy())
    acts._run_rows = lambda *a: RemediationActivities._run_rows(acts, *a)
    return acts


def test_one_approver_is_the_quorum_of_a_tier_that_needs_one():
    acts = _recording([{"body": {"workflow_id": "rem-1", "run_id": "", "plan_hash": "h", "tier": "T1",
                                 "approver": "alice"}}])
    recorded, approvers, tier, _plans = RemediationActivities._recorded(
        acts, "inc-1", "rem-1", "", FixOutcome(status="recovered", checklist={}, plan_hash="h"))
    assert (recorded["approved"], approvers, tier) == (True, {"alice"}, "T1")


def test_an_outcome_with_no_plan_hash_reads_every_row_of_its_run():
    acts = _recording([{"body": {"workflow_id": "rem-1", "run_id": "", "plan_hash": "h"}}])
    assert RemediationActivities._run_rows(acts, "inc-1", "rem-1", "", FixOutcome(status="failed", checklist={}), "k") == [
        {"workflow_id": "rem-1", "run_id": "", "plan_hash": "h"}]


def test_a_decision_kept_on_the_record_keeps_its_words():
    me = SimpleNamespace(audit=_Log(), policy=_policy())
    RemediationActivities._record_only(me, _plan(), "approved", "0" * 64, "WARDEN's plan was approved.")
    assert me.audit.appended[0][2]["said"] != HELD_BACK


def test_the_first_message_of_a_plan_carries_the_incidents_summary(monkeypatch):
    sent = []
    monkeypatch.setattr(activities, "_send", lambda _log, _inc, report: sent.append(report) or [])
    me = SimpleNamespace(audit=_Log([{"body": {"markdown": "# The incident\nwhat happened"}}]), policy=_policy(),
                         _summary_said=lambda _i: False)
    RemediationActivities._say(me, _plan(), "expired", "0" * 64, "It expired.", why=[], actions=())
    assert sent[0].markdown.startswith("# The incident\nwhat happened\n\n**Fix plan:** It expired.")


def test_an_applied_change_is_recorded_where_the_team_looks(monkeypatch):
    monkeypatch.setattr(changes, "issue_text", lambda **_k: ("title", "text"))
    me = SimpleNamespace(audit=_Log(), changes=SimpleNamespace(open=lambda _t, _x: ("https://example.test/1", "ok")))
    RemediationActivities._record_change(me, "inc-1", "rem-1", "run", end={}, plan={})
    assert me.audit.appended == [("inc-1", "change.recorded", {"workflow_id": "rem-1", "run_id": "run",
                                                                 "url": "https://example.test/1", "detail": "ok"})]


def test_past_fix_plans_go_into_the_prompt_and_on_the_record(monkeypatch):
    monkeypatch.setattr(history, "past", lambda *_a: [])
    monkeypatch.setattr(history, "for_prompt", lambda *_a: [{"seqs": [1, 2]}])
    monkeypatch.setattr(history, "prompt_facts", lambda _s: "FACTS")
    steps = []
    prompt = IncidentActivities._with_history(SimpleNamespace(audit=None), None, "EVIDENCE", steps)
    assert (prompt, steps) == ("EVIDENCE\n\nFACTS", [{"node": "history_shown", "seqs": [1, 2]}])


def test_no_fix_plan_is_said_with_why():
    me = SimpleNamespace(audit=_Log([{"body": {"run_id": "", "why": "no catalogue entry fits", "planned": False}}]))
    said = IncidentActivities._no_plan_summary(me, "inc-1", "# The incident")
    assert said == ("# The incident\n\n**No fix plan:** no catalogue entry fits. There is nothing to approve; nothing "
                    "changes unless a person acts.")


def test_a_like_incident_with_no_fix_says_what_was_proposed():
    assert history._done({"fix": None, "action": "restart", "status": "Escalated"}) == "proposed `restart`, escalated"


def test_a_like_incident_with_none_after_it_is_stable():
    row = {"at": AT, "link": "", "incident": "inc-0", "why": ["same alarm"], "fix": None, "action": "",
           "status": "Open", "stable": True}
    assert history._similar_line(row).endswith(" · `inc-0` · same alarm · Open · no incident like it since")


def test_a_grouped_alarm_is_on_the_incidents_own_record():
    log = _Log()
    ev = SimpleNamespace(rule="rule-1", alert=SimpleNamespace(name="CPU high", labels={"via": "cloudwatch"}),
                         transitioned_at=AT)
    intake._record_grouped(log, SimpleNamespace(workflow_id="inc-abc"), ev)
    assert log.appended == [("abc", "intake.grouped", {"rule": "rule-1", "name": "CPU high", "via": "cloudwatch",
                                                        "at": AT.isoformat()})]
