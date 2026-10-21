"""The workflows' decision helpers, outside Temporal: each says what the workflow said before its steps were split
into helpers (Sonar maintainability). The workflows themselves are tested against Temporal's test server
(test_remediation_workflow.py and others); these pin the words and choices the helpers now carry."""

from datetime import timedelta
from types import SimpleNamespace

from warden.approvals import Denial
from warden.discuss import (
    ELSEWHERE,
    LIMIT,
    NO_RECORD,
    NOT_APPROVER,
    NOT_READ,
    REPLAN_SOON,
    Thread,
    Turn,
)
from warden.workflows import (
    _denied,
    _for_a_person,
    _not_answered,
    _not_recovered_why,
    _relapse_why,
    _replan_said,
)


def _turn() -> Turn:
    return Turn(channel="C0123456", thread_ts="1700000000.000100", ts="1700000000.000200", user="U0123456",
                text="what happened?", environment="dev")


def test_a_denial_is_said_with_its_reason():
    assert _denied(Denial(approver="alice", workflow_id="rem-1", plan_hash="h", reason="not now")) == (
        "denied by alice: not now")


def test_a_denial_without_a_reason_names_only_who():
    assert _denied(Denial(approver="alice", workflow_id="rem-1", plan_hash="h")) == "denied by alice"


def test_a_relapse_by_a_failed_recheck_names_the_recheck():
    why = _relapse_why("orders", "", after=timedelta(minutes=15), now_too=True)
    assert why == "orders recovered, then a health check failed by the 15-minute re-check"


def test_a_relapse_by_the_alarm_ends_the_watch_at_once():
    why = _relapse_why("orders", "2026-10-21T10:00:00Z", after=timedelta(minutes=60), now_too=True)
    assert why == "orders recovered, then its alarm fired again at 2026-10-21T10:00:00Z"


def test_a_relapse_by_the_alarm_before_the_watch_ended_at_once_names_the_recheck():
    why = _relapse_why("orders", "2026-10-21T10:00:00Z", after=timedelta(minutes=60), now_too=False)
    assert why == "orders recovered, then its alarm fired again at 2026-10-21T10:00:00Z by the 60-minute re-check"


def test_not_recovered_in_time():
    req = SimpleNamespace(service="orders", recover_within_minutes=5)
    assert _not_recovered_why(req, "", 0) == "orders did not recover within 5 min"


def test_not_recovered_by_the_alarm_with_one_other_alarm_counted():
    req = SimpleNamespace(service="orders", recover_within_minutes=5)
    assert _not_recovered_why(req, "T1", 1) == (
        "orders's alarm fired again during the verify window, at T1 (register C1); also, 1 other alarm started "
        "after the fix (see the record)")


def test_not_recovered_with_other_alarms_counted_in_the_plural():
    req = SimpleNamespace(service="orders", recover_within_minutes=5)
    assert _not_recovered_why(req, "", 3).endswith("; also, 3 other alarms started after the fix (see the record)")


def test_a_replan_refused_is_said_by_why():
    assert _replan_said("not an approver", "inc-1") == NOT_APPROVER


def test_a_replan_asked_again_soon():
    assert _replan_said("asked again within the hour", "inc-1") == REPLAN_SOON.format(incident="inc-1")


def test_a_replan_with_no_record():
    assert _replan_said("no alarm on the record", "inc-1") == NO_RECORD.format(incident="inc-1")


def test_a_replan_started_reads_as_not_read_until_it_is_said():
    assert _replan_said("", "inc-1") == NOT_READ


def test_another_environments_incident_is_refused():
    assert _not_answered(Thread(elsewhere=True), _turn()) == ELSEWHERE.format(environment="dev")


def test_no_incident_named_is_asked_for():
    assert _not_answered(Thread(), _turn()).startswith("Which incident? Mention its id")


def test_past_the_daily_limit():
    assert _not_answered(Thread(incident="inc-1", over=True), _turn()) == LIMIT


def test_for_a_person_reads_the_status_value():
    verified = SimpleNamespace(verdict=SimpleNamespace(status=SimpleNamespace(value="approved_for_human")))
    assert _for_a_person(verified)


def test_for_a_person_reads_a_plain_status():
    verified = SimpleNamespace(verdict=SimpleNamespace(status="escalated"))
    assert not _for_a_person(verified)
