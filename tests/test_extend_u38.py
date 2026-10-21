"""The discussion thread can extend a waiting fix plan's approval time - an approver who may
approve that plan, bounded per extension and in total, recorded in the signed audit; the precheck before apply is
untouched (the workflow tests in test_remediation_workflow.py run on Temporal, in CI)."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import approvals, audit, discuss, environments, extend
from warden.activities import DiscussActivities, RemediationActivities

INC = "50ac32d0fe243384-20261021T071413Z"
WID = "rem-dev-abc"
APPROVER = "U" + "0" * 3 + "APPROV1"
PROD_ONLY = "U" + "0" * 3 + "PRODAP1"
T2_ONLY = "U" + "0" * 3 + "TWOAPP1"
PERSON = "U" + "0" * 3 + "PERSON1"
CHANNEL = "C" + "0" * 3 + "CHAN1"
_MESSAGES = itertools.count(100)
ID_WITH_H = "U" + "0" * 2 + "7H3" + "ABCD"  # a member id with an "H" between digits, built from parts


@pytest.fixture
def world(tmp_path):
    log = audit.AuditLog(tmp_path / "a.db", key=Ed25519PrivateKey.generate())
    policy = approvals.ApproverPolicy(approvers={
        "owner": approvals.Approver(public_key="k", tiers=["T1"], slack=APPROVER),
        "prodonly": approvals.Approver(public_key="k", tiers=["T1"], slack=PROD_ONLY, environments=["prod"]),
        "t2only": approvals.Approver(public_key="k", tiers=["T2"], slack=T2_ONLY)})
    return log, policy


def _plan(log, *, wait=timedelta(hours=1), plan_hash="h1", until=True):
    body = {"workflow_id": WID, "entry": "events_enable_rule", "tier": "T1", "environment": "dev", "service": "tick",
            "target": "dev/rule/tick", "plan_hash": plan_hash}
    if until:
        body["approval_until"] = (datetime.now(UTC) + wait).isoformat()
    log.append(INC, "remediation.plan", body)
    return log.entries(INC, kinds=("remediation.plan",))[-1]


def _ask(log, policy, user=APPROVER, hours=24, now=None, asked=None):
    """One "extend" from its own Slack message, unless `asked` names one."""
    asked = asked or f"{CHANNEL}/1760000000.{next(_MESSAGES):06d}"
    return extend.request(log, policy, incident=INC, user=user, hours=hours, now=now or datetime.now(UTC), asked=asked)


def _turn(text, user=APPROVER, ts="1760000000.000200"):
    return discuss.Turn(channel=CHANNEL, thread_ts="1760000000.000100", ts=ts, user=user, text=text)


def _rows(log):
    return log.entries(INC, kinds=(extend.EXTENDED,))


def test_an_approver_of_the_plan_extends_its_wait_and_it_is_recorded(world):
    log, policy = world
    row = _plan(log)
    base = datetime.fromisoformat(row["body"]["approval_until"])
    got = _ask(log, policy, hours=12)
    assert datetime.fromisoformat(got["until"]) == base + timedelta(hours=12)
    assert got["hours"] == 12
    [e] = _rows(log)
    assert (e["body"]["approver"], e["body"]["workflow_id"], e["body"]["plan_hash"]) == ("owner", WID, "h1")
    assert extend.extended_until(log, INC, WID, "h1", row["at"]) == base + timedelta(hours=12)
    assert extend.waiting(log, INC)["until"] == base + timedelta(hours=12)  # the next one counts from there


def test_nobody_else_extends_it(world):
    log, policy = world
    _plan(log)
    assert _ask(log, policy, user=PERSON) == {"why": "not an approver"}
    assert _ask(log, policy, user=PROD_ONLY) == {"why": "not this plan's approver"}  # another environment's approver
    assert _ask(log, policy, user=T2_ONLY) == {"why": "not this plan's approver"}  # another risk level's
    assert _ask(log, policy, user="") == {"why": "not an approver"}
    assert _rows(log) == []


@pytest.mark.parametrize("hours", [0, -1, extend.EXTEND_MAX_HOURS + 1, 10_000])
def test_at_most_a_day_at_a_time(world, hours):
    log, policy = world
    _plan(log)
    assert _ask(log, policy, hours=hours) == {"why": "hours out of range"}
    assert _rows(log) == []


def test_never_past_the_ceiling_from_when_the_plan_was_made(world):
    log, policy = world
    row = _plan(log)
    top = row["at"] + timedelta(hours=environments.MAX_APPROVAL_WAIT_HOURS)
    got = {}
    for _ in range(environments.MAX_APPROVAL_WAIT_HOURS // extend.EXTEND_MAX_HOURS + 2):
        got = _ask(log, policy)
        if got.get("why"):
            break
        assert datetime.fromisoformat(got["until"]) <= top
    assert got["why"] == "at the limit"
    assert datetime.fromisoformat(got["until"]) == top
    assert max(datetime.fromisoformat(e["body"]["until"]) for e in _rows(log)) == top
    assert _rows(log)[-1]["body"]["until"] == top.isoformat()
    # And a row that says more - written by hand - is read only up to the ceiling.
    log.append(INC, extend.EXTENDED, {"workflow_id": WID, "plan_hash": "h1", "until": (top + timedelta(days=30))
                                      .isoformat()})
    assert extend.extended_until(log, INC, WID, "h1", row["at"]) == top


def test_only_a_plan_still_waiting_is_extended(world):
    log, policy = world
    assert _ask(log, policy) == {"why": "no plan waiting"}  # none at all
    _plan(log)
    log.append(INC, "workflow.end", {"workflow_id": WID, "status": "denied"})
    assert _ask(log, policy) == {"why": "no plan waiting"}  # it ended
    _plan(log, wait=timedelta(hours=1))
    assert _ask(log, policy, now=datetime.now(UTC) + timedelta(hours=2)) == {"why": "no plan waiting"}  # it ran out
    assert _rows(log) == []


def test_an_extension_of_another_plan_extends_nothing(world):
    log, policy = world
    row = _plan(log, plan_hash="old")
    _ask(log, policy)
    assert extend.extended_until(log, INC, WID, "new", row["at"]) is None  # the plan made again after drift
    assert extend.extended_until(log, INC, "rem-other", "old", row["at"]) is None


def test_a_plan_recorded_before_it_said_its_wait_waits_its_environments(world):
    log, _ = world
    row = _plan(log, until=False)
    wait = environments.default_environment_policies().for_env("dev").approval_wait_hours
    assert extend.waiting(log, INC)["until"] == row["at"] + timedelta(hours=wait)


def test_the_activities_record_the_ask_and_read_the_extension(world):
    log, policy = world
    row = _plan(log)
    talk = DiscussActivities(audit=log, incident=None, policy=policy)
    turn = _turn("<@UWARDEN> please extend the wait by 6 hours")
    got = talk.discuss_extend(turn, INC)
    assert got["hours"] == 6
    assert got["until_said"]
    assert not got.get("why")
    asked = log.entries(f"discuss-{INC}", kinds=("discuss.extend",))
    assert [(e["body"]["hours"], e["body"]["why"]) for e in asked] == [(6, "")]
    refused = talk.discuss_extend(turn.model_copy(update={"user": PERSON, "ts": "1760000000.000300"}), INC)
    assert refused["why"] == "not an approver"
    assert log.entries(f"discuss-{INC}", kinds=("discuss.extend",))[-1]["body"]["why"] == "not an approver"
    plan = approvals.Plan(workflow_id=WID, incident_id=INC, entry="events_enable_rule", tier="T1", params={},
                          snapshot={}, plan_hash="h1", created_at=row["at"], environment="dev", target="dev/rule/tick",
                          approval_ttl_minutes=60)
    rem = RemediationActivities(audit=log, policy=policy, platform=None)
    assert rem.approval_extension(plan) == got["until"]
    assert rem.approval_extension(plan.model_copy(update={"plan_hash": "h2"})) == ""


def test_the_thread_asks_in_plain_words_and_is_answered_in_fixed_ones():
    for text, hours in (("<@UWARDEN> extend the wait", 24), ("extend by 12h please", 12), ("extend approval 6 hours", 6),
                        ("please extend the approval.", 24), ("extend the wait by 6h!", 6),
                        ("extend the wait... thanks", 24), ("extend it by 6h", 6), ("extend 12h", 12)):
        assert discuss.asks_to_extend(text), text
        assert discuss.hours_asked(text) == hours, text
    # A question about what something extends is answered, not taken as a request.
    for text in ("will this extend the outage", "what is the plan?", "extend", "can you extend it",
                 "will the restart extend it?", "does this extend the time to recover?",
                 "can you extend the wait by 6h?", "can you extend the wait...?", "extend the wait?!",
                 "extend by", "extend the outage by 2h"):
        assert not discuss.asks_to_extend(text), text
    said = discuss.extended_said({"workflow_id": WID, "until_said": "2026-10-22 07:00Z", "hours": 24}, INC)
    assert said.startswith(f"The wait for WARDEN's plan `{WID}` is extended by 24 h")
    assert "passkey" in said
    assert "target again" in said
    for why in discuss.NOT_EXTENDED:
        out = discuss.extended_said({"why": why, "workflow_id": WID, "until_said": "x"}, INC)
        assert out, why
        assert "{" not in out, why
    assert discuss.extended_said({"why": "something else"}, INC) == discuss.NOT_READ


@pytest.mark.parametrize("text", [
    # Before "extend", in the same sentence.
    "do not extend the wait", "don't extend the wait", "please don't extend the approval", "never extend the plan",
    "no need to extend the wait", "dont extend the wait", "don\u2019t extend the wait", "we can't extend the wait",
    "cannot extend the wait", "cancel: extend the wait", "stop, extend the wait", "we won't extend the plan by 6h",
    "I don't think we should extend the wait.", "no; extend the wait", "no - extend the wait",
    # After "extend", anywhere in the message ("extend the wait - no, don't" once became 24 h).
    "extend the wait - no, don't", "extend the wait. no, don't", "extend the wait, do not apply anything yet",
    "extend by 6h, never mind", "extend the wait; no", "extend the wait.\nActually no.", "extend the wait. Not now.",
    "extend by 12h - cancel that", "extend the wait, stop", "extend the wait or not",
])
def test_a_no_beside_extend_is_unclear_and_asked_again(text):
    """Fail closed: a "no" after "extend", or before it in its sentence, extends nothing - the approver is asked
    again ("don't extend the wait" once became a 24-hour extension signed in the approver's name)."""
    assert discuss.said_no(text)
    assert discuss.asks_to_extend(text)  # it reaches the extension step, which asks again; it is never extended


@pytest.mark.parametrize("text", [
    "extend the wait", "please extend the approval.", "no rush. extend the wait", "No rush!\nextend the wait",
    "Not urgent? extend the wait by 6h", "I want you to extend the wait", "the incident: extend the wait",
    "urgent, extend the wait", "extend the wait, nothing else", "extend by 6h, the incident notes are attached",
])
def test_a_no_only_in_an_earlier_sentence_or_inside_a_word_leaves_the_request(text):
    assert not discuss.said_no(text)
    assert discuss.asks_to_extend(text)


def test_a_message_that_says_no_extends_nothing_and_is_asked_again(world):
    log, policy = world
    _plan(log)
    talk = DiscussActivities(audit=log, incident=None, policy=policy)
    got = talk.discuss_extend(_turn("<@UWARDEN> extend the wait - no, don't", ts="1760000000.000600"), INC)
    assert got == {"why": "said no"}
    assert _rows(log) == []
    assert discuss.extended_said(got, INC).startswith("WARDEN read a \"no\" beside \"extend\"")
    # Who asks is still checked first.
    got = talk.discuss_extend(_turn("<@UWARDEN> don't extend the wait", user=PERSON, ts="1760000000.000601"), INC)
    assert got == {"why": "not an approver"}
    assert not _ask(log, policy, hours=6).get("why")  # the same plan, asked plainly: extended
    assert len(_rows(log)) == 1


def _accept(log, approver, *, plan_hash="h1", required=1):
    log.append(INC, "approval.accepted", {"workflow_id": WID, "plan_hash": plan_hash, "approver": approver,
                                          "required": required})


def _with_eldane(policy):
    return approvals.ApproverPolicy(approvers={**policy.approvers, "eldane": approvals.Approver(
        public_key="k-eldane", tiers=["T1"], environments=["dev"], ai=True)})


def test_a_plan_eldane_approved_is_not_extended(world):
    """Eldane's approval that was enough on its own ended the wait for a person: never extended."""
    log, policy = world
    policy = _with_eldane(policy)
    row = _plan(log)
    _accept(log, "eldane", plan_hash="other")
    assert not _ask(log, policy, hours=1).get("why")  # Eldane's approval of another plan
    _accept(log, "eldane")
    assert _ask(log, policy) == {"why": "approved by Eldane", "workflow_id": WID}
    assert extend.ai_approved(log, policy, INC, {**extend.waiting(log, INC), "seq": row["seq"]})
    said = discuss.extended_said({"why": "approved by Eldane", "workflow_id": WID}, INC)
    assert said.startswith("Eldane, the AI critic, already approved")


def test_an_eldane_approval_that_was_not_enough_leaves_the_wait_to_extend(world):
    """Where the tier needs two approvers, Eldane's approval did not end the wait (the run's _critic: not enough on
    its own): the plan still waits for a person, and an approver may extend that wait."""
    log, policy = world
    policy = _with_eldane(policy)
    _plan(log)
    _accept(log, "eldane", required=2)
    assert not _ask(log, policy, hours=1).get("why")
    assert len(_rows(log)) == 1


def test_a_plan_people_already_approved_is_not_waiting(world):
    """Its approvals reached the quorum: it is being checked and applied, not waiting."""
    log, policy = world
    _plan(log)
    _accept(log, "t2only", required=2)  # one of the two it needs: still waiting for the second
    assert not _ask(log, policy, hours=1).get("why")
    _accept(log, "prodonly", plan_hash="other", required=2)  # another plan's approval counts for nothing
    assert not _ask(log, policy, hours=1).get("why")
    _accept(log, "owner", required=2)
    assert _ask(log, policy) == {"why": "already approved", "workflow_id": WID}
    assert len(_rows(log)) == 2
    said = discuss.extended_said({"why": "already approved", "workflow_id": WID}, INC)
    assert said.startswith(f"WARDEN's plan `{WID}` already has the approvals it needs")


def test_who_asks_is_checked_before_anything_about_the_plan_is_said(world):
    """Someone who may not extend learns nothing: not whether a plan waits, nor its id, nor that Eldane approved it,
    nor whether their hours were clear."""
    log, policy = world
    policy = _with_eldane(policy)
    talk = DiscussActivities(audit=log, incident=None, policy=policy)
    assert _ask(log, policy, user=PERSON) == {"why": "not an approver"}  # no plan at all
    _plan(log)
    _accept(log, "eldane")
    assert _ask(log, policy, user=PERSON) == {"why": "not an approver"}
    assert _ask(log, policy, user=PERSON, hours=99) == {"why": "not an approver"}
    got = talk.discuss_extend(_turn("<@UWARDEN> extend the wait by 30m", user=PERSON, ts="1760000000.000500"), INC)
    assert got == {"why": "not an approver"}


def test_the_run_s_own_deadline_is_what_an_extension_moves(world):
    """The run waits from when its wait began, after the gate and the critic - later than the plan's approval_until.
    Recorded (approval_wait), an extension counts from it, so it always moves the run's deadline; and the plan is
    waiting until then, not only until its approval_until."""
    log, policy = world
    row = _plan(log)
    base = datetime.fromisoformat(row["body"]["approval_until"])
    real = base + timedelta(minutes=40)
    plan = approvals.Plan(workflow_id=WID, incident_id=INC, entry="events_enable_rule", tier="T1", params={},
                          snapshot={}, plan_hash="h1", created_at=row["at"], environment="dev", target="dev/rule/tick",
                          approval_ttl_minutes=60)
    rem = RemediationActivities(audit=log, policy=policy, platform=None)
    rem.approval_wait(plan, real.isoformat())
    rem.approval_wait(plan, (real + timedelta(hours=5)).isoformat())  # a retried activity: once per plan
    assert len(log.entries(INC, kinds=(extend.WAIT,))) == 1
    assert extend.waiting(log, INC)["until"] == real
    later = base + timedelta(minutes=20)  # past approval_until, before the run's own deadline: still waiting
    assert _ask(log, policy, hours=1, now=later)["until"] == (real + timedelta(hours=1)).isoformat()
    rem.approval_wait(plan.model_copy(update={"plan_hash": "h2"}), (real + timedelta(days=2)).isoformat())
    assert extend.waiting(log, INC)["until"] == real + timedelta(hours=1)  # another plan's wait moves nothing


def test_the_ceiling_counts_from_the_plan_s_own_creation(world):
    """The plan row says when the plan was made (its created_at), the same time the run's ceiling counts from."""
    log, policy = world
    made = datetime.now(UTC) - timedelta(hours=extend.CEILING_HOURS) + timedelta(hours=2)
    log.append(INC, "remediation.plan", {"workflow_id": WID, "tier": "T1", "environment": "dev", "plan_hash": "h1",
                                         "made": made.isoformat(),
                                         "approval_until": (datetime.now(UTC) + timedelta(hours=1)).isoformat()})
    got = _ask(log, policy, hours=6)
    assert got["until"] == extend.ceiling(made).isoformat()
    assert got["capped"]


def test_the_whole_decision_is_taken_again_inside_the_write_s_lock(world):
    """An Eldane approval, or the people's last approval, landing between the read and the write: nothing is written
    (only the plan and its time were checked again)."""
    log, policy = world
    policy = _with_eldane(policy)
    _plan(log)
    real = log.append_unless

    def eldane_first(correlation_id, kind, body, refuse):
        if kind == extend.EXTENDED and not log.entries(INC, kinds=("approval.accepted",)):
            _accept(log, "eldane")
        return real(correlation_id, kind, body, refuse)

    log.append_unless = eldane_first
    assert _ask(log, policy) == {"why": "approved by Eldane", "workflow_id": WID}
    assert _rows(log) == []


def test_the_last_approval_landing_before_the_write_stops_it(world):
    log, policy = world
    _plan(log)
    real = log.append_unless

    def approved_first(correlation_id, kind, body, refuse):
        if kind == extend.EXTENDED and not log.entries(INC, kinds=("approval.accepted",)):
            _accept(log, "owner")
        return real(correlation_id, kind, body, refuse)

    log.append_unless = approved_first
    assert _ask(log, policy) == {"why": "already approved", "workflow_id": WID}
    assert _rows(log) == []


def test_eldane_itself_never_extends_a_wait(world):
    """An AI entry on the list, even one given a Slack id, is not a person who may extend a wait."""
    log, policy = world
    eldane_slack = "U" + "0" * 3 + "ELDANE1"
    policy = approvals.ApproverPolicy(approvers={**policy.approvers, "eldane": approvals.Approver(
        public_key="k-eldane", tiers=["T1"], environments=["dev"], ai=True, slack=eldane_slack)})
    _plan(log)
    assert _ask(log, policy, user=eldane_slack) == {"why": "not an approver"}
    assert _rows(log) == []


# --- How long: read strictly from the whole message ---

@pytest.mark.parametrize(("text", "hours"), [
    ("<@UWARDEN> extend the wait", extend.EXTEND_MAX_HOURS),
    ("please extend the wait, thanks", extend.EXTEND_MAX_HOURS),
    ("extend by 12h please", 12),
    ("extend by 12 h", 12),
    ("extend the wait by 18hrs", 18),
    ("extend approval 6 hours", 6),
    # CodeRabbit's case: the hours far from "extend" were cut off by a 40-character window and became 24.
    ("extend the wait for this plan in the incident by 6 hours", 6),
    ("<@U0123ABC> extend the wait on 50ac32d0fe243384-20261021T071413Z (rem-dev-1) by 3h", 3),
    (f"<@{ID_WITH_H}> extend the wait", extend.EXTEND_MAX_HOURS),  # an "H" inside a member's id is not "h"
    ("extend by 30h", 30),  # read as said; the request then refuses it as out of range
    # A full stop that ends the sentence ends the duration ("6h." once became 24).
    ("extend by 6h.", 6),
    ("extend by 12 hours.", 12),
    ("extend by 6hours. Thanks", 6),
    ("extend the wait (6h)", 6),
    ("extend the wait to 12h", 12),
    ("extend by 12h!", 12),
    ("extend by 6h for i-0abc123", 6),
    ("extend by 6h;", 6),
    ("extend the wait 6hrs", 6),
    ("extend it 6h", 6),
    ("extend the wait https://x.y/a/1h", extend.EXTEND_MAX_HOURS),  # a number inside a link is no duration
])
def test_the_hours_said_are_the_hours_asked(text, hours):
    assert discuss.hours_asked(text) == hours


@pytest.mark.parametrize("text", [
    "extend by 6 more hours", "extend by six hours", "extend for an hour", "extend by 2 days", "extend 90 minutes",
    "extend by 1.5h", "extend by 1.5h.", "extend by 12h and 30 minutes", "extend by 12h, then 6h", "extend by 12", "extend to 14:00",
    "extend the wait until tomorrow", "extend the wait till tonight", "extend the wait half a day",
    # Another unit, or text, written against the number (each of these became 24 h).
    "extend by 30m", "extend by 45min", "extend by 90mins", "extend the wait 2days", "extend the wait by 1wk",
    "extend by 6h-ish", "extend by 6h:", "extend the wait 6h.Thanks", "extend the wait by 3d", "extend by 10s",
    "extend for 2 more hours", "extend by six", "extend the plan by 6h and the other by 2h",
    "extend the wait by 6 hours, the deploy is at 14:00", "extend the wait by 6h for 3 people",
])
def test_a_duration_that_is_not_exactly_whole_hours_once_is_not_guessed(text):
    assert discuss.hours_asked(text) is None


def test_unclear_hours_extend_nothing_and_the_approver_is_asked_again(world):
    log, policy = world
    _plan(log)
    talk = DiscussActivities(audit=log, incident=None, policy=policy)
    got = talk.discuss_extend(_turn("<@UWARDEN> extend the wait by 6 more hours"), INC)
    assert got == {"why": "hours unclear"}
    assert _rows(log) == []
    [asked] = log.entries(f"discuss-{INC}", kinds=("discuss.extend",))
    assert (asked["body"]["hours"], asked["body"]["why"]) == (None, "hours unclear")
    said = discuss.extended_said(got, INC)
    assert said.startswith("WARDEN could not tell for how long, so nothing was extended.")
    assert f"1 to {extend.EXTEND_MAX_HOURS}" in said


# --- One message extends once: a retried activity adds no hours ---

def test_the_same_message_asked_again_answers_as_first_and_adds_nothing(world):
    log, policy = world
    row = _plan(log)
    base = datetime.fromisoformat(row["body"]["approval_until"])
    first = _ask(log, policy, hours=6, asked=f"{CHANNEL}/1760000000.000900")
    again = _ask(log, policy, hours=6, asked=f"{CHANNEL}/1760000000.000900")
    assert again == first
    [e] = _rows(log)
    assert e["body"]["asked"] == f"{CHANNEL}/1760000000.000900"
    assert (e["body"]["workflow_id"], e["body"]["plan_hash"]) == (WID, "h1")
    assert extend.waiting(log, INC)["until"] == base + timedelta(hours=6)
    other = _ask(log, policy, hours=6)  # another message: a second extension, from the first one's end
    assert datetime.fromisoformat(other["until"]) == base + timedelta(hours=12)
    assert len(_rows(log)) == 2


def test_a_retried_activity_after_its_row_was_written_adds_nothing(world):
    """The extension row commits, then the reply or the activity's completion is lost and Temporal retries it."""
    log, policy = world
    row = _plan(log)
    base = datetime.fromisoformat(row["body"]["approval_until"])
    talk = DiscussActivities(audit=log, incident=None, policy=policy)
    turn = _turn("<@UWARDEN> extend the wait by 6 hours")
    first = talk.discuss_extend(turn, INC)
    retried = talk.discuss_extend(turn, INC)
    assert retried == first
    assert len(_rows(log)) == 1
    assert len(log.entries(f"discuss-{INC}", kinds=("discuss.extend",))) == 1
    assert extend.waiting(log, INC)["until"] == base + timedelta(hours=6)


def test_a_message_that_extended_one_plan_extends_no_other(world):
    """Asked again after a new plan replaced the one it extended: still its first answer, for that first plan."""
    log, policy = world
    _plan(log, plan_hash="h1")
    first = _ask(log, policy, hours=6, asked=f"{CHANNEL}/1760000000.000901")
    _plan(log, plan_hash="h2")
    assert _ask(log, policy, hours=6, asked=f"{CHANNEL}/1760000000.000901") == first
    assert [e["body"]["plan_hash"] for e in _rows(log)] == ["h1"]


def test_an_extension_that_lands_between_the_read_and_the_write_is_counted_not_lost(world):
    log, policy = world
    row = _plan(log)
    base = datetime.fromisoformat(row["body"]["approval_until"])
    real = log.append_unless
    landed = []

    def append_unless(correlation_id, kind, body, refuse):
        if body["hours"] == 6 and not landed:  # another approver's extension commits just before this write
            landed.append(_ask(log, policy, hours=2))
        return real(correlation_id, kind, body, refuse)

    log.append_unless = append_unless
    got = _ask(log, policy, hours=6)
    assert len(_rows(log)) == 2
    assert datetime.fromisoformat(landed[0]["until"]) == base + timedelta(hours=2)
    assert datetime.fromisoformat(got["until"]) == base + timedelta(hours=8)
    assert extend.waiting(log, INC)["until"] == base + timedelta(hours=8)


def test_two_attempts_of_one_message_side_by_side_extend_once(world):
    """A retry that starts while the first attempt still runs: both read the plan before either writes."""
    log, policy = world
    row = _plan(log)
    base = datetime.fromisoformat(row["body"]["approval_until"])
    asked = f"{CHANNEL}/1760000000.000902"
    real = log.append_unless
    first = []

    def append_unless(correlation_id, kind, body, refuse):
        if not first:  # the other attempt of the same message writes first
            first.append(None)
            first[0] = _ask(log, policy, hours=6, asked=asked)
        return real(correlation_id, kind, body, refuse)

    log.append_unless = append_unless
    got = _ask(log, policy, hours=6, asked=asked)
    assert got == first[0]
    assert len(_rows(log)) == 1
    assert extend.waiting(log, INC)["until"] == base + timedelta(hours=6)


def test_a_plan_that_keeps_moving_is_not_extended_blind(world):
    log, policy = world
    _plan(log)
    log.append_unless = lambda *_a, **_k: ("", "moved")
    got = _ask(log, policy, hours=6)
    assert got == {"why": "busy", "workflow_id": WID}
    assert _rows(log) == []
    assert discuss.extended_said(got, INC).startswith(f"Another extension of WARDEN's plan `{WID}`")


def test_no_message_no_extension(world):
    log, policy = world
    _plan(log)
    assert extend.request(log, policy, incident=INC, user=APPROVER, hours=6, now=datetime.now(UTC),
                          asked="") == {"why": "no message"}
    assert _rows(log) == []


def test_a_refused_message_asked_again_stays_refused_even_once_a_plan_waits(world):
    """A retried "extend" that was refused does not extend a plan made since."""
    log, policy = world
    talk = DiscussActivities(audit=log, incident=None, policy=policy)
    turn = _turn("<@UWARDEN> extend the wait by 6 hours", ts="1760000000.000400")
    assert talk.discuss_extend(turn, INC) == {"why": "no plan waiting"}
    _plan(log)  # a plan made between the first attempt and its retry
    assert talk.discuss_extend(turn, INC) == {"why": "no plan waiting"}
    assert _rows(log) == []
    assert len(log.entries(f"discuss-{INC}", kinds=("discuss.extend",))) == 1
    other = talk.discuss_extend(_turn("<@UWARDEN> extend the wait by 6 hours", ts="1760000000.000401"), INC)
    assert other["hours"] == 6  # a new message is a new request
