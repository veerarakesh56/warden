"""U3-8 (owner update 3): "the discussion thread can extend" a waiting fix plan's approval time - an approver who may
approve that plan, bounded per extension and in total, recorded in the signed audit; the precheck before apply is
untouched (the workflow tests in test_remediation_workflow.py run on Temporal, in CI)."""

from __future__ import annotations

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


def _ask(log, policy, user=APPROVER, hours=24, now=None):
    return extend.request(log, policy, incident=INC, user=user, hours=hours, now=now or datetime.now(UTC))


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
    turn = discuss.Turn(channel=CHANNEL, thread_ts="1760000000.000100", ts="1760000000.000200", user=APPROVER,
                        text="<@UWARDEN> please extend the wait by 6 hours")
    got = talk.discuss_extend(turn, INC)
    assert got["hours"] == 6
    assert got["until_said"]
    assert not got.get("why")
    asked = log.entries(f"discuss-{INC}", kinds=("discuss.extend",))
    assert [(e["body"]["hours"], e["body"]["why"]) for e in asked] == [(6, "")]
    refused = talk.discuss_extend(turn.model_copy(update={"user": PERSON}), INC)
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
                        ("can you extend it", 24)):
        assert discuss.asks_to_extend(text), text
        assert discuss.hours_asked(text) == hours, text
    for text in ("will this extend the outage", "what is the plan?", "extend"):
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
