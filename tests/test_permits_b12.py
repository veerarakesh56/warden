"""B12: before anyone is asked to approve a plan, the actor role's own policies are asked (the IAM policy simulator,
read-only) whether they allow the exact calls the fix's apply and its undo would make - the calls traced from the
entry's own write code, which sends nothing while traced."""

from __future__ import annotations

import pytest

from test_apply_reverifies import _acts
from test_aws_platform_g6 import ACCT, FN, FN_ARN, WHO, Fake
from test_remediation_workflow import REQ
from warden import permits
from warden.activities import FixRequest
from warden.platforms import RoutedPlatform
from warden.platforms.aws import _KINDS, AwsPlatform

ROLE = f"arn:aws:iam::{ACCT}:role/warden-dev-actor"


class Iam:
    """The policy simulator: allows `allow`, denies the rest; `missing` makes a call undecidable for want of a key."""

    def __init__(self, allow=(), missing=(), page=0):
        self.allow, self.missing, self.page, self.asked = set(allow), set(missing), page, []

    def simulate_principal_policy(self, **kw):
        self.asked.append(kw)
        results = []
        for a in kw["ActionNames"]:
            decision = "allowed" if a in self.allow else "implicitDeny"
            results.append({"EvalActionName": a, "EvalDecision": decision, "ResourceSpecificResults": [
                {"EvalResourceName": r, "EvalResourceDecision": decision,
                 "MissingContextValues": sorted(self.missing) if decision != "allowed" else []}
                for r in kw["ResourceArns"]]})
        if self.page and "Marker" not in kw:  # the first page only says there is a second
            return {"EvaluationResults": [], "IsTruncated": True, "Marker": "m2"}
        return {"EvaluationResults": results, "IsTruncated": False}


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.delenv("WARDEN_AWS_ROLE_ARN_TEMPLATE", raising=False)
    monkeypatch.setenv("WARDEN_AWS_ACTOR_ROLE_ARN", ROLE)
    f = Fake()
    return f, AwsPlatform(reader=lambda service: f.iam if service == "iam" else f, actor=f.actor,
                          sleep=lambda s: None)


def _rule(f, p, iam):
    f.iam = iam
    params = {"rule": f.rule["Name"]}
    snap = p.live("events_enable_rule", params)["state"]
    return p.permitted("events_enable_rule", params, snap, incident="7", environment="dev")


def test_the_apply_and_its_undo_are_checked_and_nothing_is_sent(aws):
    f, p = aws
    got = _rule(f, p, Iam(allow={"events:EnableRule", "events:DisableRule"}))
    assert got["checked"] is True and got["denied"] == [] and got["unconfirmed"] == []
    assert [(c["step"], c["actions"]) for c in got["calls"]] == [("apply", ["events:EnableRule"]),
                                                                 ("undo", ["events:DisableRule"])]
    # The trace minted no actor session and sent no write: only the simulator was asked.
    assert f.writes == [] and f.sessions == []
    asked = f.iam.asked[0]
    assert asked["PolicySourceArn"] == ROLE and asked["ResourceArns"] == [f.rule["Arn"]]
    context = {c["ContextKeyName"]: c["ContextKeyValues"] for c in asked["ContextEntries"]}
    assert context == {"aws:SourceIdentity": ["inc-7"], "aws:ResourceTag/Environment": ["dev"]}


def test_an_undo_the_role_does_not_allow_refuses_the_plan(aws):
    f, p = aws
    got = _rule(f, p, Iam(allow={"events:EnableRule"}))
    [denied] = got["denied"]
    assert denied.startswith("ACTOR-PERMISSION: the actor role warden-dev-actor may not events:DisableRule")
    assert "undo" in denied and ACCT not in denied  # the resource is said without the account


def test_an_apply_the_role_does_not_allow_refuses_the_plan(aws):
    f, p = aws
    got = _rule(f, p, Iam(allow={"events:DisableRule"}))
    assert [d.split(" on ")[0] for d in got["denied"]] == [
        "ACTOR-PERMISSION: the actor role warden-dev-actor may not events:EnableRule"]


def test_a_key_warden_cannot_supply_is_unconfirmed_not_refused(aws):
    f, p = aws
    got = _rule(f, p, Iam(allow={"events:EnableRule"}, missing={"aws:PrincipalTag/team"}))
    assert got["denied"] == []
    assert got["unconfirmed"] == [(f"undo: events:DisableRule on rule/{f.rule['Name']} needs aws:PrincipalTag/team, "
                                   "which WARDEN cannot supply")]


def test_every_page_of_the_simulators_answer_is_read(aws):
    f, p = aws
    got = _rule(f, p, Iam(allow={"events:EnableRule"}, page=1))
    assert len(got["denied"]) == 1 and [a.get("Marker") for a in f.iam.asked] == [None, "m2", None, "m2"]


def test_the_sessions_own_condition_keys_are_supplied(aws):
    f, p = aws
    f.iam = Iam(allow={"lambda:UpdateEventSourceMapping"})
    params = {"function": FN, "mapping": "u-1"}
    snap = p.live("lambda_enable_esm", params)["state"]
    got = p.permitted("lambda_enable_esm", params, snap, incident="inc-7", environment="dev")
    assert got["denied"] == [] and got["checked"] is True
    context = {c["ContextKeyName"]: c["ContextKeyValues"] for c in f.iam.asked[0]["ContextEntries"]}
    assert context["lambda:FunctionArn"] == [FN_ARN] and context["aws:SourceIdentity"] == ["inc-7"]


def test_a_canary_write_is_traced_without_its_wait_or_its_write(aws):
    f, p = aws
    f.iam = Iam(allow={"lambda:UpdateAlias"})
    params = {"function": FN, "alias": "live", "to_version": "3"}
    snap = p.live("lambda_move_alias", params)["state"]
    got = p.permitted("lambda_move_alias", params, snap, incident="7", environment="dev")
    assert got["denied"] == [] and [c["actions"] for c in got["calls"]] == [["lambda:UpdateAlias"]] * 2
    assert f.writes == [] and f.sessions == []


def test_no_actor_role_or_a_refusing_write_code_is_unconfirmed(aws, monkeypatch):
    f, p = aws
    monkeypatch.delenv("WARDEN_AWS_ACTOR_ROLE_ARN")
    got = _rule(f, p, Iam())
    assert got["checked"] is False and got["denied"] == [] and "no actor role" in got["unconfirmed"][0]
    monkeypatch.setenv("WARDEN_AWS_ACTOR_ROLE_ARN", ROLE)
    f.iam = Iam()
    params = {"rule": f.rule["Name"]}
    snap = p.live("events_enable_rule", params)["state"]
    f.rule["State"] = "ENABLED"  # moved since the plan: the write code refuses before any session
    got = p.permitted("events_enable_rule", params, snap, incident="7", environment="dev")
    assert got["checked"] is False and got["denied"] == [] and "could not be traced" in got["unconfirmed"][0]
    assert f.iam.asked == []


def test_the_role_is_the_environments_actor(monkeypatch):
    monkeypatch.setenv("WARDEN_AWS_ROLE_ARN_TEMPLATE", f"arn:aws:iam::{ACCT}:role/warden-{{env}}-{{role}}")
    assert permits.actor_role_arn("dev") == ROLE
    monkeypatch.setenv("WARDEN_AWS_ROLE_ARN_TEMPLATE", f"arn:aws:iam::{ACCT}:role/fixed")
    assert permits.actor_role_arn("dev") == ""


def test_every_aws_entry_says_what_its_undo_calls():
    tables = (set(permits.UNDO), permits.SAME_UNDO, permits.NO_UNDO)
    for entry in _KINDS:
        assert sum(entry in t for t in tables) == 1, entry
    assert set().union(*tables) == set(_KINDS)


@pytest.mark.parametrize("entry", sorted(permits.NO_UNDO))
def test_an_entry_without_an_undo_really_undoes_nothing(entry):
    p = AwsPlatform(reader=lambda s: None, actor=lambda *a, **k: None)
    assert p.rollback(entry, {}, {}, who=WHO).startswith("nothing to roll back")


def test_the_undo_table_holds_what_the_real_undo_asks_for(aws):
    f, p = aws
    params = {"rule": f.rule["Name"]}
    snap = p.live("events_enable_rule", params)["state"]
    f.iam = Iam(allow={"events:EnableRule", "events:DisableRule"})
    said = p.permitted("events_enable_rule", params, snap, incident="7", environment="dev")
    f.rule["State"] = "ENABLED"
    p.rollback("events_enable_rule", params, snap, who=WHO)
    assert f.sessions[-1]["actions"] == next(c for c in said["calls"] if c["step"] == "undo")["actions"]


def test_the_routed_platform_asks_the_platform_that_carries_the_entry(aws):
    f, p = aws
    f.iam = Iam(allow={"events:EnableRule", "events:DisableRule"})
    routed = RoutedPlatform(events=p)
    snap = p.live("events_enable_rule", {"rule": f.rule["Name"]})["state"]
    assert routed.permitted("events_enable_rule", {"rule": f.rule["Name"]}, snap, "7", "dev")["checked"] is True
    assert routed.permitted("k8s_restart", {}, {}, "7", "dev") is None  # no Kubernetes platform connected


def test_a_plan_the_actor_may_not_carry_out_is_refused_before_any_approval_is_asked():
    acts, platform, _ = _acts()
    platform.permitted = lambda entry, params, snapshot, incident, environment: {
        "checked": True, "denied": ["ACTOR-PERMISSION: the actor role r may not x on y (implicitDeny), ..."],
        "unconfirmed": []}
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert [p for p in plan.problems if p.startswith("ACTOR-PERMISSION")]
    [row] = acts.audit.entries(REQ["incident_id"], kinds=("remediation.permissions",))
    assert row["body"]["workflow_id"] == "rem-1" and row["body"]["checked"] is True


def test_a_failed_check_refuses_nothing_and_is_recorded():
    acts, platform, _ = _acts()

    def boom(*a, **k):
        raise RuntimeError("simulator unreachable")

    platform.permitted = boom
    plan = acts.resolve_plan(FixRequest(**REQ), "rem-1")
    assert plan.problems == []
    [row] = acts.audit.entries(REQ["incident_id"], kinds=("remediation.permissions",))
    assert row["body"]["checked"] is False and "simulator unreachable" in row["body"]["unconfirmed"][0]


def test_a_platform_without_the_check_refuses_nothing_and_writes_no_row():
    acts, _, _ = _acts()
    assert acts.resolve_plan(FixRequest(**REQ), "rem-1").problems == []
    assert acts.audit.entries(REQ["incident_id"], kinds=("remediation.permissions",)) == []


def test_a_simulator_that_cannot_be_read_is_unconfirmed_not_refused(aws):
    class Down:
        def simulate_principal_policy(self, **kw):
            raise OSError("connection reset")

    f, p = aws
    got = _rule(f, p, Down())
    assert got["checked"] is False and got["denied"] == []
    assert got["unconfirmed"] == ["the policy simulator could not be read: connection reset"]
