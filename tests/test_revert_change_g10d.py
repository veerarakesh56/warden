"""G10-D1: undo ONE security group change CloudTrail recorded before the alarm (research g10-undo-change.md, owner
decisions 2026-10-10). The event decides the write - a revoke is undone by authorizing exactly its rules, an
authorize by revoking exactly the rules it created - and every refusal the research names holds: a change after the
alarm, by root, by an AWS service, by WARDEN, by a named security principal, more than one write, ingress from the
whole internet, a record CloudTrail cut short, rules already back."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from test_aws_fixes_g9d import ALARM, Config
from test_aws_platform_g6 import ACCT, NOW, WHO
from warden import catalog, resolver
from warden.models import ActionKind, Alert, RemediationProposal, Severity
from warden.platforms.aws import AwsPlatform, AwsPlatformRefused

SG = "sg-0abc1234def567890"
SG_ARN = f"arn:aws:ec2:test-region-1:{ACCT}:security-group/{SG}"
EGRESS_443 = {"groupId": SG, "securityGroupRuleId": "sgr-0old", "isEgress": True, "ipProtocol": "tcp",
              "fromPort": 443, "toPort": 443, "cidrIpv4": "0.0.0.0/0"}


def _event(name, *, minutes_before_alarm=60, items=(EGRESS_443,), who=None, error=None, eid="e-1", group=SG,
           response=True):
    field = "revokedSecurityGroupRuleSet" if name.startswith("Revoke") else "securityGroupRuleSet"
    detail = {"eventName": name, "requestParameters": {"groupId": group},
              "userIdentity": who or {"type": "AssumedRole", "sessionContext": {"sessionIssuer": {"userName": "ops"}}},
              **({"responseElements": {"_return": True, field: {"items": list(items)}}} if response else {}),
              **({"errorCode": error} if error else {})}
    return {"EventId": eid, "EventName": name, "EventTime": NOW - timedelta(minutes=30 + minutes_before_alarm),
            "CloudTrailEvent": json.dumps(detail)}


class Groups(Config):
    """A security group, its rules, and the CloudTrail events that changed them. The alarm went into ALARM 30 minutes
    before NOW (Config.describe_alarms)."""

    def __init__(self):
        super().__init__()
        self.sg_rules = []  # the egress rule was revoked: it is not there
        self.sg_events = [_event("RevokeSecurityGroupEgress")]
        self.sg_tags = [{"Key": "Environment", "Value": "dev"}]

    def describe_security_groups(self, GroupIds):
        return {"SecurityGroups": [{"GroupId": g, "OwnerId": ACCT, "Tags": list(self.sg_tags)} for g in GroupIds]}

    def describe_security_group_rules(self, Filters):
        return {"SecurityGroupRules": [dict(r) for r in self.sg_rules]}

    def lookup_events(self, **kw):
        attrs = kw.get("LookupAttributes") or [{}]
        key, value = attrs[0].get("AttributeKey"), attrs[0].get("AttributeValue")
        if key == "EventName":
            return {"Events": [e for e in self.sg_events if e["EventName"] == value]}
        if key == "EventId":
            return {"Events": [e for e in self.sg_events if e["EventId"] == value]}
        return super().lookup_events(**kw)


def _platform(f):
    return AwsPlatform(reader=lambda service: f, actor=f.actor, clock=lambda: NOW, sleep=lambda s: None)


PARAMS = {"alarm": ALARM, "group": SG}


def test_a_revoked_egress_rule_is_authorized_again_exactly_and_only_on_that_group():
    f = Groups()
    p = _platform(f)
    live = p.live("ec2_revert_sg_change", PARAMS)
    assert live["event"] == {"e-1"} and live["environment"] == "dev", live.get("refused")
    plan = {**PARAMS, "event": "e-1"}
    assert catalog.validate("ec2_revert_sg_change", plan, live) == []
    p.apply("ec2_revert_sg_change", plan, snapshot=live["state"], who=WHO)
    [session] = f.sessions
    assert session["actions"] == ["ec2:AuthorizeSecurityGroupEgress"]
    assert session["resources"] == [SG_ARN, f"arn:aws:ec2:test-region-1:{ACCT}:security-group-rule/*"]
    assert f.writes == [("authorize_security_group_egress", {"GroupId": SG, "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]})]


def test_health_is_the_rule_back_and_the_alarm_ok_and_the_rollback_revokes_it_again():
    f = Groups()
    p = _platform(f)
    plan = {**PARAMS, "event": "e-1"}
    snap = p.live("ec2_revert_sg_change", PARAMS)["state"]
    f.sg_rules = [{"GroupId": SG, "SecurityGroupRuleId": "sgr-0new", "IsEgress": True, "IpProtocol": "tcp",
                   "FromPort": 443, "ToPort": 443, "CidrIpv4": "0.0.0.0/0"}]
    assert not p.healthy(SG, entry="ec2_revert_sg_change", params=plan)  # the alarm still reads ALARM
    f.alarm_state = "OK"
    assert p.healthy(SG, entry="ec2_revert_sg_change", params=plan)
    p.rollback("ec2_revert_sg_change", plan, snap, who=WHO)
    assert f.sessions[-1]["actions"] == ["ec2:RevokeSecurityGroupEgress"] and f.sessions[-1]["resources"] == [SG_ARN]
    assert f.writes[-1][0] == "revoke_security_group_egress"


def test_an_added_ingress_rule_is_revoked_by_the_rule_it_created_only():
    f = Groups()
    rule = {"groupId": SG, "securityGroupRuleId": "sgr-0added", "isEgress": False, "ipProtocol": "tcp",
            "fromPort": 22, "toPort": 22, "cidrIpv4": "203.0.113.0/24"}
    f.sg_events = [_event("AuthorizeSecurityGroupIngress", items=(rule,))]
    f.sg_rules = [{"GroupId": SG, "SecurityGroupRuleId": "sgr-0added", "IsEgress": False, "IpProtocol": "tcp",
                   "FromPort": 22, "ToPort": 22, "CidrIpv4": "203.0.113.0/24"}]
    p = _platform(f)
    live = p.live("ec2_revert_sg_change", PARAMS)
    assert live["event"] == {"e-1"}, live.get("refused")
    p.apply("ec2_revert_sg_change", {**PARAMS, "event": "e-1"}, snapshot=live["state"], who=WHO)
    assert f.sessions[0]["actions"] == ["ec2:RevokeSecurityGroupIngress"] and f.sessions[0]["resources"] == [SG_ARN]
    assert f.writes[0][1]["IpPermissions"][0]["IpRanges"] == [{"CidrIp": "203.0.113.0/24"}]


@pytest.mark.parametrize("change, why", [
    (lambda f: f.sg_events.__setitem__(0, _event("RevokeSecurityGroupEgress", minutes_before_alarm=-10)),
     "after the alarm"),
    (lambda f: f.sg_events.__setitem__(0, _event("RevokeSecurityGroupEgress", minutes_before_alarm=60 * 7)),
     "no recorded write"),
    (lambda f: f.sg_events.append(_event("AuthorizeSecurityGroupEgress", eid="e-2")), "2 writes"),
    (lambda f: f.sg_events.__setitem__(0, _event("RevokeSecurityGroupEgress", who={"type": "Root"})), "root"),
    (lambda f: f.sg_events.__setitem__(0, _event("RevokeSecurityGroupEgress", who={
        "type": "AWSService", "invokedBy": "config.amazonaws.com"})), "AWS service"),
    (lambda f: f.sg_events.__setitem__(0, _event("RevokeSecurityGroupEgress", who={
        "type": "AssumedRole", "sessionContext": {"sourceIdentity": "inc-7", "sessionIssuer": {"userName": "x"}}})),
     "WARDEN's own"),
    (lambda f: f.sg_events.__setitem__(0, _event("RevokeSecurityGroupIngress", items=(
        {**EGRESS_443, "isEgress": False},))), "whole internet"),
    (lambda f: f.sg_events.__setitem__(0, _event("RevokeSecurityGroupEgress", response=False)), "did not record"),
    (lambda f: f.sg_rules.append({"GroupId": SG, "IsEgress": True, "IpProtocol": "tcp", "FromPort": 443,
                                  "ToPort": 443, "CidrIpv4": "0.0.0.0/0"}), "back already"),
    (lambda f: setattr(f, "alarm_state", "OK"), "not in ALARM"),
])
def test_every_refusal_allows_no_event_and_says_why(change, why):
    f = Groups()
    change(f)
    live = _platform(f).live("ec2_revert_sg_change", PARAMS)
    assert live["event"] == set() and why in live["refused"], live.get("refused")


def test_a_named_security_principals_change_is_never_reverted(monkeypatch):
    monkeypatch.setenv("WARDEN_NEVER_REVERT_PRINCIPALS", "security-response, ops")
    live = _platform(Groups()).live("ec2_revert_sg_change", PARAMS)
    assert live["event"] == set() and "never reverts" in live["refused"]


def test_a_failed_attempt_and_another_groups_change_are_not_this_groups_writes():
    f = Groups()
    f.sg_events += [_event("RevokeSecurityGroupEgress", error="AccessDenied", eid="e-2"),
                    _event("AuthorizeSecurityGroupEgress", group="sg-0someoneelse0000", eid="e-3")]
    assert _platform(f).live("ec2_revert_sg_change", PARAMS)["event"] == {"e-1"}


def test_the_undo_is_refused_when_the_group_moved_since_the_approval():
    f = Groups()
    p = _platform(f)
    snap = p.live("ec2_revert_sg_change", PARAMS)["state"]
    f.sg_events[0] = _event("RevokeSecurityGroupEgress", items=({**EGRESS_443, "toPort": 444},))
    with pytest.raises(AwsPlatformRefused, match="changed since the plan was approved"):
        p.apply("ec2_revert_sg_change", {**PARAMS, "event": "e-1"}, snapshot=snap, who=WHO)
    assert f.writes == []


def _alert(**labels):
    return Alert(alert_id="a1", name="n", service="orders", environment="dev", severity=Severity.high, summary="",
                 started_at="2026-10-10T00:00:00+00:00", labels={"alarm": ALARM, **labels})


def _revert(target):
    return RemediationProposal(action=ActionKind.revert_change, target=target, reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)


def test_the_resolver_plans_the_one_change_the_platform_allows_and_says_why_when_none():
    f = Groups()
    p = _platform(f)
    req, why = resolver.request_for(_alert(), _revert(SG), lambda e, params: p.live(e, params))
    assert why == "" and req["entry"] == "ec2_revert_sg_change" and req["params"] == {**PARAMS, "event": "e-1"}
    f.alarm_state = "OK"
    req, why = resolver.request_for(_alert(), _revert(SG), lambda e, params: p.live(e, params))
    assert req is None and "not in ALARM" in why


def test_a_disabled_rule_is_reverted_through_its_enable_entry():
    assert catalog.for_action(ActionKind.revert_change, "events").name == "events_enable_rule"
    assert catalog.for_action(ActionKind.revert_change, "lambda").name == "lambda_enable_esm"
