"""Characterisation of platforms/aws.py's _sg_parse, _trail_change and _route_target_for, written BEFORE their
cognitive-complexity refactor (Sonar python:S3776) and passing on the code as it was: the same records, field by
field and in the same key order, the same refusals (None)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from warden.platforms import aws

AT = datetime(2026, 10, 12, 8, 30, 5, tzinfo=UTC)
GROUP = "sg-0123456789abcdef0"


def _who(**over):
    who = {"type": "AssumedRole", "userName": "plain-user", "invokedBy": "",
           "sessionContext": {"sessionIssuer": {"userName": "deployer"}, "sourceIdentity": "inc-7"}}
    who.update(over)
    return who


def _raw(event, **top):
    return {"CloudTrailEvent": json.dumps(event), **top}


def _sg_event(name="RevokeSecurityGroupIngress", **over):
    field = "revokedSecurityGroupRuleSet" if name.startswith("Revoke") else "securityGroupRuleSet"
    event = {"eventName": name, "eventID": "ev-1", "eventTime": "2026-10-12T08:30:05Z", "userIdentity": _who(),
             "userAgent": "aws-cli/2", "requestParameters": {"groupId": GROUP},
             "responseElements": {field: {"items": [
                 {"groupId": GROUP, "isEgress": False, "ipProtocol": "tcp", "fromPort": 443, "toPort": 443,
                  "cidrIpv4": "10.0.0.0/8", "securityGroupRuleId": "sgr-2"},
                 {"groupId": GROUP, "isEgress": False, "ipProtocol": "-1", "fromPort": -1, "toPort": -1,
                  "cidrIpv6": "::/0", "securityGroupRuleId": "sgr-1"}]}}}
    event.update(over)
    return event


SG_KEYS = ["event", "event_name", "kind", "egress", "at", "event_time", "rules", "rule_ids", "who_type",
           "invoked_by", "source_identity", "actor_name", "actor", "user_agent", "truncated"]


def test_sg_parse_a_revoke_exactly():
    got = aws._sg_parse(_raw(_sg_event()), GROUP)
    assert list(got) == SG_KEYS
    assert got == {"event": "ev-1", "event_name": "RevokeSecurityGroupIngress", "kind": "revoke", "egress": False,
                   "at": AT, "event_time": "2026-10-12T08:30:05Z",
                   "rules": sorted([[False, "tcp", 443, 443, "cidr4", "10.0.0.0/8"], [False, "-1", -1, -1, "cidr6", "::/0"]],
                                   key=json.dumps),
                   "rule_ids": ["sgr-1", "sgr-2"], "who_type": "AssumedRole", "invoked_by": "",
                   "source_identity": "inc-7", "actor_name": "deployer", "actor": "assumedrole/deployer",
                   "user_agent": "aws-cli/2", "truncated": False}


def test_sg_parse_an_authorize_egress_with_the_top_level_fields_first():
    event = _sg_event("AuthorizeSecurityGroupEgress", userIdentity={"type": "IAMUser", "userName": "bob"})
    got = aws._sg_parse(_raw(event, EventName="AuthorizeSecurityGroupEgress", EventId="top-id",
                             EventTime=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)), GROUP)
    assert (got["event"], got["kind"], got["egress"], got["event_time"]) == (
        "top-id", "authorize", True, "2026-01-02T03:04:05Z")
    assert (got["actor_name"], got["actor"], got["source_identity"], got["who_type"]) == (
        "bob", "iamuser/bob", "", "IAMUser")


def test_sg_parse_what_it_cannot_read_is_said():
    no_response = aws._sg_parse(_raw(_sg_event(responseElements=None)), GROUP)
    assert (no_response["rules"], no_response["rule_ids"], no_response["truncated"]) == ([], [], True)
    empty = aws._sg_parse(_raw(_sg_event(responseElements={"revokedSecurityGroupRuleSet": {"items": []}})), GROUP)
    assert empty["truncated"] is True
    bare = aws._sg_parse(_raw({"eventName": "RevokeSecurityGroupEgress", "requestParameters": {"groupId": GROUP}}),
                         GROUP)
    assert {k: bare[k] for k in ("event", "at", "event_time", "actor_name", "actor", "who_type", "user_agent")} == {
        "event": "", "at": None, "event_time": "?", "actor_name": "", "actor": "?/?", "who_type": "", "user_agent": ""}


@pytest.mark.parametrize("raw", [
    {"CloudTrailEvent": "{not json"},
    {},
    _raw(_sg_event("CreateSecurityGroup")),
    _raw(_sg_event(errorCode="Client.UnauthorizedOperation")),
    _raw(_sg_event(requestParameters={"groupId": "sg-other"})),
    _raw(_sg_event(requestParameters=None)),
])
def test_sg_parse_refuses(raw):
    assert aws._sg_parse(raw, GROUP) is None


TRAIL_KEYS = ["event", "event_name", "at", "event_time", "request", "who_type", "invoked_by", "source_identity",
              "actor_name", "actor", "user_agent"]


def test_trail_change_exactly():
    event = {"eventName": "UpdateFunctionConfiguration", "eventID": "ev-9", "eventTime": "2026-10-12T08:30:05Z",
             "requestParameters": {"functionName": "f", "timeout": 3}, "userAgent": "Terraform/1.9",
             "userIdentity": _who(type="AWSService", invokedBy="lambda.amazonaws.com", sessionContext=None)}
    got = aws._trail_change(_raw(event))
    assert list(got) == TRAIL_KEYS
    assert got == {"event": "ev-9", "event_name": "UpdateFunctionConfiguration", "at": AT,
                   "event_time": "2026-10-12T08:30:05Z", "request": {"functionName": "f", "timeout": 3},
                   "who_type": "AWSService", "invoked_by": "lambda.amazonaws.com", "source_identity": "",
                   "actor_name": "plain-user", "actor": "awsservice/plain-user", "user_agent": "Terraform/1.9"}


def test_trail_change_a_request_that_is_not_an_object_is_none_and_top_fields_win():
    got = aws._trail_change(_raw({"eventName": "x", "requestParameters": ["a"]}, EventName="Top", EventId="t"))
    assert (got["request"], got["event_name"], got["event"], got["at"], got["event_time"], got["actor"]) == (
        None, "Top", "t", None, "?", "?/?")


@pytest.mark.parametrize("raw", [{"CloudTrailEvent": "nope"}, _raw({"errorCode": "AccessDenied"})])
def test_trail_change_refuses(raw):
    assert aws._trail_change(raw) is None


def test_trail_change_an_empty_record_is_a_record():
    assert aws._trail_change({}) == {"event": "", "event_name": "", "at": None, "event_time": "?", "request": None,
                                     "who_type": "", "invoked_by": "", "source_identity": "", "actor_name": "",
                                     "actor": "?/?", "user_agent": ""}


ROUTES = [
    "not a route",
    {"destinationCidrBlock": "10.1.0.0/16", "natGatewayId": "nat-1"},
    {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "local", "NatGatewayId": ""},
    {"destinationCidrBlock": "0.0.0.0/0", "gatewayId": "igw-0123456789abcdef0"},
    {"destinationIpv6CidrBlock": "::/0", "egressOnlyInternetGatewayId": "eigw-1"},
    {"destinationPrefixListId": "pl-1", "gatewayId": "vpce-1", "networkInterfaceId": "eni-1"},
]


@pytest.mark.parametrize(("routes", "dest", "target"), [
    (ROUTES, ("destinationCidrBlock", "10.1.0.0/16"), ["natGatewayId", "nat-1"]),
    (ROUTES, ["destinationIpv6CidrBlock", "::/0"], ["egressOnlyInternetGatewayId", "eigw-1"]),
    (ROUTES, ("destinationCidrBlock", "0.0.0.0/0"), None),             # the first route to it: `local`, not WARDEN's
    (ROUTES[3:], ("destinationCidrBlock", "0.0.0.0/0"), ["gatewayId", "igw-0123456789abcdef0"]),
    (ROUTES, ("destinationPrefixListId", "pl-1"), ["networkInterfaceId", "eni-1"]),  # a vpce gateway is skipped
    (ROUTES, ("destinationCidrBlock", "10.9.0.0/16"), None),
    (ROUTES, None, None),
    (ROUTES, (), None),
    ([], ("destinationCidrBlock", "10.1.0.0/16"), None),
    ([{"destinationCidrBlock": "10.1.0.0/16"}], ("destinationCidrBlock", "10.1.0.0/16"), None),
])
def test_route_target_for(routes, dest, target):
    assert aws._route_target_for(routes, dest) == target
