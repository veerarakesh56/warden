"""G10 v2 routes (owner decision 2026-10-10: routes only, T3 with a passkey): a route a person deleted or replaced, back
to the target AWS Config recorded just before the change (held-out route-deleted, cmp-multi-lambda-route-and-timeout).
Field names from AWS's Config resource schema AWS::EC2::RouteTable (configuration.routes.*, read 2026-10-10); EC2's own
DescribeRouteTables spells them in PascalCase."""

from __future__ import annotations

import json

import pytest

from test_aws_platform_g6 import ACCT, WHO
from test_revert_config_history_g10d3 import ALARM, Fake, _ci, _p, _trail
from warden import resolver
from warden.models import ActionKind, Alert, RemediationProposal, Severity
from warden.platforms.aws import AwsPlatformRefused

RTB = "rtb-0a1b2c3d4e5f60718"
RTB_ARN = f"arn:aws:ec2:test-region-1:{ACCT}:route-table/{RTB}"
NAT = "nat-0123456789abcdef0"
NAT2 = "nat-0fedcba9876543210"
LOCAL = {"destinationCidrBlock": "10.0.0.0/16", "gatewayId": "local"}


class Routes(Fake):
    """A private route table whose default route to the NAT gateway one person's DeleteRoute removed."""

    def __init__(self, event="DeleteRoute", request=None, before=None, after=None, now=None, agent=""):
        super().__init__()
        req = request or {"routeTableId": RTB, "destinationCidrBlock": "0.0.0.0/0",
                          **({"natGatewayId": NAT2} if event == "ReplaceRoute" else {})}
        self.events = [_trail(event, req, eid="r-1", source="ec2.amazonaws.com")]
        if agent:
            detail = json.loads(self.events[0]["CloudTrailEvent"])
            detail["userAgent"] = agent
            self.events[0]["CloudTrailEvent"] = json.dumps(detail)
        default = {"destinationCidrBlock": "0.0.0.0/0", "natGatewayId": NAT}
        moved = {"destinationCidrBlock": "0.0.0.0/0", "natGatewayId": NAT2}
        later = after if after is not None else ([LOCAL, moved] if event == "ReplaceRoute" else [LOCAL])
        self.history["AWS::EC2::RouteTable"] = [_ci(600, {"routes": before or [LOCAL, default]}),
                                                _ci(59, {"routes": later}, related=["r-1"])]
        self.routes = now if now is not None else [
            {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local", "State": "active"},
            *([{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": NAT2, "State": "active"}]
              if event == "ReplaceRoute" else [])]

    def describe_route_tables(self, RouteTableIds):
        return {"RouteTables": [{"RouteTableId": RTB, "OwnerId": ACCT, "Routes": list(self.routes),
                                 "Tags": [{"Key": "Environment", "Value": "dev"}]}]}


RP = {"alarm": ALARM, "route_table": RTB}


def test_a_deleted_default_route_is_created_again_to_the_nat_gateway_config_recorded():
    f = Routes()
    p = _p(f)
    live = p.live("ec2_restore_route", RP)
    assert live["event"] == {"r-1"}, live.get("refused")
    assert live["state"]["before"] == ["natGatewayId", NAT] and live["state"]["after"] is None
    params = {**RP, "event": "r-1"}
    p.apply("ec2_restore_route", params, snapshot=live["state"], who=WHO)
    assert f.sessions[-1] == {"actions": ["ec2:CreateRoute"], "resources": [RTB_ARN]}
    assert f.writes[-1] == ("create_route", {"RouteTableId": RTB, "DestinationCidrBlock": "0.0.0.0/0",
                                             "NatGatewayId": NAT})
    f.routes.append({"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": NAT, "State": "active"})
    f.alarm_state = "OK"
    assert p.healthy(RTB, entry="ec2_restore_route", params=params) is True
    # The rollback deletes the route WARDEN created again - the state the change left.
    p.rollback("ec2_restore_route", params, live["state"], who=WHO)
    assert f.sessions[-1]["actions"] == ["ec2:DeleteRoute"]
    assert f.writes[-1] == ("delete_route", {"RouteTableId": RTB, "DestinationCidrBlock": "0.0.0.0/0"})


def test_a_replaced_route_is_replaced_back():
    f = Routes(event="ReplaceRoute")
    p = _p(f)
    live = p.live("ec2_restore_route", RP)
    assert live["event"] == {"r-1"}, live.get("refused")
    p.apply("ec2_restore_route", {**RP, "event": "r-1"}, snapshot=live["state"], who=WHO)
    assert f.writes[-1] == ("replace_route", {"RouteTableId": RTB, "DestinationCidrBlock": "0.0.0.0/0",
                                              "NatGatewayId": NAT})


@pytest.mark.parametrize("fake, why", [
    (Routes(event="CreateRoute", request={"routeTableId": RTB, "destinationCidrBlock": "0.0.0.0/0",
                                          "natGatewayId": NAT}), "created a route"),
    (Routes(agent="APN/1.0 HashiCorp/1.0 Terraform/1.9.8"), "infrastructure as code"),
    (Routes(before=[LOCAL, {"destinationCidrBlock": "0.0.0.0/0", "gatewayId": "vpce-0abc12345678def00"}]),
     "no route to that destination"),  # a gateway endpoint's own route is not written
    (Routes(before=[LOCAL]), "no route to that destination"),
    (Routes(now=[{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": NAT2, "State": "active"}]), "moved since"),
    (Routes(request={"routeTableId": RTB}), "names no destination"),
])
def test_a_route_change_wardens_restore_may_not_undo_is_refused(fake, why):
    live = _p(fake).live("ec2_restore_route", RP)
    assert live["event"] == set() and why in live["refused"], live.get("refused")


def test_two_route_writes_to_the_table_are_a_choice_warden_does_not_make():
    f = Routes()
    f.events.append(_trail("ReplaceRoute", {"routeTableId": RTB, "destinationCidrBlock": "10.9.0.0/16",
                                            "natGatewayId": NAT}, eid="r-2", source="ec2.amazonaws.com"))
    assert "route write(s)" in _p(f).live("ec2_restore_route", RP)["refused"]


def test_a_route_restore_is_refused_when_the_route_came_back_after_the_plan():
    f = Routes()
    p = _p(f)
    snap = p.live("ec2_restore_route", RP)["state"]
    f.routes.append({"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": NAT, "State": "active"})
    with pytest.raises(AwsPlatformRefused):
        p.apply("ec2_restore_route", {**RP, "event": "r-1"}, snapshot=snap, who=WHO)
    assert f.writes == []


def test_the_resolver_plans_a_route_restore_from_the_route_table_the_model_names():
    f = Routes()
    alert = Alert(alert_id="a1", name="n", service="fn", environment="dev", severity=Severity.high, summary="",
                  started_at="2026-10-10T00:00:00+00:00", labels={"alarm": ALARM, "lambda": "warden-dev-fn"})
    proposal = RemediationProposal(action=ActionKind.revert_change, target=RTB, reasoning="r", expected_effect="e",
                                   blast_radius="single_service", reversible=True)
    req, why = resolver.request_for(alert, proposal, lambda e, params: _p(f).live(e, params))
    assert why == "" and req["entry"] == "ec2_restore_route" and req["params"] == {**RP, "event": "r-1"}
