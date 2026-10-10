"""G10-C4: writes to the network a workload depends on. Recorded ecs-12 (a revoked egress rule) and ecs-13 (a deleted
route) were answered "no action" and "roll back": nothing WARDEN read said its security group or route table had just
changed. Looked up by event name (the attribute CloudTrail documents), kept only when the request names this
workload's own security group, route table, association or network ACL; and only on a network symptom."""

from __future__ import annotations

import json
from datetime import timedelta

from test_aws_stack import NOW, Fake, P, _alert, _backend, _clients, _ecs


def _event(name, request, *, error=None, minutes=10):
    detail = {"requestParameters": request, "userIdentity": {"type": "IAMUser", "userName": "ops"},
              **({"errorCode": error} if error else {})}
    return {"EventName": name, "EventTime": NOW - timedelta(minutes=minutes), "ReadOnly": "false",
            "CloudTrailEvent": json.dumps(detail)}


EVENTS = {
    "RevokeSecurityGroupEgress": [_event("RevokeSecurityGroupEgress", {"groupId": "sg-0ecs"}),
                                  _event("RevokeSecurityGroupEgress", {"groupId": "sg-0someone-else"}),
                                  _event("RevokeSecurityGroupEgress", {"groupId": "sg-0ecs"}, error="AccessDenied")],
    "DeleteRoute": [_event("DeleteRoute", {"routeTableId": "rtb-0app", "destinationCidrBlock": "0.0.0.0/0"})],
    "ModifySecurityGroupRules": [_event("ModifySecurityGroupRules",
                                        {"ModifySecurityGroupRulesRequest": {"GroupId": "sg-0ecs"}})],
}


def _read(stopped_cause_network=True, events=EVENTS):
    ecs = _ecs()
    svc = ecs._methods["describe_services"]["services"][0]
    svc["networkConfiguration"]["awsvpcConfiguration"]["subnets"] = ["subnet-0a"]
    if stopped_cause_network:
        ecs._methods["describe_tasks"]["tasks"][0]["stoppedReason"] = (
            "CannotPullContainerError: failed to resolve ref: dial tcp 52.0.0.1:443: i/o timeout")
    ec2 = _clients()["ec2"]
    ec2._methods.update(
        describe_subnets={"Subnets": [{"SubnetId": "subnet-0a", "VpcId": "vpc-0a"}]},
        describe_route_tables={"RouteTables": [{"RouteTableId": "rtb-0app", "Associations": [
            {"SubnetId": "subnet-0a", "RouteTableAssociationId": "rtbassoc-0a"}]}]},
        describe_network_acls={"NetworkAcls": [{"NetworkAclId": "acl-0a"}]})
    ct = Fake(lookup_events=lambda LookupAttributes, **_: {
        "Events": list(events.get(LookupAttributes[0]["AttributeValue"], []))}
        if LookupAttributes[0]["AttributeKey"] == "EventName" else {"Events": []})
    b = _backend(_clients(ecs=Fake(**ecs._methods), ec2=Fake(**ec2._methods), cloudtrail=ct))
    alert = _alert(ecs_cluster=f"{P}c", ecs_service=f"{P}orders-api")
    return b.logs(alert), b.metrics(alert), ct


def test_the_workloads_own_security_group_and_route_table_changes_are_named():
    lines, metrics, _ = _read()
    changes = [line for line in lines if line.startswith("CHANGE ") and "this workload's" in line]
    assert any("RevokeSecurityGroupEgress on sg-0ecs (this workload's security group) by user/ops" in c for c in changes)
    assert any("DeleteRoute on rtb-0app (this workload's route table)" in c for c in changes)
    assert any("ModifySecurityGroupRules on sg-0ecs" in c for c in changes)  # the newer APIs' request wrapper
    assert metrics["network_changes_before_alert"] == 3


def test_someone_elses_group_and_a_denied_attempt_are_not_this_workloads_changes():
    lines, _, _ = _read()
    assert not any("sg-0someone-else" in line for line in lines)
    assert sum("RevokeSecurityGroupEgress on sg-0ecs" in line for line in lines) == 1


def test_no_network_symptom_no_lookup():
    """CloudTrail allows two lookups a second: a secret that does not exist is not a network question."""
    _, metrics, ct = _read(stopped_cause_network=False)
    assert "network_changes_before_alert" not in metrics
    assert not [c for c in ct.calls if c[1]["LookupAttributes"][0]["AttributeKey"] == "EventName"]
