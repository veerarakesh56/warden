"""A DynamoDB table's provisioned capacity back to what AWS Config recorded before ONE recorded cut (2026-10-11; held-out
g10-092, g10-107, g10-130: a person cut a table's write capacity and the undo had no entry). Only a cut is undone, only
of the table's own read and write units: never a billing mode, an index, a raise, or a table an autoscaler owns.
Field names: AWS::DynamoDB::Table configuration.provisionedThroughput.readCapacityUnits / .writeCapacityUnits
(awslabs/aws-config-resource-schema, read 2026-10-11); CloudTrail's UpdateTable request in the API's own casing."""

from __future__ import annotations

import pytest

from test_aws_platform_g6 import ACCT, WHO
from test_revert_config_history_g10d3 import ALARM, Fake, _ci, _p, _trail
from warden import catalog, grounding, resolver
from warden.models import ActionKind, Alert, Citation, RemediationProposal, RootCause, Severity
from warden.platforms.aws import AwsPlatformRefused

T = "warden-dev-carts"
T_ARN = f"arn:aws:dynamodb:test-region-1:{ACCT}:table/{T}"
TP = {"alarm": ALARM, "table": T}
PLAN = {**TP, "event": "d-1", "throughput": "100/400"}


def _units(read, write):
    return {"provisionedThroughput": {"readCapacityUnits": read, "writeCapacityUnits": write}}


class Tables(Fake):
    """A table whose write capacity one person's UpdateTable cut from 400 to 50 units."""

    def __init__(self, request=None, before=(100, 400)):
        super().__init__()
        self.units, self.mode, self.status = [100, 50], "PROVISIONED", "ACTIVE"
        self.events = [_trail("UpdateTable", request or {"tableName": T, **_units(100, 50)}, eid="d-1",
                              source="dynamodb.amazonaws.com")]
        self.history["AWS::DynamoDB::Table"] = [_ci(600, _units(*before)), _ci(59, _units(100, 50), related=["d-1"])]

    def describe_table(self, TableName):
        return {"Table": {"TableName": T, "TableArn": T_ARN, "TableStatus": self.status,
                          "BillingModeSummary": {"BillingMode": self.mode},
                          "ProvisionedThroughput": {"ReadCapacityUnits": self.units[0],
                                                    "WriteCapacityUnits": self.units[1]}}}

    def list_tags_of_resource(self, ResourceArn):
        return {"Tags": [{"Key": "Environment", "Value": "dev"}]}

    def list_discovered_resources(self, resourceType, resourceName):
        if resourceType == "AWS::DynamoDB::Table":
            return {"resourceIdentifiers": [{"resourceType": resourceType, "resourceId": T, "resourceName": T}]}
        return super().list_discovered_resources(resourceType, resourceName)


def test_a_cut_capacity_is_set_back_judged_by_its_alarm_and_rolled_back_to_what_the_cut_set():
    f = Tables()
    p = _p(f)
    live = p.live("dynamodb_restore_capacity", TP)
    assert live["event"] == {"d-1"}, live
    assert live["throughput"] == {"100/400"}, live
    assert live["environment"] == "dev", live
    assert catalog.validate("dynamodb_restore_capacity", PLAN, live) == []
    assert "read/write capacity units of table warden-dev-carts: 100/50 -> 100/400" in catalog.change_of(
        "dynamodb_restore_capacity", PLAN, live["state"])[0]
    p.apply("dynamodb_restore_capacity", PLAN, snapshot=live["state"], who=WHO)
    assert f.sessions == [{"actions": ["dynamodb:UpdateTable"], "resources": [T_ARN]}]
    assert f.writes == [("update_table", {"TableName": T, "ProvisionedThroughput": {
        "ReadCapacityUnits": 100, "WriteCapacityUnits": 400}})]
    f.units = [100, 400]
    assert not p.healthy(T, entry="dynamodb_restore_capacity", params=PLAN)  # the alarm still reads ALARM
    f.alarm_state = "OK"
    assert p.healthy(T, entry="dynamodb_restore_capacity", params=PLAN)
    f.status = "UPDATING"
    assert not p.healthy(T, entry="dynamodb_restore_capacity", params=PLAN)
    f.status, f.units = "ACTIVE", [100, 300]
    assert not p.healthy(T, entry="dynamodb_restore_capacity", params=PLAN)
    f.units = [100, 400]
    p.rollback("dynamodb_restore_capacity", PLAN, live["state"], who=WHO)
    assert f.writes[-1] == ("update_table", {"TableName": T, "ProvisionedThroughput": {
        "ReadCapacityUnits": 100, "WriteCapacityUnits": 50}})


@pytest.mark.parametrize("fake, why", [
    (Tables(request={"tableName": T, **_units(100, 50), "billingMode": "PROVISIONED"}), "also set billingMode"),
    (Tables(request={"tableName": T, **_units(100, 50), "globalSecondaryIndexUpdates": []}),
     "also set globalSecondaryIndexUpdates"),
    (Tables(request={"tableName": T, "onDemandThroughput": {"maxWriteRequestUnits": 100}}), "also set onDemandThroughput"),
    (Tables(before=(100, 50)), "no higher capacity"),  # nothing was cut
    (Tables(before=(100, 40)), "no higher capacity"),  # the change raised it
    (Tables(before=(50, 400)), "no higher capacity"),  # read raised with write cut: a person's trade
    (Tables(before=(0, 0)), "no higher capacity"),  # the table was on demand before
    (Tables(request={"tableName": T, **_units(100, 60)}), "moved since"),  # Config's record is not this request
])
def test_a_table_change_wardens_restore_may_not_undo_is_refused(fake, why):
    live = _p(fake).live("dynamodb_restore_capacity", TP)
    assert live["throughput"] == set(), live.get("refused")
    assert live["event"] == set(), live.get("refused")
    assert why in live["refused"], live.get("refused")


@pytest.mark.parametrize("change, why", [
    (lambda f: setattr(f, "mode", "PAY_PER_REQUEST"), "not in provisioned capacity mode"),
    (lambda f: f.scaled.append({"ResourceId": f"table/{T}"}), "autoscaler"),
    (lambda f: setattr(f, "units", [100, 80]), "moved since"),
    (lambda f: setattr(f, "alarm_state", "OK"), "not in ALARM"),
    (lambda f: f.events.append(_trail("UpdateTable", {"tableName": T, **_units(100, 50)}, eid="d-2",
                                      source="dynamodb.amazonaws.com")), "2 change(s)"),
    (lambda f: f.events.__setitem__(0, _trail("UpdateTable", {"tableName": "warden-dev-other", **_units(100, 50)},
                                              eid="d-1", source="dynamodb.amazonaws.com")), "no recorded"),
    (lambda f: f.events.__setitem__(0, _trail("UpdateTable", {"tableName": T, **_units(100, 50)}, eid="d-1",
                                              source="dynamodb.amazonaws.com", minutes_before_alarm=-5)),
     "after the alarm"),
    (lambda f: f.history.__setitem__("AWS::DynamoDB::Table", [_ci(59, _units(100, 50), related=["d-1"])]),
     "no record of the resource before"),
])
def test_a_table_that_is_not_as_the_cut_left_it_is_refused(change, why):
    f = Tables()
    change(f)
    live = _p(f).live("dynamodb_restore_capacity", TP)
    assert live["throughput"] == set(), live.get("refused")
    assert why in live["refused"], live.get("refused")


def test_a_table_still_updating_is_not_acted_on():
    f = Tables()
    f.status = "UPDATING"
    live = _p(f).live("dynamodb_restore_capacity", TP)
    assert any("P21" in problem for problem in catalog.validate("dynamodb_restore_capacity", PLAN, live))


def test_a_capacity_that_moved_after_the_plan_is_never_written_over():
    f = Tables()
    p = _p(f)
    snap = p.live("dynamodb_restore_capacity", TP)["state"]
    f.units = [100, 80]
    with pytest.raises(AwsPlatformRefused):
        p.apply("dynamodb_restore_capacity", PLAN, snapshot=snap, who=WHO)
    for bad in ("100", "0/400", "100/x", "-1/400", "100/400/1"):
        g = Tables()
        q = _p(g)
        with pytest.raises(AwsPlatformRefused):
            q.apply("dynamodb_restore_capacity", {**PLAN, "throughput": bad},
                    snapshot=q.live("dynamodb_restore_capacity", TP)["state"], who=WHO)
        assert g.writes == []
    assert f.writes == []


def _proposal():
    return RemediationProposal(action=ActionKind.revert_change, target=T, reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)


def test_the_resolver_plans_the_restore_from_the_tables_label_and_it_has_a_fix_path():
    alert = Alert(alert_id="a1", name="n", service=T, environment="dev", severity=Severity.high, summary="",
                  started_at="2026-10-10T00:00:00+00:00", labels={"alarm": ALARM, "dynamodb_table": T})
    f = Tables()
    request, why = resolver.request_for(alert, _proposal(), lambda e, params: _p(f).live(e, params))
    assert why == "", why
    assert request["entry"] == "dynamodb_restore_capacity", why
    assert request["params"] == PLAN, why
    assert resolver.no_fix_path(alert, _proposal()) == ""
    g = Tables(before=(100, 40))
    request, why = resolver.request_for(alert, _proposal(), lambda e, params: _p(g).live(e, params))
    assert request is None
    assert "no higher capacity" in why


def test_every_config_type_a_restore_reads_is_in_the_owners_recorder_step():
    """A type the recorder does not record is a restore that always refuses (the table's was missing, 2026-10-11)."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    read = set(re.findall(r'"(AWS::[A-Za-z0-9]+::[A-Za-z0-9]+)"',
                          (root / "src/warden/platforms/aws.py").read_text(encoding="utf-8")))
    step = (root / "docs/SETUP.md").read_text(encoding="utf-8")
    assert "AWS::DynamoDB::Table" in read
    assert len(read) >= 8
    assert sorted(t for t in read if f"`{t}`" not in step) == []


def _support(line):
    from warden.evidence import Item

    items = {"C2": Item(id="C2", text=line)}
    cause = RootCause(hypothesis="h", confidence=0.9, citations=[Citation(id="C2", quote="UpdateTable on carts")])
    return grounding.action_support_problem(cause, _proposal(), items)


def test_only_an_update_table_that_set_the_tables_own_capacity_supports_the_revert():
    base = "CHANGE 2026-10-10T07:31:18Z dynamodb.amazonaws.com UpdateTable on carts by user/j.mehta"
    assert _support(base) is None  # a line without the request's fields: as before
    assert _support(base + " request=provisionedThroughput,tableName") is None
    assert "names a write" in _support(base + " request=billingMode,tableName")
    assert "names a write" in _support(base + " request=onDemandThroughput,tableName")
