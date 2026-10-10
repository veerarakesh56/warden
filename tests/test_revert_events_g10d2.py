"""G10-D2: undoing a change whose own CloudTrail record holds the undo - targets a person deregistered, a key's
scheduled deletion, a deleted secret still in its recovery window. Each with the refusals every revert shares, and one
of its own: an ECS service's or Auto Scaling group's own deregistrations are AWS-made; a key cancelled stays disabled
(enabling it is a person's); a secret deleted without recovery is gone."""

from __future__ import annotations

import pytest

from test_aws_platform_g6 import ACCT, WHO
from test_revert_config_history_g10d3 import ALARM, Fake, _p, _trail
from warden import catalog, resolver
from warden.models import ActionKind, Alert, RemediationProposal, Severity

TG = "warden-dev-web-tg"
TG_ARN = f"arn:aws:elasticloadbalancing:test-region-1:{ACCT}:targetgroup/{TG}/abc"
KEY_ID = "1234abcd-12ab-34cd-56ef-1234567890ab"
KEY_ARN = f"arn:aws:kms:test-region-1:{ACCT}:key/{KEY_ID}"
SECRET = "warden-dev-db-app"
SECRET_ARN = f"arn:aws:secretsmanager:test-region-1:{ACCT}:secret:{SECRET}-AbCdEf"


class Reverts(Fake):
    def __init__(self):
        super().__init__()
        self.registered, self.health = set(), "healthy"
        self.key_state, self.key_manager, self.deleted = "PendingDeletion", "CUSTOMER", True
        self.events = [
            _trail("DeregisterTargets", {"targetGroupArn": TG_ARN, "targets": [{"id": "i-0aaa", "port": 80}]},
                   eid="t-1", source="elasticloadbalancing.amazonaws.com"),
            _trail("ScheduleKeyDeletion", {"keyId": KEY_ID, "pendingWindowInDays": 7}, eid="k-1", source="kms.amazonaws.com"),
            _trail("DeleteSecret", {"secretId": SECRET, "recoveryWindowInDays": 30}, eid="s-1",
                   source="secretsmanager.amazonaws.com")]

    def lookup_events(self, LookupAttributes, **kw):
        name = LookupAttributes[0]["AttributeValue"]
        return {"Events": [e for e in self.events if e["EventName"] == name]}

    # elbv2
    def describe_target_groups(self, Names):
        return {"TargetGroups": [{"TargetGroupName": TG, "TargetGroupArn": TG_ARN}]}

    def describe_tags(self, ResourceArns):
        return {"TagDescriptions": [{"ResourceArn": TG_ARN, "Tags": [{"Key": "Environment", "Value": "dev"}]}]}

    def describe_target_health(self, TargetGroupArn, Targets):
        return {"TargetHealthDescriptions": [
            {"Target": {"Id": t["Id"]}, "TargetHealth": {"State": self.health if t["Id"] in self.registered else "unused"}}
            for t in Targets]}

    # kms
    def describe_key(self, KeyId):
        return {"KeyMetadata": {"KeyId": KEY_ID, "Arn": KEY_ARN, "KeyState": self.key_state,
                                "KeyManager": self.key_manager}}

    def list_resource_tags(self, KeyId):
        return {"Tags": [{"TagKey": "Environment", "TagValue": "dev"}]}

    # secretsmanager
    def describe_secret(self, SecretId):
        return {"ARN": SECRET_ARN, "Name": SECRET, "Tags": [{"Key": "Environment", "Value": "dev"}],
                **({"DeletedDate": "2026-10-10T00:00:00Z"} if self.deleted else {})}


def test_targets_a_person_deregistered_are_registered_again_and_judged_by_their_health():
    f = Reverts()
    p = _p(f)
    params = {"alarm": ALARM, "target_group": TG}
    live = p.live("elb_reregister_targets", params)
    assert live["event"] == {"t-1"} and live["environment"] == "dev", live.get("refused")
    plan = {**params, "event": "t-1"}
    p.apply("elb_reregister_targets", plan, snapshot=live["state"], who=WHO)
    assert f.sessions[-1] == {"actions": ["elasticloadbalancing:RegisterTargets"], "resources": [TG_ARN]}
    assert f.writes[-1] == ("register_targets", {"TargetGroupArn": TG_ARN, "Targets": [{"Id": "i-0aaa", "Port": 80}]})
    f.registered, f.alarm_state = {"i-0aaa"}, "OK"
    f.health = "initial"
    assert not p.healthy(TG, entry="elb_reregister_targets", params=plan)
    f.health = "healthy"
    assert p.healthy(TG, entry="elb_reregister_targets", params=plan)


def test_an_ecs_services_own_deregistration_is_aws_made_and_a_registered_target_is_back_already():
    f = Reverts()
    f.events[0] = _trail("DeregisterTargets", {"targetGroupArn": TG_ARN, "targets": [{"id": "10.0.1.5", "port": 80}]},
                         eid="t-1", who={"type": "AWSService", "invokedBy": "ecs.amazonaws.com"})
    assert "AWS service" in _p(f).live("elb_reregister_targets", {"alarm": ALARM, "target_group": TG})["refused"]
    g = Reverts()
    g.registered = {"i-0aaa"}
    assert "registered again already" in _p(g).live("elb_reregister_targets",
                                                    {"alarm": ALARM, "target_group": TG})["refused"]


def test_a_scheduled_key_deletion_is_cancelled_and_the_key_stays_disabled_for_a_person():
    f = Reverts()
    p = _p(f)
    params = {"alarm": ALARM, "key": KEY_ID}
    live = p.live("kms_cancel_key_deletion", params)
    assert live["event"] == {"k-1"}, live.get("refused")
    p.apply("kms_cancel_key_deletion", {**params, "event": "k-1"}, snapshot=live["state"], who=WHO)
    assert f.sessions[-1] == {"actions": ["kms:CancelKeyDeletion"], "resources": [KEY_ARN]}
    assert "kms_cancel_key_deletion" in catalog.MITIGATES  # the page stays open: the key is not enabled
    assert p.rollback("kms_cancel_key_deletion", params, live["state"], who=WHO).startswith("nothing to roll back")
    f.key_state = "Disabled"
    assert p.healthy(KEY_ID, entry="kms_cancel_key_deletion", params=params)


@pytest.mark.parametrize("change, why", [
    (lambda f: setattr(f, "key_manager", "AWS"), "AWS managed key"),
    (lambda f: setattr(f, "key_state", "Disabled"), "not pending deletion"),
])
def test_a_key_that_is_not_the_customers_or_not_pending_deletion_is_refused(change, why):
    f = Reverts()
    change(f)
    assert why in _p(f).live("kms_cancel_key_deletion", {"alarm": ALARM, "key": KEY_ID})["refused"]


def test_a_deleted_secret_in_its_recovery_window_is_restored_and_one_deleted_without_recovery_is_not():
    f = Reverts()
    p = _p(f)
    params = {"alarm": ALARM, "secret": SECRET}
    live = p.live("secrets_restore_secret", params)
    assert live["event"] == {"s-1"}, live.get("refused")
    p.apply("secrets_restore_secret", {**params, "event": "s-1"}, snapshot=live["state"], who=WHO)
    assert f.sessions[-1] == {"actions": ["secretsmanager:RestoreSecret"], "resources": [SECRET_ARN]}
    g = Reverts()
    g.events[2] = _trail("DeleteSecret", {"secretId": SECRET, "forceDeleteWithoutRecovery": True}, eid="s-1")
    assert "no recorded" in _p(g).live("secrets_restore_secret", params)["refused"]


def test_the_resolver_reaches_each_from_the_alarms_labels():
    f = Reverts()
    p = _p(f)

    def plan(labels, target):
        alert = Alert(alert_id="a1", name="n", service="x", environment="dev", severity=Severity.high, summary="",
                      started_at="2026-10-10T00:00:00+00:00", labels={"alarm": ALARM, **labels})
        proposal = RemediationProposal(action=ActionKind.revert_change, target=target, reasoning="r",
                                       expected_effect="e", blast_radius="single_service", reversible=True)
        return resolver.request_for(alert, proposal, lambda e, params: p.live(e, params))

    assert plan({"alb_target_group": TG}, TG)[0]["entry"] == "elb_reregister_targets"
    assert plan({"kms_key": KEY_ID}, KEY_ID)[0]["entry"] == "kms_cancel_key_deletion"
    assert plan({"secret": SECRET}, SECRET)[0]["entry"] == "secrets_restore_secret"


def test_another_target_groups_deregistration_is_not_this_ones():
    f = Reverts()
    f.events.append(_trail("DeregisterTargets", {"targetGroupArn": TG_ARN.replace(TG, "warden-dev-other"),
                                                 "targets": [{"id": "i-0bbb", "port": 80}]}, eid="t-2"))
    assert _p(f).live("elb_reregister_targets", {"alarm": ALARM, "target_group": TG})["event"] == {"t-1"}
