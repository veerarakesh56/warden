"""G10-D3: a value back to what AWS Config recorded just before ONE recorded change - an ECS service's desired count
(recorded ecs-09 and k8s-07: scaled to zero, escalated with nothing to restore to) and a Lambda function's reserved
concurrency. Field paths are AWS's own Config resource schemas (awslabs/aws-config-resource-schema, read 2026-10-10):
AWS::ECS::Service configuration.DesiredCount, AWS::Lambda::Function supplementaryConfiguration.Concurrency."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from test_aws_platform_g6 import ACCT, NOW, WHO
from warden import catalog, resolver
from warden.models import ActionKind, Alert, RemediationProposal, Severity
from warden.platforms.aws import AwsPlatform, AwsPlatformRefused

ALARM = "warden-dev-orders-running"
SVC_ARN = f"arn:aws:ecs:test-region-1:{ACCT}:service/c1/warden-dev-orders"
FN = "warden-dev-checkout"
FN_ARN = f"arn:aws:lambda:test-region-1:{ACCT}:function:{FN}"
ONSET = NOW - timedelta(minutes=30)


def _trail(name, request, *, eid="e-1", minutes_before_alarm=60, who=None, source="ecs.amazonaws.com"):
    detail = {"eventName": name, "eventSource": source, "requestParameters": request,
              "userIdentity": who or {"type": "IAMUser", "userName": "ops"}}
    return {"EventId": eid, "EventName": name, "EventTime": ONSET - timedelta(minutes=minutes_before_alarm),
            "CloudTrailEvent": json.dumps(detail)}


def _ci(minutes_before_alarm, configuration=None, supplementary=None, related=(), frequency="Continuous"):
    return {"configurationItemCaptureTime": ONSET - timedelta(minutes=minutes_before_alarm), "recordingFrequency": frequency,
            "configuration": json.dumps(configuration or {}), "relatedEvents": list(related),
            "supplementaryConfiguration": {k: json.dumps(v) for k, v in (supplementary or {}).items()}}


class Fake:
    def __init__(self):
        self.alarm_state, self.desired, self.running, self.reserved, self.scaled = "ALARM", 0, 0, 0, []
        self.events = [_trail("UpdateService", {"cluster": "c1", "service": "warden-dev-orders", "desiredCount": 0})]
        self.history = {"AWS::ECS::Service": [_ci(600, {"DesiredCount": 2}), _ci(59, {"DesiredCount": 0}, related=["e-1"])],
                        "AWS::Lambda::Function": [_ci(600, supplementary={"Concurrency": {"reservedConcurrentExecutions": 50}}),
                                                  _ci(59, supplementary={"Concurrency": {"reservedConcurrentExecutions": 0}},
                                                      related=["l-1"])]}
        self.sessions, self.writes = [], []
        self.meta = type("M", (), {"region_name": "test-region-1"})()

    # cloudwatch
    def describe_alarms(self, AlarmNames, AlarmTypes):
        return {"MetricAlarms": [{"AlarmName": ALARM, "StateValue": self.alarm_state, "StateTransitionedTimestamp": ONSET}]}

    # ecs / application-autoscaling
    def describe_services(self, cluster, services, include=None):
        return {"services": [{"serviceName": "warden-dev-orders", "serviceArn": SVC_ARN, "desiredCount": self.desired,
                              "runningCount": self.running, "tags": [{"key": "Environment", "value": "dev"}]}]}

    def describe_scalable_targets(self, **kw):
        return {"ScalableTargets": list(self.scaled)}

    # lambda
    def get_function_configuration(self, FunctionName):
        return {"FunctionName": FN, "FunctionArn": FN_ARN}

    def get_function_concurrency(self, FunctionName):
        return {} if self.reserved is None else {"ReservedConcurrentExecutions": self.reserved}

    def get_account_settings(self):
        return {"AccountLimit": {"UnreservedConcurrentExecutions": 900}}

    def list_tags(self, Resource):
        return {"Tags": {"Environment": "dev"}}

    # cloudtrail / config
    def lookup_events(self, LookupAttributes, **kw):
        return {"Events": list(self.events)}

    def list_discovered_resources(self, resourceType, resourceName):
        rid = {"AWS::ECS::Service": SVC_ARN, "AWS::Lambda::Function": FN}[resourceType]
        return {"resourceIdentifiers": [{"resourceType": resourceType, "resourceId": rid, "resourceName": resourceName}]}

    def get_resource_config_history(self, resourceType, **kw):
        return {"configurationItems": list(self.history[resourceType])}

    def actor(self, who, actions, resources, condition, also=()):
        self.sessions.append({"actions": actions, "resources": resources})
        fake = self

        class Writer:
            def __getattr__(self, name):
                return lambda **kw: fake.writes.append((name, kw))
        return lambda service: Writer()


def _p(f):
    return AwsPlatform(reader=lambda service: f, actor=f.actor, clock=lambda: NOW, sleep=lambda s: None)


ECS = {"alarm": ALARM, "cluster": "c1", "service": "warden-dev-orders"}
LAM = {"alarm": ALARM, "function": FN}


def test_a_service_scaled_to_zero_is_set_back_to_the_count_config_recorded_before():
    f = Fake()
    p = _p(f)
    live = p.live("ecs_restore_desired", ECS)
    assert live["event"] == {"e-1"} and live["desired"] == {"2"} and live["environment"] == "dev", live.get("refused")
    plan = {**ECS, "event": "e-1", "desired": "2"}
    assert catalog.validate("ecs_restore_desired", plan, live) == []
    p.apply("ecs_restore_desired", plan, snapshot=live["state"], who=WHO)
    assert f.sessions == [{"actions": ["ecs:UpdateService"], "resources": [SVC_ARN]}]
    assert f.writes == [("update_service", {"cluster": "c1", "service": "warden-dev-orders", "desiredCount": 2})]
    assert "desired tasks of service warden-dev-orders: 0 -> 2" in catalog.change_of("ecs_restore_desired", plan,
                                                                                       live["state"])[0]


def test_restored_means_every_task_running_and_the_alarm_ok_and_the_rollback_sets_what_the_change_set():
    f = Fake()
    p = _p(f)
    plan = {**ECS, "event": "e-1", "desired": "2"}
    snap = p.live("ecs_restore_desired", ECS)["state"]
    f.desired, f.running = 2, 1
    assert not p.healthy("warden-dev-orders", entry="ecs_restore_desired", params=plan)
    f.running, f.alarm_state = 2, "OK"
    assert p.healthy("warden-dev-orders", entry="ecs_restore_desired", params=plan)
    p.rollback("ecs_restore_desired", plan, snap, who=WHO)
    assert f.writes[-1] == ("update_service", {"cluster": "c1", "service": "warden-dev-orders", "desiredCount": 0})


@pytest.mark.parametrize("change, why", [
    (lambda f: f.scaled.append({"ResourceId": "service/c1/warden-dev-orders"}), "autoscaler"),
    (lambda f: setattr(f, "alarm_state", "OK"), "not in ALARM"),
    (lambda f: f.events.__setitem__(0, _trail("UpdateService", {"cluster": "c1", "service": "warden-dev-orders",
                                                                 "desiredCount": 0}, minutes_before_alarm=-5)),
     "after the alarm"),
    (lambda f: f.events.append(_trail("UpdateService", {"cluster": "c1", "service": "warden-dev-orders",
                                                         "desiredCount": 1}, eid="e-2")), "2 change"),
    (lambda f: f.events.__setitem__(0, _trail("UpdateService", {"cluster": "c1", "service": "warden-dev-orders",
                                                                 "desiredCount": 0}, who={"type": "Root"})), "root"),
    (lambda f: f.history["AWS::ECS::Service"].pop(0), "no record of the resource before"),
    (lambda f: f.history["AWS::ECS::Service"].append(_ci(10, {"DesiredCount": 1})), "changed again"),
    (lambda f: f.history["AWS::ECS::Service"].__setitem__(0, _ci(600, {"DesiredCount": 2}, frequency="Daily")),
     "daily"),
    (lambda f: f.history["AWS::ECS::Service"].__setitem__(0, _ci(600, {"DesiredCount": 0})), "nothing to restore"),
    (lambda f: setattr(f, "desired", 3), "moved since"),
])
def test_every_refusal_allows_no_change_and_says_why(change, why):
    f = Fake()
    change(f)
    live = _p(f).live("ecs_restore_desired", ECS)
    assert live["event"] == set() and live["desired"] == set() and why in live["refused"], live.get("refused")


def test_another_services_change_and_a_change_that_set_no_count_are_not_this_ones():
    f = Fake()
    f.events += [_trail("UpdateService", {"cluster": "c1", "service": "warden-dev-other", "desiredCount": 0}, eid="o"),
                 _trail("UpdateService", {"cluster": "c1", "service": "warden-dev-orders", "forceNewDeployment": True},
                        eid="r")]
    assert _p(f).live("ecs_restore_desired", ECS)["event"] == {"e-1"}


def _lambda_fake(reserved_before=50):
    f = Fake()
    f.reserved = 0
    f.events = [_trail("PutFunctionConcurrency20171031", {"functionName": FN, "reservedConcurrentExecutions": 0},
                       eid="l-1", source="lambda.amazonaws.com")]
    if reserved_before is None:
        f.history["AWS::Lambda::Function"][0] = _ci(600)
    return f


def test_a_concurrency_cut_is_put_back_and_an_unreserved_function_has_its_reservation_deleted():
    f = _lambda_fake()
    p = _p(f)
    live = p.live("lambda_restore_concurrency", LAM)
    assert live["event"] == {"l-1"} and live["concurrency"] == {"50"}, live.get("refused")
    p.apply("lambda_restore_concurrency", {**LAM, "event": "l-1", "concurrency": "50"}, snapshot=live["state"], who=WHO)
    assert f.sessions[-1] == {"actions": ["lambda:PutFunctionConcurrency"], "resources": [FN_ARN]}
    assert f.writes[-1] == ("put_function_concurrency", {"FunctionName": FN, "ReservedConcurrentExecutions": 50})

    g = _lambda_fake(reserved_before=None)
    live = _p(g).live("lambda_restore_concurrency", LAM)
    assert live["concurrency"] == {"none"}, live.get("refused")
    _p(g).apply("lambda_restore_concurrency", {**LAM, "event": "l-1", "concurrency": "none"}, snapshot=live["state"],
                who=WHO)
    assert g.sessions[-1]["actions"] == ["lambda:DeleteFunctionConcurrency"]
    assert g.writes[-1] == ("delete_function_concurrency", {"FunctionName": FN})


def test_the_restore_is_refused_when_the_value_moved_since_the_approval():
    f = Fake()
    p = _p(f)
    snap = p.live("ecs_restore_desired", ECS)["state"]
    f.desired = 1
    with pytest.raises(AwsPlatformRefused, match="wants 1 tasks, not 0"):
        p.apply("ecs_restore_desired", {**ECS, "event": "e-1", "desired": "2"}, snapshot=snap, who=WHO)
    assert f.writes == []


def test_the_resolver_plans_revert_change_on_a_labelled_service_with_the_alarm_and_config_values():
    f = Fake()
    p = _p(f)
    alert = Alert(alert_id="a1", name="n", service="warden-dev-orders", environment="dev", severity=Severity.high,
                  summary="", started_at="2026-10-10T00:00:00+00:00",
                  labels={"alarm": ALARM, "ecs_cluster": "c1", "ecs_service": "warden-dev-orders"})
    proposal = RemediationProposal(action=ActionKind.revert_change, target="warden-dev-orders", reasoning="r",
                                   expected_effect="e", blast_radius="single_service", reversible=True)
    req, why = resolver.request_for(alert, proposal, lambda e, params: p.live(e, params))
    assert why == "" and req["entry"] == "ecs_restore_desired"
    assert req["params"] == {**ECS, "event": "e-1", "desired": "2"}
