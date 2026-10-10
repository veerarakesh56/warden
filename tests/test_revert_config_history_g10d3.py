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


# ---------------------------------------------------------------- D3b: an Auto Scaling group, an API Gateway stage

ASG_ARN = f"arn:aws:autoscaling:test-region-1:{ACCT}:autoScalingGroup:1-2-3:autoScalingGroupName/warden-dev-web"
ASG = {"alarm": ALARM, "asg": "warden-dev-web"}
STAGE = {"alarm": ALARM, "api": "warden-dev-shop", "stage": "prod"}


class Groups(Fake):
    def __init__(self):
        super().__init__()
        self.capacity, self.bounds, self.serving = 2, (1, 8), 2
        self.deployment, self.deployments = "dep-new", {"dep-old", "dep-new"}
        self.events = [_trail("SetDesiredCapacity", {"autoScalingGroupName": "warden-dev-web", "desiredCapacity": 2},
                              eid="a-1", source="autoscaling.amazonaws.com")]
        self.history["AWS::AutoScaling::AutoScalingGroup"] = [_ci(600, {"desiredCapacity": 6}),
                                                               _ci(59, {"desiredCapacity": 2}, related=["a-1"])]
        self.history["AWS::ApiGateway::Stage"] = [_ci(600, {"deploymentId": "dep-old"}),
                                                  _ci(59, {"deploymentId": "dep-new"}, related=["s-1"])]

    def describe_auto_scaling_groups(self, AutoScalingGroupNames):
        return {"AutoScalingGroups": [{"AutoScalingGroupName": "warden-dev-web", "AutoScalingGroupARN": ASG_ARN,
                                       "DesiredCapacity": self.capacity, "MinSize": self.bounds[0],
                                       "MaxSize": self.bounds[1], "Tags": [{"Key": "Environment", "Value": "dev"}],
                                       "Instances": [{"LifecycleState": "InService", "HealthStatus": "Healthy"}]
                                       * self.serving}]}

    def list_discovered_resources(self, resourceType, resourceName):
        if resourceType == "AWS::AutoScaling::AutoScalingGroup":
            return {"resourceIdentifiers": [{"resourceId": ASG_ARN}]}
        if resourceType == "AWS::ApiGateway::Stage":
            return {"resourceIdentifiers": [{"resourceId": "api1/prod"}, {"resourceId": "other/prod"}]}
        return super().list_discovered_resources(resourceType, resourceName)

    # apigateway
    def get_rest_apis(self, **kw):
        return {"items": [{"id": "api1", "name": "warden-dev-shop", "tags": {"Environment": "dev"}}]}

    def get_stage(self, restApiId, stageName):
        return {"deploymentId": self.deployment, "tags": {"Environment": "dev"}}

    def get_deployment(self, restApiId, deploymentId):
        if deploymentId not in self.deployments:
            raise RuntimeError("NotFoundException")
        return {"id": deploymentId}


def test_a_capacity_cut_is_set_back_within_the_groups_bounds():
    f = Groups()
    p = _p(f)
    live = p.live("asg_restore_capacity", ASG)
    assert live["event"] == {"a-1"} and live["desired"] == {"6"} and live["environment"] == "dev", live.get("refused")
    plan = {**ASG, "event": "a-1", "desired": "6"}
    p.apply("asg_restore_capacity", plan, snapshot=live["state"], who=WHO)
    assert f.sessions == [{"actions": ["autoscaling:SetDesiredCapacity"], "resources": [ASG_ARN]}]
    assert f.writes == [("set_desired_capacity", {"AutoScalingGroupName": "warden-dev-web", "DesiredCapacity": 6,
                                                  "HonorCooldown": False})]
    f.capacity, f.alarm_state = 6, "OK"
    assert not p.healthy("warden-dev-web", entry="asg_restore_capacity", params=plan)  # 2 of 6 serving
    f.serving = 6
    assert p.healthy("warden-dev-web", entry="asg_restore_capacity", params=plan)


@pytest.mark.parametrize("change, why", [
    (lambda f: f.events.__setitem__(0, _trail("UpdateAutoScalingGroup", {
        "autoScalingGroupName": "warden-dev-web", "desiredCapacity": 2, "maxSize": 2}, eid="a-1")), "bounds"),
    (lambda f: setattr(f, "bounds", (1, 4)), "outside the group's bounds"),
    (lambda f: f.events.clear(), "no recorded"),  # a scheduled action: AWS made it, no such event
])
def test_a_group_change_a_person_owns_is_refused(change, why):
    f = Groups()
    change(f)
    live = _p(f).live("asg_restore_capacity", ASG)
    assert live["event"] == set() and why in live["refused"], live.get("refused")


def test_a_stage_moved_to_a_new_deployment_goes_back_to_the_one_before():
    f = Groups()
    f.events = [_trail("UpdateStage", {"restApiId": "api1", "stageName": "prod", "patchOperations": [
        {"op": "replace", "path": "/deploymentId", "value": "dep-new"}]}, eid="s-1", source="apigateway.amazonaws.com")]
    p = _p(f)
    live = p.live("apigw_restore_stage", STAGE)
    assert live["event"] == {"s-1"} and live["deployment"] == {"dep-old"}, live.get("refused")
    p.apply("apigw_restore_stage", {**STAGE, "event": "s-1", "deployment": "dep-old"}, snapshot=live["state"], who=WHO)
    assert f.sessions[-1]["actions"] == ["apigateway:PATCH"]
    assert f.writes[-1] == ("update_stage", {"restApiId": "api1", "stageName": "prod", "patchOperations": [
        {"op": "replace", "path": "/deploymentId", "value": "dep-old"}]})


@pytest.mark.parametrize("ops, gone, why", [
    ([{"op": "replace", "path": "/deploymentId", "value": "dep-new"},
      {"op": "replace", "path": "/variables/x", "value": "1"}], False, "no recorded"),  # more than a move: a person's
    ([{"op": "replace", "path": "/deploymentId", "value": "dep-new"}], True, "no longer exists"),
    ([{"op": "replace", "path": "/variables/x", "value": "1"}], False, "no recorded"),  # another setting, not a move
])
def test_a_stage_change_that_did_more_or_a_deployment_that_is_gone_is_refused(ops, gone, why):
    f = Groups()
    f.events = [_trail("UpdateStage", {"restApiId": "api1", "stageName": "prod", "patchOperations": ops}, eid="s-1")]
    if gone:
        f.deployments.discard("dep-old")
    live = _p(f).live("apigw_restore_stage", STAGE)
    assert live["event"] == set() and why in live["refused"], live.get("refused")


# ---------------------------------------------------------------- D4: a function's timeout, memory or ephemeral storage

class Settings(Fake):
    """A function whose timeout was cut from 30 s to 3 s by one recorded UpdateFunctionConfiguration (held-out
    g10-data-28: an un-aliased function - no version to roll back to)."""

    def __init__(self, request=None, before=None, related=("f-1",)):
        super().__init__()
        self.timeout, self.memory = 3, 256
        self.events = [_trail("UpdateFunctionConfiguration20150331v2",
                              request or {"functionName": FN, "timeout": 3}, eid="f-1", source="lambda.amazonaws.com")]
        self.history["AWS::Lambda::Function"] = [
            _ci(600, before or {"timeout": 30, "memorySize": 256, "ephemeralStorage": {"size": 512}}),
            _ci(59, {"timeout": 3, "memorySize": 256, "ephemeralStorage": {"size": 512}}, related=list(related))]

    def get_function_configuration(self, FunctionName):
        return {"FunctionName": FN, "FunctionArn": FN_ARN, "Timeout": self.timeout, "MemorySize": self.memory,
                "EphemeralStorage": {"Size": 512}, "RevisionId": "rev-7", "LastUpdateStatus": "Successful"}


SETTINGS = {**LAM, "event": "f-1", "settings": "timeout=30"}


def test_a_timeout_cut_is_set_back_to_what_config_recorded_under_the_revision_the_plan_saw():
    f = Settings()
    p = _p(f)
    live = p.live("lambda_restore_settings", LAM)
    assert live["event"] == {"f-1"} and live["settings"] == {"timeout=30"}, live.get("refused")
    p.apply("lambda_restore_settings", SETTINGS, snapshot=live["state"], who=WHO)
    assert f.sessions[-1] == {"actions": ["lambda:UpdateFunctionConfiguration"], "resources": [FN_ARN]}
    assert f.writes[-1] == ("update_function_configuration", {"FunctionName": FN, "RevisionId": "rev-7", "Timeout": 30})
    f.timeout = 30
    assert p.healthy(FN, entry="lambda_restore_settings", params=SETTINGS) is False  # the alarm still reads ALARM
    f.alarm_state = "OK"
    assert p.healthy(FN, entry="lambda_restore_settings", params=SETTINGS) is True
    p.rollback("lambda_restore_settings", SETTINGS, live["state"], who=WHO)
    assert f.writes[-1] == ("update_function_configuration", {"FunctionName": FN, "RevisionId": "rev-7", "Timeout": 3})


@pytest.mark.parametrize("fake, why", [
    (Settings(request={"functionName": FN, "timeout": 3, "environment": "HIDDEN_DUE_TO_SECURITY_REASONS"}),
     "also set environment"),
    (Settings(request={"functionName": FN, "timeout": 3, "role": "arn:role/x"}), "also set role"),
    (Settings(request={"functionName": FN, "handler": "app.other"}), "also set handler"),
    (Settings(request={"functionName": FN, "description": "x"}), "also set description"),
    (Settings(before={"timeout": 1000}), "outside what Lambda allows"),
    (Settings(before={"memorySize": 256}), "no value before"),
])
def test_a_settings_change_wardens_restore_may_not_undo_is_refused(fake, why):
    live = _p(fake).live("lambda_restore_settings", LAM)
    assert live["settings"] == set() and why in live["refused"], live.get("refused")


def test_a_settings_restore_is_refused_when_the_function_moved_since():
    f = Settings()
    p = _p(f)
    snap = p.live("lambda_restore_settings", LAM)["state"]
    f.timeout = 10
    with pytest.raises(AwsPlatformRefused):
        p.apply("lambda_restore_settings", SETTINGS, snapshot=snap, who=WHO)
    assert f.writes == []


def test_the_resolver_uses_the_lambda_revert_that_found_the_recorded_change_and_never_chooses_between_two():
    alert = Alert(alert_id="a1", name="n", service=FN, environment="dev", severity=Severity.high, summary="",
                  started_at="2026-10-10T00:00:00+00:00", labels={"alarm": ALARM, "lambda": FN})
    proposal = RemediationProposal(action=ActionKind.revert_change, target=FN, reasoning="r", expected_effect="e",
                                   blast_radius="single_service", reversible=True)
    f = Settings()
    req, why = resolver.request_for(alert, proposal, lambda e, params: _p(f).live(e, params))
    assert why == "" and req["entry"] == "lambda_restore_settings" and req["params"] == SETTINGS
    g = _lambda_fake()
    req, why = resolver.request_for(alert, proposal, lambda e, params: _p(g).live(e, params))
    assert why == "" and req["entry"] == "lambda_restore_concurrency"
    both = Settings()
    both.reserved = 0
    both.events += _lambda_fake().events
    both.history["AWS::Lambda::Function"][0]["supplementaryConfiguration"] = {
        "Concurrency": json.dumps({"reservedConcurrentExecutions": 50})}
    req, why = resolver.request_for(alert, proposal, lambda e, params: _p(both).live(e, params))
    assert req is None and "more than one kind of recorded change" in why
    none = Settings()
    none.events = []
    req, why = resolver.request_for(alert, proposal, lambda e, params: _p(none).live(e, params))
    assert req is None and "no change WARDEN may undo: no recorded" in why


def test_a_function_whose_setting_moved_before_the_plan_is_refused():
    f = Settings()
    f.timeout = 10  # neither what the change set (3) nor what it was (30): someone changed it again
    live = _p(f).live("lambda_restore_settings", LAM)
    assert live["settings"] == set() and "moved since" in live["refused"]
