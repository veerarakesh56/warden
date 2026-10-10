"""G9-D2b (2026-10-10): the generic fix classes on AWS. Each entry reads what the catalogue checks, writes only through an
actor session for that one plan, refuses when the target moved since the approval, has an inverse, and calls the
target healthy only on a positive signal - and refuses the cases AWS's own documentation says it cannot undo safely
(verify-fix-apis.md, 2026-10-10): a stream mapping paused past its retention, an event-pattern rule dropping events,
an ECS restart pulling a mutable tag, a manual count an autoscaler would undo."""

from __future__ import annotations

import pytest

from test_aws_platform_g6 import ACCT, FN, FN_ARN, NOW, WHO, Fake
from warden import catalog
from warden.platforms.aws import AwsPlatform, AwsPlatformRefused

QUEUE_ARN = f"arn:aws:sqs:test-region-1:{ACCT}:warden-dev-orders"
STREAM_ARN = f"arn:aws:kinesis:test-region-1:{ACCT}:stream/warden-dev-clicks"


class More(Fake):
    def __init__(self):
        super().__init__()
        self.esm = {"UUID": "u-1", "FunctionArn": FN_ARN, "State": "Enabled", "EventSourceArn": QUEUE_ARN}
        self.mappings = [self.esm, {"UUID": "u-2", "FunctionArn": FN_ARN, "State": "Enabled",
                                    "EventSourceArn": STREAM_ARN}]
        self.rule = {**self.rule, "State": "ENABLED", "ScheduleExpression": "rate(5 minutes)"}
        self.image = "registry.example/orders@sha256:" + "a" * 64
        self.service = {**self.service, "deploymentConfiguration": {"minimumHealthyPercent": 50}}

    def get_event_source_mapping(self, UUID):
        return {**next(m for m in self.mappings if m["UUID"] == UUID)}

    def list_event_source_mappings(self, FunctionName, **kw):
        return {"EventSourceMappings": [dict(m) for m in self.mappings]}

    def describe_task_definition(self, taskDefinition):
        return {"taskDefinition": {"containerDefinitions": [{"image": self.image}]}}

    retention = "345600"  # four days, SQS's default

    def get_queue_url(self, QueueName):
        return {"QueueUrl": f"https://sqs.test-region-1.amazonaws.com/{ACCT}/{QueueName}"}

    def get_queue_attributes(self, QueueUrl, AttributeNames):
        return {"Attributes": {"MessageRetentionPeriod": self.retention}}


@pytest.fixture
def aws():
    f = More()
    return f, AwsPlatform(reader=lambda service: f, actor=f.actor, clock=lambda: NOW, sleep=lambda s: None)


def test_only_a_queue_mapping_is_ever_paused_and_the_rollback_resumes_it(aws):
    f, p = aws
    live = p.live("lambda_disable_esm", {"function": FN})
    assert live["mapping"] == {"u-1"}  # u-2 reads a stream: its records would age out while paused
    params = {"function": FN, "mapping": "u-1"}
    assert catalog.validate("lambda_disable_esm", params, live) == []
    assert catalog.validate("lambda_disable_esm", {"function": FN, "mapping": "u-2"}, live)
    snap = p.live("lambda_disable_esm", params)["state"]
    p.apply("lambda_disable_esm", params, snapshot=snap, who=WHO)
    assert f.writes[-1] == ("update_event_source_mapping", {"UUID": "u-1", "Enabled": False})
    assert f.sessions[-1]["actions"] == ["lambda:UpdateEventSourceMapping"]
    assert snap["retention_s"] == 345600  # in the plan: how long the waiting messages are kept
    f.esm["State"] = "Disabled"
    assert p.healthy("u-1", entry="lambda_disable_esm", params=params)
    p.rollback("lambda_disable_esm", params, snap, who=WHO)
    assert f.writes[-1] == ("update_event_source_mapping", {"UUID": "u-1", "Enabled": True})
    f.esm["State"], f.retention = "Enabled", "60"  # review H2: a queue that keeps a message a minute is never paused
    assert p.live("lambda_disable_esm", {"function": FN})["mapping"] == set()


def test_a_mapping_of_another_function_is_never_allowed(aws):
    f, p = aws
    f.esm["FunctionArn"] = FN_ARN.replace(FN, "warden-dev-other")
    assert p.live("lambda_disable_esm", {"function": FN, "mapping": "u-1"})["mapping"] == set()


def test_only_a_scheduled_rule_is_ever_paused(aws):
    f, p = aws
    params = {"rule": f.rule["Name"]}
    live = p.live("events_disable_rule", params)
    assert live["rule"] == {f.rule["Name"]}
    p.apply("events_disable_rule", params, snapshot=live["state"], who=WHO)
    assert f.writes[-1] == ("disable_rule", {"Name": f.rule["Name"]})
    f.rule = {**f.rule, "ScheduleExpression": None, "EventPattern": '{"source": ["orders"]}'}
    assert p.live("events_disable_rule", params)["rule"] == set()  # it would drop the events it matches
    f.rule = {**f.rule, "State": "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS", "ScheduleExpression": "rate(1 hour)",
              "EventPattern": None}
    assert p.live("events_disable_rule", params)["rule"] == set()


def test_an_ecs_restart_needs_digest_pinned_images_and_keeps_most_tasks_serving(aws):
    f, p = aws
    params = {"cluster": "c1", "service": "orders"}
    live = p.live("ecs_restart_service", params)
    assert catalog.validate("ecs_restart_service", params, live) == []
    p.apply("ecs_restart_service", params, snapshot=live["state"], who=WHO)
    assert f.writes[-1] == ("update_service", {"cluster": "c1", "service": "orders", "forceNewDeployment": True})
    # The workflow's own wording (review M5): it ends not_recovered, never rolled_back.
    assert p.rollback("ecs_restart_service", params, live["state"], who=WHO).startswith("nothing to roll back")
    f.image = "registry.example/orders:latest"
    live = p.live("ecs_restart_service", params)
    assert catalog.validate("ecs_restart_service", params, live)  # a tag could pull new code
    with pytest.raises(AwsPlatformRefused, match="not pinned by digest"):
        p.apply("ecs_restart_service", params, snapshot=live["state"], who=WHO)
    f.image = "registry.example/orders@sha256:" + "a" * 64
    f.service = {**f.service, "deploymentConfiguration": {"minimumHealthyPercent": 0}}
    assert any("C10" in x for x in catalog.validate("ecs_restart_service", params, p.live("ecs_restart_service", params)))


def test_an_ecs_scale_up_is_bounded_refused_under_an_autoscaler_and_rolled_back(aws):
    f, p = aws
    live = p.live("ecs_scale_service", {"cluster": "c1", "service": "orders"})
    assert live["current_replicas"] == 2
    assert catalog.validate("ecs_scale_service", {"cluster": "c1", "service": "orders", "replicas": 5}, live)
    params = {"cluster": "c1", "service": "orders", "replicas": 3}
    assert catalog.validate("ecs_scale_service", params, live) == []
    p.apply("ecs_scale_service", params, snapshot=live["state"], who=WHO)
    assert f.writes[-1] == ("update_service", {"cluster": "c1", "service": "orders", "desiredCount": 3})
    f.service = {**f.service, "desiredCount": 3}
    p.rollback("ecs_scale_service", params, live["state"], who=WHO)
    assert f.writes[-1] == ("update_service", {"cluster": "c1", "service": "orders", "desiredCount": 2})
    f.scaled = [{"ResourceId": "service/c1/orders"}]  # now at 3 tasks, so 4 is within the bound
    live = p.live("ecs_scale_service", params)
    assert any("C4" in x for x in catalog.validate("ecs_scale_service", {**params, "replicas": 4}, live))


DLQ = "warden-dev-orders-dlq"
DLQ_ARN = f"arn:aws:sqs:test-region-1:{ACCT}:{DLQ}"
SRC_URL = f"https://sqs.test-region-1.amazonaws.com/{ACCT}/warden-dev-orders"


class Queues(More):
    def __init__(self):
        super().__init__()
        self.dlq_attrs = {"QueueArn": DLQ_ARN, "ApproximateNumberOfMessages": "42"}
        self.sources = [SRC_URL]
        self.moves = []
        minutes = lambda m: {"EngineExecutionTimeInMillis": m * 60000}
        self.queries = {"q-1": {"QueryExecutionId": "q-1", "WorkGroup": "warden-dev-bi", "SubstatementType": "SELECT",
                                "Status": {"State": "RUNNING"}, "Statistics": minutes(40)},
                        "q-2": {"QueryExecutionId": "q-2", "WorkGroup": "warden-dev-bi", "SubstatementType": "SELECT",
                                "Status": {"State": "RUNNING"}, "Statistics": minutes(2)},
                        "q-3": {"QueryExecutionId": "q-3", "WorkGroup": "warden-dev-bi", "SubstatementType": "INSERT",
                                "Status": {"State": "RUNNING"}, "Statistics": minutes(40)}}
        self.stage = {"methodSettings": {"*/*": {"throttlingRateLimit": 100.0, "throttlingBurstLimit": 50}},
                      "tags": {"Environment": "dev"}}
        self.meta = type("Meta", (), {"region_name": "test-region-1"})()

    def get_queue_url(self, QueueName):
        return {"QueueUrl": f"https://sqs.test-region-1.amazonaws.com/{ACCT}/{QueueName}"}

    def get_queue_attributes(self, QueueUrl, AttributeNames):
        return {"Attributes": dict(self.dlq_attrs)}

    def list_dead_letter_source_queues(self, QueueUrl, MaxResults):
        return {"queueUrls": list(self.sources)}

    def list_message_move_tasks(self, SourceArn, MaxResults):
        return {"Results": list(self.moves)}

    def list_queue_tags(self, QueueUrl):
        return {"Tags": {"Environment": "dev"}}

    def get_caller_identity(self):
        return {"Account": ACCT}

    def get_work_group(self, WorkGroup):
        return {"WorkGroup": {"Name": WorkGroup, "State": "ENABLED"}}

    def list_query_executions(self, WorkGroup, MaxResults):
        return {"QueryExecutionIds": list(self.queries)}

    def batch_get_query_execution(self, QueryExecutionIds):
        return {"QueryExecutions": [dict(self.queries[q]) for q in QueryExecutionIds if q in self.queries]}

    def get_query_execution(self, QueryExecutionId):
        return {"QueryExecution": dict(self.queries[QueryExecutionId])}

    def list_tags_for_resource(self, ResourceARN):
        return {"Tags": [{"Key": "Environment", "Value": "dev"}]}

    def get_rest_apis(self, limit, **kw):
        return {"items": [{"id": "a1", "name": "warden-dev-shop"}, {"id": "a2", "name": "warden-dev-other"}]}

    def get_stage(self, restApiId, stageName):
        return {**self.stage, "methodSettings": {k: dict(v) for k, v in self.stage["methodSettings"].items()}}

    def get_account(self):
        return {"throttleSettings": {"rateLimit": 10000.0, "burstLimit": 5000}}


@pytest.fixture
def more():
    f = Queues()
    return f, AwsPlatform(reader=lambda service: f, actor=f.actor, clock=lambda: NOW, sleep=lambda s: None)


def test_a_redrive_goes_to_the_one_source_queue_capped_and_each_queue_gets_only_its_own_actions(more):
    f, p = more
    live = p.live("sqs_redrive_dlq", {"queue": DLQ})
    assert live["to_queue"] == {"warden-dev-orders"} and live["state"]["waiting"] == 42
    params = {"queue": DLQ, "to_queue": "warden-dev-orders", "per_second": 10}
    assert catalog.validate("sqs_redrive_dlq", params, live) == []
    assert catalog.validate("sqs_redrive_dlq", {**params, "per_second": 500}, live)
    p.apply("sqs_redrive_dlq", params, snapshot=live["state"], who=WHO)
    assert f.writes[-1] == ("start_message_move_task", {"SourceArn": DLQ_ARN, "DestinationArn": QUEUE_ARN,
                                                        "MaxNumberOfMessagesPerSecond": 10})
    s = f.sessions[-1]
    assert s["resources"] == [DLQ_ARN] and "sqs:SendMessage" not in s["actions"]
    assert s["also"] == [(["sqs:SendMessage"], [QUEUE_ARN])]  # send on the destination only, never the cross product
    f.moves = [{"Status": "RUNNING", "TaskHandle": "h-1"}]
    assert "cancelled" in p.rollback("sqs_redrive_dlq", params, live["state"], who=WHO)
    assert f.writes[-1] == ("cancel_message_move_task", {"TaskHandle": "h-1"})


def test_no_redrive_to_a_queue_that_is_not_its_source_or_of_an_encrypted_queue(more):
    f, p = more
    live = p.live("sqs_redrive_dlq", {"queue": DLQ})
    assert catalog.validate("sqs_redrive_dlq", {"queue": DLQ, "to_queue": "warden-dev-payments", "per_second": 10}, live)
    f.sources = [SRC_URL.replace(ACCT, "1" * 12)]  # another account's source is never a destination
    assert p.live("sqs_redrive_dlq", {"queue": DLQ})["to_queue"] == set()
    f.sources, f.dlq_attrs["KmsMasterKeyId"] = [SRC_URL], "alias/x"
    assert p.live("sqs_redrive_dlq", {"queue": DLQ})["queue"] == set()


def test_only_the_runaway_query_is_cancelled(more):
    f, p = more
    live = p.live("athena_stop_query", {"workgroup": "warden-dev-bi"})
    assert live["query"] == {"q-1"}  # q-2 has run two minutes; q-3 is an INSERT (review M4: partial data)
    params = {"workgroup": "warden-dev-bi", "query": "q-1"}
    snap = p.live("athena_stop_query", params)["state"]
    p.apply("athena_stop_query", params, snapshot=snap, who=WHO)
    assert f.writes[-1] == ("stop_query_execution", {"QueryExecutionId": "q-1"})
    assert f.sessions[-1]["resources"] == [f"arn:aws:athena:test-region-1:{ACCT}:workgroup/warden-dev-bi"]
    f.queries["q-1"]["Status"] = {"State": "SUCCEEDED"}
    with pytest.raises(AwsPlatformRefused, match="no longer a runaway"):
        p.apply("athena_stop_query", params, snapshot={**snap, "query_state": "SUCCEEDED"}, who=WHO)


def test_a_stage_throttle_is_raised_within_double_and_the_account_and_rolled_back(more):
    f, p = more
    base = {"api": "warden-dev-shop", "stage": "prod"}
    live = p.live("apigw_raise_stage_throttle", base)
    params = {**base, "rate_limit": 200, "burst_limit": 100}
    assert catalog.validate("apigw_raise_stage_throttle", params, live) == []
    assert catalog.validate("apigw_raise_stage_throttle", {**params, "rate_limit": 201}, live)
    p.apply("apigw_raise_stage_throttle", params, snapshot=live["state"], who=WHO)
    assert f.writes[-1][1]["patchOperations"] == [
        {"op": "replace", "path": "/*/*/throttling/rateLimit", "value": "200"},
        {"op": "replace", "path": "/*/*/throttling/burstLimit", "value": "100"}]
    assert f.sessions[-1]["resources"] == ["arn:aws:apigateway:test-region-1::/restapis/a1/stages/prod"]
    f.stage["methodSettings"]["*/*"] = {"throttlingRateLimit": 200.0, "throttlingBurstLimit": 100}
    p.rollback("apigw_raise_stage_throttle", params, live["state"], who=WHO)
    assert f.writes[-1][1]["patchOperations"][0]["value"] == "100"
    f.stage = {"methodSettings": {}, "tags": {"Environment": "dev"}}  # no all-methods throttle to replace
    assert p.live("apigw_raise_stage_throttle", base)["stage"] == set()


def test_a_session_policy_holds_each_pair_exactly_and_no_pattern():
    import json

    from warden import identity

    doc = json.loads(identity.session_policy(["sqs:StartMessageMoveTask"], [DLQ_ARN], None,
                                             also=[(["sqs:SendMessage"], [QUEUE_ARN])]))
    assert [(st["Action"], st["Resource"]) for st in doc["Statement"]] == [
        (["sqs:StartMessageMoveTask"], [DLQ_ARN]), (["sqs:SendMessage"], [QUEUE_ARN])]
    with pytest.raises(identity.IdentityError, match="exact ARNs"):
        identity.session_policy(["sqs:StartMessageMoveTask"], [DLQ_ARN], None, also=[(["sqs:SendMessage"], ["*"])])


LB = "app/warden-dev-shop/abc123"
LB_ARN = f"arn:aws:elasticloadbalancing:test-region-1:{ACCT}:loadbalancer/{LB}"


class Zones(Queues):
    def __init__(self):
        super().__init__()
        self.zonal = "true"
        self.health = {"test-region-1a": (0.0, 3.0), "test-region-1b": (2.0, 0.0)}  # (healthy, unhealthy)
        self.shifts, self.weights = [], {}

    def describe_load_balancers(self, Names):
        return {"LoadBalancers": [{"LoadBalancerArn": LB_ARN, "AvailabilityZones": [
            {"ZoneName": "test-region-1a"}, {"ZoneName": "test-region-1b"}]}]}

    def describe_availability_zones(self, ZoneNames):
        return {"AvailabilityZones": [{"ZoneName": z, "ZoneId": "tr1-az" + z[-1]} for z in ZoneNames]}

    def describe_load_balancer_attributes(self, LoadBalancerArn):
        return {"Attributes": [{"Key": "zonal_shift.config.enabled", "Value": self.zonal}]}

    def describe_tags(self, ResourceArns):
        return {"TagDescriptions": [{"ResourceArn": ResourceArns[0], "Tags": [{"Key": "Environment", "Value": "dev"}]}]}

    def describe_target_groups(self, LoadBalancerArn):
        return {"TargetGroups": [{"TargetGroupArn": f"arn:aws:elasticloadbalancing:test-region-1:{ACCT}:targetgroup/tg/1"}]}

    def get_metric_data(self, MetricDataQueries, StartTime, EndTime, **kw):
        out = []
        for q in MetricDataQueries:
            m = q["MetricStat"]["Metric"]
            zone = {d["Name"]: d["Value"] for d in m["Dimensions"]}.get("AvailabilityZone")
            if zone is None:
                return super().get_metric_data(MetricDataQueries, StartTime, EndTime)
            h, u = self.health.get(zone, (None, None))
            v = h if m["MetricName"] == "HealthyHostCount" else u
            out.append({"Id": q["Id"], "Values": [] if v is None else [v]})
        return {"MetricDataResults": out}

    def get_managed_resource(self, resourceIdentifier):
        return {"zonalShifts": [dict(s) for s in self.shifts], "appliedWeights": dict(self.weights)}


@pytest.fixture
def zones():
    f = Zones()
    return f, AwsPlatform(reader=lambda service: f, actor=f.actor, clock=lambda: NOW, sleep=lambda s: None)


def test_traffic_shifts_away_from_the_one_impaired_zone_and_the_rollback_cancels_only_its_own_shift(zones):
    f, p = zones
    live = p.live("arc_zonal_shift", {"load_balancer": LB})
    assert live["away_from"] == {"tr1-aza"} and live["environment"] == "dev"
    params = {"load_balancer": LB, "away_from": "tr1-aza", "minutes": 60}
    assert catalog.validate("arc_zonal_shift", params, live) == []
    p.apply("arc_zonal_shift", params, snapshot=live["state"], who=WHO)
    name, kw = f.writes[-1]
    assert name == "start_zonal_shift" and kw["resourceIdentifier"] == LB_ARN and kw["awayFrom"] == "tr1-aza"
    assert kw["expiresIn"] == "60m" and kw["comment"].startswith("WARDEN inc-7 plan ")
    assert f.sessions[-1]["resources"] == [LB_ARN] and f.sessions[-1]["actions"] == ["arc-zonal-shift:StartZonalShift"]
    assert "shifted away from zone tr1-aza (test-region-1a)" in catalog.change_of("arc_zonal_shift", params, live["state"])[0]
    f.weights = {"tr1-aza": 0, "tr1-azb": 1}
    assert p.healthy(LB, entry="arc_zonal_shift", params=params)
    f.shifts = [{"zonalShiftId": "z-other", "awayFrom": "tr1-aza", "comment": "someone else", "appliedStatus": "APPLIED"},
                {"zonalShiftId": "z-mine", "awayFrom": "tr1-aza", "comment": kw["comment"], "appliedStatus": "APPLIED"}]
    p.rollback("arc_zonal_shift", params, live["state"], who=WHO)
    assert f.writes[-1] == ("cancel_zonal_shift", {"zonalShiftId": "z-mine"})


def test_no_shift_without_exactly_one_impaired_zone_the_balancers_consent_or_with_one_in_place(zones):
    f, p = zones
    base = {"load_balancer": LB}
    f.health = {"test-region-1a": (0.0, 3.0), "test-region-1b": (0.0, 2.0)}  # nothing serves: a shift helps nobody
    assert p.live("arc_zonal_shift", base)["away_from"] == set()
    f.health = {"test-region-1a": (0.0, 3.0), "test-region-1b": (2.0, 0.0)}
    f.zonal = "false"
    assert p.live("arc_zonal_shift", base)["away_from"] == set()
    f.zonal = "true"
    f.shifts = [{"zonalShiftId": "z-1", "awayFrom": "tr1-azb", "appliedStatus": "APPLIED"}]
    live = p.live("arc_zonal_shift", base)
    assert any("P21" in x for x in catalog.validate("arc_zonal_shift",
                                                    {**base, "away_from": "tr1-aza", "minutes": 60}, live))
    assert p.live("arc_zonal_shift", {"load_balancer": "app/warden-dev-shop/other-id"}) == {}
