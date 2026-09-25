"""StackBackend (WARDEN_BACKEND=stack), against fake AWS clients - no account, no network.

The load-bearing tests are the two at the bottom: the IAM role in terraform/fullstack/reader.tf is
checked against every call this module (and the AwsBackend it reuses) makes, in both directions,
and the module is walked for anything write-shaped.
"""

from __future__ import annotations

import ast
import inspect
import io
import json
import pathlib
import re
import zipfile
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from warden import aws_backend, aws_stack
from warden.aws_stack import StackBackend, parse_tracebacks, source_excerpt
from warden.models import Alert, Severity
from warden.tools import PARTIAL_PREFIX, gather, resolve_backend

ROOT = pathlib.Path(__file__).resolve().parents[1]
NOW = datetime.now(UTC).replace(microsecond=0)
P = "warden-pg-fs-"


# --------------------------------------------------------------------------- fakes


class Fake:
    """A boto3-shaped client: each method returns a canned value, raises it, or calls it."""

    def __init__(self, **methods):
        self.meta = SimpleNamespace(region_name="ap-south-2")
        self.calls: list[tuple[str, dict]] = []
        self._methods = methods

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def call(**kwargs):
            self.calls.append((name, kwargs))
            value = self._methods[name]
            if isinstance(value, Exception):
                raise value
            return value(**kwargs) if callable(value) else value

        return call


class ClientError(Exception):
    def __init__(self, code):
        super().__init__(f"An error occurred ({code})")
        self.response = {"Error": {"Code": code}}


def _cw(values: dict[str, list[float]] | None = None):
    """get_metric_data answering by MetricName (or 'expr' for an Expression query)."""
    values = values if values is not None else {}

    def get_metric_data(MetricDataQueries, **_):
        out = []
        for q in MetricDataQueries:
            name = q["MetricStat"]["Metric"]["MetricName"] if "MetricStat" in q else "expr"
            out.append({"Id": q["Id"], "Values": list(values.get(name, []))})
        return {"MetricDataResults": out}

    return Fake(get_metric_data=get_metric_data)


def _events(group_messages: dict[str, list[tuple[str, str]]]):
    """filter_log_events by group: {group: [(stream, message), ...]}."""
    ts = int(NOW.timestamp() * 1000)
    return Fake(filter_log_events=lambda logGroupName, **_: {"events": [
        {"logStreamName": s, "timestamp": ts, "message": m}
        for s, m in group_messages.get(logGroupName, [])
    ]})


def _lambda(**over):
    methods = {
        "get_alias": {"FunctionVersion": "7"},
        "get_function_configuration": {"Timeout": 1, "MemorySize": 256, "Environment": {
            "Variables": {"TABLE_NAME": "warden-pg-fs-carts", "REDIS_HOST": "cache.internal",
                          "DB_PASSWORD": "super-secret-value", "API_TOKEN": "tok-123"}}},
        "get_function_concurrency": {"ReservedConcurrentExecutions": 0},
        "list_versions_by_function": {"Versions": [
            {"Version": "$LATEST"},
            {"Version": "6", "LastModified": (NOW - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")},
            {"Version": "7", "LastModified": (NOW - timedelta(minutes=4)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")},
        ]},
        "list_event_source_mappings": {"EventSourceMappings": []},
        "get_function": {"Code": {"Location": "https://bucket.example/pkg.zip"}},
    }
    methods.update(over)
    return Fake(**methods)


def _sqs(policy_allows=True):
    queues = {
        f"{P}orders": {"ApproximateNumberOfMessages": "120", "ApproximateNumberOfMessagesNotVisible": "5",
                       "VisibilityTimeout": "30",
                       "RedrivePolicy": json.dumps({"deadLetterTargetArn": f"arn:aws:sqs:ap-south-2:1:{P}orders-dlq",
                                                    "maxReceiveCount": 3})},
        f"{P}orders-dlq": {"ApproximateNumberOfMessages": "14"},
        f"{P}payments": {"ApproximateNumberOfMessages": "2", "ApproximateNumberOfMessagesNotVisible": "0",
                         "VisibilityTimeout": "60"},
        f"{P}notifications": {"Policy": json.dumps({"Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage",
            "Condition": {"ArnEquals": {"aws:SourceArn": f"arn:aws:sns:ap-south-2:1:{P}order-events"
                                        if policy_allows else "arn:aws:sns:ap-south-2:1:other"}}}]})},
    }
    return Fake(
        get_queue_url=lambda QueueName: {"QueueUrl": f"https://sqs/{QueueName}"},
        get_queue_attributes=lambda QueueUrl, AttributeNames: {"Attributes": {
            k: v for k, v in queues[QueueUrl.rsplit("/", 1)[1]].items() if k in AttributeNames}},
    )


def _ecs():
    arn = "arn:aws:ecs:ap-south-2:1:task-definition/orders-api:"
    return Fake(
        describe_services={"services": [{
            "status": "ACTIVE", "runningCount": 2, "desiredCount": 2, "pendingCount": 0,
            "networkConfiguration": {"awsvpcConfiguration": {"securityGroups": ["sg-0ecs"]}},
            "deployments": [
                {"status": "PRIMARY", "createdAt": NOW - timedelta(minutes=3), "taskDefinition": arn + "8"},
                {"status": "ACTIVE", "createdAt": NOW - timedelta(days=1), "taskDefinition": arn + "7"},
            ]}], "failures": []},
        describe_task_definition=lambda taskDefinition: {"taskDefinition": {"containerDefinitions": [
            {"image": f"app:{taskDefinition.rsplit(':', 1)[1]}"}]}},
    )


class FakeK8s:
    def __init__(self):
        self.alerts = []

    def logs(self, alert):
        self.alerts.append(alert)
        return ["EVENT BackOff Pod/catalog-api-1: back-off", "catalog-api-1/app 2026 boom"]

    def metrics(self, alert):
        return {"pods_ready": 0.0, "restart_count": 4.0}

    def deploys(self, alert):
        return [{"deployment": alert.labels["deployment"], "revision": "3", "image": "cat:bad",
                 "previous_image": "cat:good", "at": NOW.isoformat(), "by": "kubernetes"}]


class FakeDb:
    def __init__(self, dsn):
        self.dsn = dsn

    def metrics(self, alert):
        return {"connections_active": 90.0, "max_connections": 100.0}

    def logs(self, alert):
        return [f"postgres stuck connection: pid 42 on {self.dsn}"]


def _clients(**over):
    c = {
        "lambda": _lambda(),
        "logs": _events({}),
        "cloudwatch": _cw(),
        "ecs": _ecs(),
        "sqs": _sqs(),
        "dynamodb": Fake(describe_table={"Table": {
            "TableStatus": "ACTIVE", "BillingModeSummary": {"BillingMode": "PROVISIONED"},
            "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1}}}),
        "elasticache": Fake(
            describe_replication_groups={"ReplicationGroups": [{"MemberClusters": [f"{P}redis-001", f"{P}redis-002"],
                                                                "NodeGroups": [{"PrimaryEndpoint": {"Port": 6379}}]}]},
            describe_cache_clusters={"CacheClusters": [
                {"ReplicationGroupId": f"{P}redis", "CacheClusterStatus": "available",
                 "CacheNodeType": "cache.t4g.micro", "SecurityGroups": [{"SecurityGroupId": "sg-0redis"}]},
                {"ReplicationGroupId": f"{P}redis", "CacheClusterStatus": "modifying",
                 "CacheNodeType": "cache.t4g.micro", "SecurityGroups": [{"SecurityGroupId": "sg-0redis"}]},
                {"ReplicationGroupId": "someone-else", "CacheClusterStatus": "available"}]},
            describe_events={"Events": [
                {"SourceIdentifier": f"{P}redis-001", "Date": NOW, "Message": "Failover complete"},
                {"SourceIdentifier": "someone-else", "Date": NOW, "Message": "not ours"}]}),
        "rds": Fake(
            describe_db_clusters={"DBClusters": [{"Status": "available", "DBClusterMembers": [
                {"DBInstanceIdentifier": f"{P}aurora-1", "IsClusterWriter": True},
                {"DBInstanceIdentifier": f"{P}aurora-2", "IsClusterWriter": False}]}]},
            describe_db_instances={"DBInstances": [{"DBInstanceStatus": "available"}] * 2},
            describe_events={"Events": [{"SourceIdentifier": f"{P}aurora", "Date": NOW,
                                         "Message": "Completed failover to DB instance"}]}),
        "elbv2": Fake(
            describe_target_groups={"TargetGroups": [{
                "TargetGroupArn": f"arn:aws:elasticloadbalancing:ap-south-2:1:targetgroup/{P}orders/abc",
                "HealthCheckPath": "/healthz", "HealthCheckPort": "traffic-port", "Matcher": {"HttpCode": "200"},
                "LoadBalancerArns": [f"arn:aws:elasticloadbalancing:ap-south-2:1:loadbalancer/app/{P}alb/def"]}]},
            describe_target_health={"TargetHealthDescriptions": [
                {"Target": {"Id": "10.42.0.12", "Port": 8080}, "TargetHealth": {
                    "State": "unhealthy", "Reason": "Target.ResponseCodeMismatch",
                    "Description": "Health checks failed with these codes: [404]"}},
                {"Target": {"Id": "10.42.0.13", "Port": 8080}, "TargetHealth": {"State": "healthy"}}]}),
        "apigatewayv2": Fake(get_apis={"Items": [{"Name": f"{P}api", "ApiId": "a1"}]}),
        "secretsmanager": Fake(describe_secret={"Name": f"{P}db-app", "LastChangedDate": NOW - timedelta(minutes=10)}),
        "sns": Fake(list_subscriptions_by_topic={"Subscriptions": [
            {"Protocol": "sqs", "Endpoint": f"arn:aws:sqs:ap-south-2:1:{P}notifications"}]}),
        "events": Fake(describe_rule={"State": "DISABLED", "ScheduleExpression": "rate(5 minutes)"}),
        "sts": Fake(get_caller_identity={"Account": "1"}),
        # ⛔ Every client the backend builds MUST be faked here: a missing one makes StackBackend build
        # a REAL boto3 client inside a unit test (test_no_real_client_is_ever_built guards it).
        "ec2": Fake(describe_security_groups={"SecurityGroups": [{"GroupId": "sg-0redis", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 6379, "ToPort": 6379, "UserIdGroupPairs": [{"GroupId": "sg-0lambda"}]},
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "UserIdGroupPairs": [{"GroupId": "sg-0other"}]}]}]}),
        "eks": Fake(describe_cluster={"cluster": {"resourcesVpcConfig": {
            "clusterSecurityGroupId": "sg-0eks", "securityGroupIds": []}}}),
    }
    c.update(over)
    return c


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in files.items():
            zf.writestr(name, text)
    return buf.getvalue()


APP_PY = "\n".join(f"line{n}" for n in range(1, 41)) + "\n    sku = body['sku']\nline42\nline43\nline44\nline45\n"


def _backend(clients=None, **kw):
    kw.setdefault("k8s_factory", FakeK8s)
    kw.setdefault("db_factory", FakeDb)
    kw.setdefault("download", lambda url: _zip({"app.py": APP_PY}))
    return StackBackend(clients=clients or _clients(), **kw)


def _alert(**labels):
    return Alert(alert_id="fs-1", name="CheckoutErrors", severity=Severity.high, service="shop",
                 environment="prod", summary="5xx on checkout", started_at=NOW.isoformat(),
                 labels={"app": "shop", **labels})


FULL = dict(
    lambda_=f"{P}checkout", sqs=f"{P}orders", dynamodb_table=f"{P}carts", elasticache=f"{P}redis",
    aurora_cluster=f"{P}aurora", alb_target_group=f"{P}orders", apigw=f"{P}api", ecs_cluster=f"{P}ecs",
    ecs_service=f"{P}orders-api", namespace="shop", deployment="catalog-api", secret=f"{P}db-app",
    sns_topic=f"{P}order-events", eventbridge_rule=f"{P}reconcile-5m",
)


def _full_alert(**over):
    labels = {**FULL, **over}
    labels["lambda"] = labels.pop("lambda_")
    return _alert(**labels)


@pytest.fixture
def dsns(monkeypatch):
    monkeypatch.setenv("WARDEN_STACK_DB_WRITER_DSN", "postgresql://writer")
    monkeypatch.setenv("WARDEN_STACK_DB_READER_DSN", "postgresql://reader")


# --------------------------------------------------------------------------- happy path


def test_every_reader_emits_the_contract_lines(dsns):
    b = _backend(_clients(logs=_events({
        f"/aws/lambda/{P}checkout": [("2026/09/26/[7]abc", "START RequestId: x"), ("2026/09/26/[7]abc", "hello")],
        f"/ecs/{P}orders-api": [("ecs/app/1", "GET /orders 500")],
    })))
    lines = b.logs(_full_alert())
    assert not [x for x in lines if x.startswith(PARTIAL_PREFIX)], lines
    z = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
    expected = [
        f"LOG lambda/{P}checkout {z} hello",
        f"LOG ecs/{P}orders-api {z} GET /orders 500",
        "LOG k8s/shop/catalog-api EVENT BackOff Pod/catalog-api-1: back-off",
        (f"CONFIG lambda {P}checkout timeout=1s memory=256MB reserved_concurrency=0 "
         "env=[API_TOKEN,DB_PASSWORD,REDIS_HOST=cache.internal,TABLE_NAME=warden-pg-fs-carts] "
         "version=7 alias_live=7"),
        f"QUEUE {P}orders visible=120 in_flight=5 dlq={P}orders-dlq dlq_visible=14 max_receive=3",
        f"POLICY sqs {P}notifications allows_sns_topic={P}order-events:yes",
        f"TABLE {P}carts billing=PROVISIONED rcu=1 wcu=1 status=ACTIVE",
        f"EVENT elasticache {P}redis {z} Failover complete",
        f"EVENT aurora {P}aurora {z} Completed failover to DB instance",
        f"CLUSTER aurora {P}aurora writer={P}aurora-1 readers=[{P}aurora-2] status=available",
        (f"TARGET {P}orders 10.42.0.12:8080 unhealthy Target.ResponseCodeMismatch: "
         "Health checks failed with these codes: [404]"),
        f"TARGETGROUP {P}orders health_path=/healthz port=traffic-port matcher=200",
        f"SECRET {P}db-app changed {(NOW - timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')} (metadata only)",
        f"RULE {P}reconcile-5m State=DISABLED schedule=rate(5 minutes)",
        "postgres stuck connection: pid 42 on postgresql://writer",
        "[reader] postgres stuck connection: pid 42 on postgresql://reader",
    ]
    for line in expected:
        assert line in lines, line
    assert not any("START RequestId" in x for x in lines)
    assert not any("not ours" in x for x in lines)
    # Environment variable NAMES only - a value would be a secret in the evidence.
    # Secret-looking NAMES are shown without their value, so no fix can ever write a value back blind.
    assert not any("super-secret-value" in x or "tok-123" in x for x in lines)


def test_metrics_use_the_contract_names(dsns):
    b = _backend(_clients(cloudwatch=_cw({
        "Errors": [3, 4], "Throttles": [0], "Invocations": [10, 10], "Duration": [900, 1000],
        "ConcurrentExecutions": [2], "ApproximateAgeOfOldestMessage": [30, 600],
        "ConsumedReadCapacityUnits": [30, 60], "ConsumedWriteCapacityUnits": [120],
        "ReadThrottleEvents": [1], "WriteThrottleEvents": [5, 6], "expr": [7],
        "DatabaseMemoryUsagePercentage": [91], "Evictions": [3], "CurrConnections": [4],
        "EngineCPUUtilization": [12], "ReplicationLag": [0.5], "DatabaseConnections": [80],
        "AuroraReplicaLag": [20], "ACUUtilization": [99], "CPUUtilization": [70], "Deadlocks": [0],
        "HTTPCode_Target_5XX_Count": [2], "HTTPCode_ELB_5XX_Count": [1], "TargetResponseTime": [0.2],
        "5xx": [9], "4xx": [1], "Latency": [1500], "NumberOfNotificationsFailed": [4],
        "NumberOfNotificationsDelivered": [0],
    })))
    m = b.metrics(_full_alert())
    assert m["lambda_errors"] == 7 and m["lambda_duration_max_ms"] == 1000
    assert m["lambda_timeout_s"] == 1 and m["lambda_memory_mb"] == 256
    assert m["lambda_reserved_concurrency"] == 0 and m["lambda_concurrent_executions"] == 2
    assert m["sqs_visible"] == 120 and m["sqs_in_flight"] == 5 and m["sqs_oldest_age_s"] == 600
    assert m["sqs_visibility_timeout_s"] == 30 and m["dlq_visible"] == 14 and m["sqs_max_receive_count"] == 3
    assert m["ddb_provisioned_wcu"] == 1 and m["ddb_consumed_rcu"] == 1.0 and m["ddb_consumed_wcu"] == 2.0
    assert m["ddb_write_throttle_events"] == 11 and m["ddb_throttled_requests"] == 7
    assert m["redis_memory_pct"] == 91 and m["redis_evictions"] == 6  # summed across the two nodes
    assert m["redis_nodes_total"] == 2 and m["redis_nodes_available"] == 1
    assert m["aurora_connections"] == 80 and m["aurora_replica_lag_ms"] == 20
    assert m["aurora_acu_utilization_pct"] == 99 and m["aurora_members_available"] == 2
    assert m["connections_active"] == 90 and m["reader_connections_active"] == 90
    assert m["alb_unhealthy_hosts"] == 1 and m["alb_healthy_hosts"] == 1 and m["alb_target_5xx"] == 2
    assert m["apigw_5xx"] == 9 and m["apigw_latency_ms"] == 1500
    assert m["tasks_running"] == 2  # AwsBackend's names, unchanged
    assert m["pods_ready"] == 0  # KubernetesBackend's names, one Deployment: no suffix
    assert m["sns_notifications_failed"] == 4 and m["rule_enabled"] == 0
    assert 590 <= m["secret_changed_age_s"] <= 610


def test_absent_metrics_are_absent_not_zero(dsns):
    m = _backend().metrics(_full_alert())  # CloudWatch has no datapoint for anything
    for key in ("lambda_errors", "lambda_throttles", "sqs_oldest_age_s", "ddb_consumed_rcu",
                "redis_memory_pct", "aurora_connections", "alb_target_5xx", "apigw_5xx",
                "sns_notifications_failed", "rule_invocations", "cpu_utilization_pct"):
        assert key not in m, key
    # ...while exact API figures are still there.
    assert m["lambda_timeout_s"] == 1 and m["rule_enabled"] == 0


def test_no_reserved_concurrency_and_no_esm_are_absent():
    b = _backend(_clients(**{"lambda": _lambda(get_function_concurrency={})}))
    m = b.metrics(_alert(**{"lambda": f"{P}checkout"}))
    assert "lambda_reserved_concurrency" not in m and "lambda_esm_enabled" not in m


def test_esm_line_and_enabled_flag():
    lam = _lambda(list_event_source_mappings={"EventSourceMappings": [{
        "EventSourceArn": f"arn:aws:sqs:ap-south-2:1:{P}orders", "State": "Disabled", "BatchSize": 5,
        "LastProcessingResult": "OK"}]})
    b = _backend(_clients(**{"lambda": lam}))
    a = _alert(**{"lambda": f"{P}order-processor"})
    assert f"ESM {P}order-processor <- {P}orders State=Disabled BatchSize=5 LastProcessingResult=OK" in b.logs(a)
    assert b.metrics(a)["lambda_esm_enabled"] == 0


def test_deploys_carry_kind_and_previous(dsns):
    deploys = _backend().deploys(_full_alert())
    by_kind = {d["kind"]: d for d in deploys}
    assert by_kind["lambda"]["version"] == "7" and by_kind["lambda"]["previous"] == "6"
    assert by_kind["ecs"]["image"] == "app:8" and by_kind["ecs"]["previous_image"] == "app:7"
    # previous/version are family:revision - what an ECS rollback command aims at.
    assert re.fullmatch(r"[\w-]+:\d+", by_kind["ecs"]["previous"]), by_kind["ecs"]
    assert re.fullmatch(r"[\w-]+:\d+", by_kind["ecs"]["version"]), by_kind["ecs"]
    assert by_kind["k8s"]["image"] == "cat:bad" and by_kind["k8s"]["previous"] == "cat:good"
    assert by_kind["secret"]["service"] == f"{P}db-app"  # reported, but as a secret, not code
    assert all(d["at"].endswith("Z") for d in deploys)


def test_an_old_lambda_version_is_not_a_deploy():
    lam = _lambda(get_alias={"FunctionVersion": "6"})
    assert _backend(_clients(**{"lambda": lam})).deploys(_alert(**{"lambda": f"{P}checkout"})) == []


def test_several_lambdas_queues_rules_and_deployments_get_suffixes():
    b = _backend()
    m = b.metrics(_alert(**{"lambda": f"{P}checkout,{P}notifier", "sqs": f"{P}orders,{P}payments",
                            "eventbridge_rule": f"{P}reconcile-5m,{P}traffic-1m",
                            "namespace": "shop", "deployment": "catalog-api,cart-worker"}))
    for key in ("lambda_timeout_s__checkout", "lambda_timeout_s__notifier", "sqs_visible__orders",
                "sqs_visible__payments", "dlq_visible__orders", "rule_enabled__reconcile-5m",
                "rule_enabled__traffic-1m", "pods_ready__catalog-api", "pods_ready__cart-worker"):
        assert key in m, key
    assert "lambda_timeout_s" not in m and "sqs_visible" not in m and "pods_ready" not in m


def test_k8s_is_read_per_deployment_with_its_own_selector():
    k = FakeK8s()
    b = _backend(k8s_factory=lambda: k)
    b.logs(_alert(namespace="shop", deployment="catalog-api,cart-worker"))
    assert sorted(a.labels["selector"] for a in k.alerts) == ["app=cart-worker", "app=catalog-api"]


def test_one_read_serves_all_three_methods():
    lam = _lambda()
    b = _backend(_clients(**{"lambda": lam}))
    a = _alert(**{"lambda": f"{P}checkout"})
    b.logs(a), b.metrics(a), b.deploys(a)
    assert sum(1 for name, _ in lam.calls if name == "get_function_configuration") == 1


def test_config_reads_the_live_alias_version():
    lam = _lambda()
    _backend(_clients(**{"lambda": lam})).logs(_alert(**{"lambda": f"{P}checkout"}))
    assert ("get_function_configuration", {"FunctionName": f"{P}checkout", "Qualifier": "live"}) in lam.calls


# --------------------------------------------------------------------------- isolation


def test_a_failing_reader_is_a_partial_and_the_others_still_read(dsns):
    clients = _clients(dynamodb=Fake(describe_table=ClientError("AccessDeniedException")))
    bundle = gather(_full_alert(), backend=_backend(clients), timeout=30)
    assert any(e.startswith("logs: dynamodb: ") and "AccessDenied" in e for e in bundle.tool_errors)
    assert not any(x.startswith("TABLE ") for x in bundle.logs)
    assert bundle.metrics["lambda_timeout_s"] == 1 and bundle.metrics["rule_enabled"] == 0
    assert any(x.startswith("QUEUE ") for x in bundle.logs)


def test_a_failed_metric_read_keeps_the_api_evidence_and_says_so():
    clients = _clients(cloudwatch=Fake(get_metric_data=RuntimeError("throttled")))
    b = _backend(clients)
    a = _alert(**{"lambda": f"{P}checkout"})
    lines = b.logs(a)
    assert f"{PARTIAL_PREFIX}lambda/{P}checkout metrics: throttled" in lines
    assert any(x.startswith("CONFIG lambda") for x in lines)
    assert b.metrics(a)["lambda_timeout_s"] == 1


def test_a_failed_config_read_keeps_the_lambda_logs():
    lam = _lambda(get_function_configuration=RuntimeError("denied"))
    b = _backend(_clients(**{"lambda": lam}, logs=_events({f"/aws/lambda/{P}checkout": [("s", "boom")]})))
    lines = b.logs(_alert(**{"lambda": f"{P}checkout"}))
    assert any(x.endswith(" boom") and x.startswith(f"LOG lambda/{P}checkout") for x in lines)
    assert f"{PARTIAL_PREFIX}lambda/{P}checkout: denied" in lines


def test_a_missing_alias_is_normal_not_a_partial():
    lam = _lambda(get_alias=ClientError("ResourceNotFoundException"))
    lines = _backend(_clients(**{"lambda": lam})).logs(_alert(**{"lambda": f"{P}notifier"}))
    assert not [x for x in lines if x.startswith(PARTIAL_PREFIX)]
    assert any("alias_live=-" in x for x in lines)


def test_a_missing_dsn_is_a_partial_not_silence(monkeypatch):
    monkeypatch.delenv("WARDEN_STACK_DB_WRITER_DSN", raising=False)
    monkeypatch.delenv("WARDEN_STACK_DB_READER_DSN", raising=False)
    lines = _backend().logs(_alert(aurora_cluster=f"{P}aurora"))
    assert any(x.startswith(f"{PARTIAL_PREFIX}aurora-db-writer: WARDEN_STACK_DB_WRITER_DSN") for x in lines)
    assert any(x.startswith("CLUSTER aurora") for x in lines)


def test_an_alert_with_no_stack_labels_is_an_error_not_an_empty_bill_of_health():
    bundle = gather(_alert(), backend=_backend(), timeout=10)
    assert bundle.tool_errors and not bundle.metrics


def test_sns_policy_that_no_longer_allows_the_topic():
    lines = _backend(_clients(sqs=_sqs(policy_allows=False))).logs(_alert(sns_topic=f"{P}order-events"))
    assert f"POLICY sqs {P}notifications allows_sns_topic={P}order-events:no" in lines


def test_secret_is_read_as_metadata_only():
    sm = Fake(describe_secret={"LastChangedDate": NOW, "SecretString": "never-shown"})
    lines = _backend(_clients(secretsmanager=sm)).logs(_alert(secret=f"{P}db-app"))
    assert [name for name, _ in sm.calls] == ["describe_secret"]
    assert not any("never-shown" in x for x in lines)


# --------------------------------------------------------------------------- code-level evidence


def _v(lines, version="7"):
    return [(x, version) for x in lines]


def test_traceback_in_one_lambda_runtime_event():
    msg = ("[ERROR] KeyError: 'sku'\rTraceback (most recent call last):\r"
           '  File "/var/lang/lib/python3.12/runpy.py", line 9, in run\r    x()\r'
           '  File "/var/task/app.py", line 12, in handler\r    return process(body)\r'
           '  File "/var/task/lib/orders.py", line 41, in process\r    sku = body["sku"]')
    [tb] = parse_tracebacks(_v(msg.splitlines()))
    assert (tb["path"], tb["line"], tb["func"], tb["exception"]) == ("lib/orders.py", 41, "process", "KeyError: 'sku'")


def test_traceback_over_several_events_with_non_task_frames_skipped():
    lines = ["[ERROR] 2026-09-26 req-1 checkout failed", "Traceback (most recent call last):",
             '  File "/var/task/app.py", line 42, in handler', "    sku = body['sku']",
             '  File "/opt/python/botocore/client.py", line 960, in _make_api_call', "    raise error",
             "botocore.errorfactory.ResourceNotFoundException: Requested resource not found", "next line"]
    [tb] = parse_tracebacks(_v(lines))
    assert (tb["path"], tb["line"], tb["func"]) == ("app.py", 42, "handler")
    assert tb["exception"].startswith("botocore.errorfactory.ResourceNotFoundException")


def test_a_traceback_entirely_outside_var_task_yields_no_frame():
    lines = ["Traceback (most recent call last):", '  File "/var/runtime/bootstrap.py", line 1, in main',
             "RuntimeError: x"]
    assert parse_tracebacks(_v(lines)) == []


def test_source_excerpt_marks_the_failing_line():
    out = source_excerpt(f"{P}checkout", _zip({"app.py": APP_PY}), "app.py", 41)
    assert out[0] == f"SOURCE {P}checkout app.py:38 | line38"
    assert f"SOURCE {P}checkout app.py:41 >|     sku = body['sku']" in out
    assert len(out) == 7


def test_code_and_source_lines_from_the_running_version():
    msg = "[ERROR] KeyError: 'sku'\rTraceback (most recent call last):\r  File \"/var/task/app.py\", line 41, in handler"
    lam = _lambda()
    b = _backend(_clients(**{"lambda": lam}, logs=_events({f"/aws/lambda/{P}checkout": [("2026/09/26/[7]x", msg)]})))
    lines = b.logs(_alert(**{"lambda": f"{P}checkout"}))
    assert f"CODE {P}checkout app.py:41 in handler: KeyError: 'sku'" in lines
    assert f"SOURCE {P}checkout app.py:41 >|     sku = body['sku']" in lines
    assert ("get_function", {"FunctionName": f"{P}checkout", "Qualifier": "7"}) in lam.calls


def test_a_failed_code_download_keeps_the_frame_and_reports_the_gap():
    msg = "[ERROR] KeyError: 'sku'\rTraceback (most recent call last):\r  File \"/var/task/app.py\", line 41, in handler"

    def fail(url):
        raise TimeoutError("timed out")

    b = _backend(_clients(logs=_events({f"/aws/lambda/{P}checkout": [("s/[7]x", msg)]})), download=fail)
    lines = b.logs(_alert(**{"lambda": f"{P}checkout"}))
    assert f"CODE {P}checkout app.py:41 in handler: KeyError: 'sku'" in lines
    assert f"{PARTIAL_PREFIX}lambda/{P}checkout code: timed out" in lines


def test_download_is_https_only_and_size_capped(monkeypatch):
    with pytest.raises(Exception, match="https"):
        aws_stack._download("file:///etc/passwd")
    monkeypatch.setattr(aws_stack, "CODE_MAX_BYTES", 10)
    monkeypatch.setattr(aws_stack.urllib.request, "urlopen", lambda url, timeout: io.BytesIO(b"x" * 11))
    with pytest.raises(Exception, match="larger than 10"):
        aws_stack._download("https://bucket.example/pkg.zip")


# --------------------------------------------------------------------------- wiring


def test_resolve_backend_knows_stack(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-2")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "x")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "x")
    assert isinstance(resolve_backend("stack"), StackBackend)


# --------------------------------------------------------------------------- the boundary


def _dotted(node) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _tree(module):
    return ast.parse(pathlib.Path(inspect.getsourcefile(module)).read_text(encoding="utf-8"))


# boto3 client attribute (in both modules) -> IAM service prefix.
_CLIENT_PREFIX = {
    "_lambda": "lambda", "_logs": "logs", "_cw": "cloudwatch", "_ecs": "ecs", "_sqs": "sqs",
    "_ddb": "dynamodb", "_ec": "elasticache", "_rds": "rds", "_elb": "elasticloadbalancing",
    "_ec2": "ec2", "_eks": "eks",
    "_apigw": "apigateway", "_sm": "secretsmanager", "_sns": "sns", "_events": "events", "_sts": "sts",
}
_NOT_CLIENTS = {"_aws"}  # the reused AwsBackend; its own calls are collected from aws_backend.py
# Where the IAM action is not the CamelCase of the boto3 method.
_ACTION_OVERRIDES = {
    ("_rds", "describe_db_clusters"): "rds:DescribeDBClusters",
    ("_rds", "describe_db_instances"): "rds:DescribeDBInstances",
}


def _api_calls() -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for module in (aws_stack, aws_backend):
        for node in ast.walk(_tree(module)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                target = _dotted(node.func.value)
                if target.startswith("self._") and target.count(".") == 1:
                    attr = target.split(".", 1)[1]
                    if attr in _NOT_CLIENTS or target == "self._images":
                        continue
                    assert attr in _CLIENT_PREFIX, f"unmapped client attribute self.{attr}"
                    found.add((attr, node.func.attr))
    return found


def _iam_action(attr: str, method: str) -> str:
    if attr == "_apigw":
        # API Gateway v2 authorises every read as apigateway:GET on the resource path.
        assert method.startswith("get_"), method
        return "apigateway:GET"
    if (attr, method) in _ACTION_OVERRIDES:
        return _ACTION_OVERRIDES[(attr, method)]
    return f"{_CLIENT_PREFIX[attr]}:{''.join(p.title() for p in method.split('_'))}"


def _granted() -> set[str]:
    text = (ROOT / "terraform" / "fullstack" / "reader.tf").read_text(encoding="utf-8")
    block = re.search(r'data "aws_iam_policy_document" "fs_reader" \{.*?\n\}\n', text, re.DOTALL)
    assert block, "fs_reader policy document not found in terraform/fullstack/reader.tf"
    lists = re.findall(r"actions\s*=\s*\[(.*?)\]", block.group(0), re.DOTALL)
    assert lists, "no actions in fs_reader"
    return {a for chunk in lists for a in re.findall(r'"([^"]+)"', chunk)}


def test_iam_policy_grants_exactly_what_the_code_calls():
    called = {_iam_action(a, m) for a, m in _api_calls()}
    granted = _granted()
    assert len(called) > 20, "the AST walk found too few calls - the test itself has rotted"
    assert called == granted, (
        f"IAM policy and code disagree.\n"
        f"  code calls but policy does not grant: {sorted(called - granted)}\n"
        f"  policy grants but code never calls:   {sorted(granted - called)}"
    )


def test_every_granted_action_is_a_read():
    for action in _granted():
        verb = action.split(":", 1)[1]
        assert action == "apigateway:GET" or verb.startswith(("Describe", "Get", "List", "Filter")), action
    for forbidden in ("secretsmanager:GetSecretValue", "s3:GetObject", "ssm:GetParameter"):
        assert not any(a.startswith(forbidden) for a in _granted()), forbidden


def test_the_stack_backend_cannot_write_checked_on_the_ast():
    write_shaped = re.compile(
        r"^(create|delete|update|put|send|invoke|purge|modify|reboot|failover|terminate|start|stop|"
        r"tag|untag|register|deregister|run|restore|attach|detach|set|associate|disassociate|"
        r"execute|publish|enable|disable|rotate|copy|receive|change)_"
    )
    never = {"get_secret_value", "get_object", "get_parameter", "get_parameters",
             "get_parameters_by_path", "make_api_call", "extract", "extractall", "write_bytes",
             "write_text", "system", "popen", "Popen", "check_output"}
    offenders: list[str] = []
    for node in ast.walk(_tree(aws_stack)):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            leaf = name.rsplit(".", 1)[-1]
            if write_shaped.match(leaf) or leaf in never:
                offenders.append(name)
            if leaf == "open" or (leaf == "ZipFile" and any(
                    isinstance(a, ast.Constant) and a.value in ("w", "a", "x") for a in node.args)):
                offenders.append(f"file write {name}")
            if leaf == "getattr" and node.args and _dotted(node.args[0]).startswith("self._"):
                offenders.append("dynamic lookup on an AWS client")
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mods = [a.name for a in node.names] + ([node.module] if isinstance(node, ast.ImportFrom) else [])
            offenders += [f"import {m}" for m in mods
                          if m and m.split(".")[0] in ("subprocess", "shlex", "pty", "tempfile", "shutil")]
    assert not offenders, f"aws_stack.py must not be able to write; found: {offenders}"


def test_no_account_id_or_email_in_the_owned_files():
    for path in (ROOT / "src/warden/aws_stack.py", ROOT / "terraform/fullstack/reader.tf"):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"(?<!\d)\d{12}(?!\d)", text), path
        assert not re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", text), path


def test_no_real_client_is_ever_built():
    """_clients() must fake every client StackBackend needs, or a unit test reaches real AWS."""
    import inspect

    from warden import aws_stack
    src = inspect.getsource(aws_stack.StackBackend.__init__)
    needed = set(re.findall(r'"([a-z0-9]+)"', src[src.index("needed = ("):src.index(")", src.index("needed = ("))]))
    assert needed and needed <= set(_clients()), f"not faked: {sorted(needed - set(_clients()))}"


def test_the_cache_network_path_is_evidence(dsns):
    """An unreachable cache is a missing ingress rule; the report can only name it if these lines exist."""
    b = _backend(_clients())
    lines = b.logs(_full_alert(eks_cluster=f"{P}eks"))
    assert f"REPLGROUP {P}redis node_type=cache.t4g.micro sgs=[sg-0redis]" in lines
    assert "SG sg-0redis ingress tcp/6379 from=[sg-0lambda]" in lines, [x for x in lines if x.startswith("SG")]
    assert f"APPSG ecs/{P}orders-api sgs=[sg-0ecs]" in lines
    assert f"APPSG eks/{P}eks sgs=[sg-0eks]" in lines
