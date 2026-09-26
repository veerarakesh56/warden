"""Wave 4: every fault class of docs/WAVE4-FULLSTACK.md section 7 is detected from contract-shaped
evidence (docs/WAVE4-CONTRACT.md B/C/D), and every fix command it prints is aimed at real names and
would pass the harness allow-list (section 6, mirrored here by `allowed`).

The contexts below are built from the contract text, not from a live run: the stack backend is built
separately against the same contract. A healthy stack detects nothing; each fault detects its own
class and nothing that belongs to another fault.
"""

from __future__ import annotations

import itertools
import json
import re
import shlex

import pytest

from warden.models import Alert, ContextBundle, Severity
from warden.playbook import detect

# A real redaction placeholder looks like <EMAIL_1> or <IPV4_1>; anything else in angle brackets is a
# hole. (tests/test_report_structure.py's _HOLE, widened to labels with digits as redaction.py makes them.)
_HOLE = re.compile(r"<(?![A-Z][A-Z0-9]*_\d+>)[^>\n]{1,40}>")
ACCT = "0" * 12   # synthetic, so the redaction of account ids is exercised without writing one
TS = "2026-09-26T10:00:01Z"
REGION = "ap-south-2"

LABELS = {
    "app": "shop",
    "lambda": "warden-pg-fs-checkout,warden-pg-fs-order-processor,warden-pg-fs-notifier,warden-pg-fs-reconciler",
    "sqs": "warden-pg-fs-orders,warden-pg-fs-notifications", "dynamodb_table": "warden-pg-fs-carts",
    "elasticache": "warden-pg-fs-redis", "aurora_cluster": "warden-pg-fs-aurora",
    "alb_target_group": "warden-pg-fs-orders", "apigw": "warden-pg-fs-api", "ecs_cluster": "warden-pg-fs-ecs",
    "ecs_service": "warden-pg-fs-orders-api", "namespace": "shop", "deployment": "catalog-api,cart-worker",
    "secret": "warden-pg-fs-db-app", "sns_topic": "warden-pg-fs-order-events",
    "eventbridge_rule": "warden-pg-fs-reconcile-5m,warden-pg-fs-traffic-1m",
}

BASE_LOGS = [
    "CONFIG lambda warden-pg-fs-checkout timeout=10s memory=256MB env=[TABLE_NAME,REDIS_HOST] version=6 alias_live=6",
    "CONFIG lambda warden-pg-fs-order-processor timeout=30s memory=256MB env=[DB_HOST,DB_SECRET] version=3",
    "ESM warden-pg-fs-order-processor <- warden-pg-fs-orders State=Enabled BatchSize=5 LastProcessingResult=OK",
    "QUEUE warden-pg-fs-orders visible=0 in_flight=1 dlq=warden-pg-fs-orders-dlq dlq_visible=0 max_receive=3",
    "POLICY sqs warden-pg-fs-notifications allows_sns_topic=warden-pg-fs-order-events:yes",
    "TABLE warden-pg-fs-carts billing=PROVISIONED rcu=5 wcu=5 status=ACTIVE",
    "CLUSTER aurora warden-pg-fs-aurora writer=warden-pg-fs-aurora-1 readers=[warden-pg-fs-aurora-2] status=available",
    "TARGETGROUP warden-pg-fs-orders health_path=/health port=traffic-port matcher=200",
    "RULE warden-pg-fs-reconcile-5m State=ENABLED schedule=rate(5 minutes)",
    "RULE warden-pg-fs-traffic-1m State=ENABLED schedule=rate(1 minute)",
    f'LOG ecs/warden-pg-fs-orders-api {TS} 10.42.0.7 - "GET /health HTTP/1.1" 200 2',
    f"LOG lambda/warden-pg-fs-checkout {TS} START RequestId: 1 Version: 6",
    "LOG k8s/shop/catalog-api ROLLOUT revision 3 (current): app:v3 created 2026-09-26T09:40:00Z",
    "LOG k8s/shop/catalog-api ROLLOUT revision 2: app:v2 created 2026-09-25T09:40:00Z",
    "LOG k8s/shop/cart-worker ROLLOUT revision 4 (current): app:v3 created 2026-09-26T09:41:00Z",
    "LOG k8s/shop/cart-worker ROLLOUT revision 3: app:v2 created 2026-09-25T09:41:00Z",
]
BASE_METRICS = {
    "lambda_errors__checkout": 0.0, "lambda_throttles__checkout": 0.0, "lambda_invocations__checkout": 300.0,
    "lambda_timeout_s__checkout": 10.0, "lambda_duration_max_ms__checkout": 180.0,
    "lambda_esm_enabled__order-processor": 1.0, "sqs_visible__orders": 0.0, "dlq_visible__orders": 0.0,
    "ddb_provisioned_wcu": 5.0, "ddb_write_throttle_events": 0.0, "ddb_read_throttle_events": 0.0,
    "redis_memory_pct": 40.0, "redis_evictions": 0.0, "aurora_connections": 12.0, "connections_used_pct": 0.1,
    "alb_unhealthy_hosts": 0.0, "alb_healthy_hosts": 2.0, "apigw_5xx": 0.0, "sns_notifications_failed": 0.0,
    "rule_enabled__reconcile-5m": 1.0, "rule_enabled__traffic-1m": 1.0,
    "pods_ready__catalog-api": 2.0, "pods_total__catalog-api": 2.0,
}
_REPLACEABLE = ("CONFIG ", "ESM ", "QUEUE ", "POLICY ", "TABLE ", "CLUSTER ", "TARGETGROUP ", "RULE ")


def _resource(line: str) -> str:
    """`CONFIG lambda <fn>` / `TABLE <name>`: the tag and the resource the structural line is about."""
    return " ".join(line.split()[:3 if line.startswith(("CONFIG ", "POLICY ", "CLUSTER ")) else 2])


def ctx(logs=(), metrics=None, deploys=(), tool_errors=()) -> ContextBundle:
    """The healthy stack with a fault's lines/metrics on top. A structural line (CONFIG, RULE, ...)
    replaces the baseline line for the same resource."""
    keys = {_resource(ln) for ln in logs if ln.startswith(_REPLACEABLE)}
    base = [ln for ln in BASE_LOGS if _resource(ln) not in keys]
    return ContextBundle(logs=[*base, *logs], metrics={**BASE_METRICS, **(metrics or {})},
                         recent_deploys=list(deploys), tool_errors=list(tool_errors))


def alert() -> Alert:
    return Alert(alert_id="fs-x", name="ShopAlarm", severity=Severity.high, service="shop", environment="staging",
                 summary="shop symptom", started_at="2026-09-26T10:00:00Z", labels=dict(LABELS))


def _lam(fn, msg):
    return f"LOG lambda/warden-pg-fs-{fn} {TS} {msg}"


def _ecs(msg):
    return f"LOG ecs/warden-pg-fs-orders-api {TS} {msg}"


def _k8s(dep, msg):
    return f"LOG k8s/shop/{dep} {msg}"


ECS_DEPLOY = {"kind": "ecs", "service": "warden-pg-fs-orders-api", "at": "2026-09-26T09:55:00Z",
              "version": "warden-pg-fs-orders-api:12", "previous": "warden-pg-fs-orders-api:11"}
RO_ERR = "psycopg2.errors.ReadOnlySqlTransaction: cannot execute INSERT in a read-only transaction"
# What psycopg 3 prints when Aurora refuses an IAM token (the long host name comes first).
PAM_ERR = ('psycopg.OperationalError: connection failed: connection to server at "warden-pg-fs-aurora.cluster-'
           'cabc123.ap-south-2.rds.amazonaws.com" (203.0.113.10), port 5432 failed: FATAL:  PAM authentication '
           'failed for user "app"')

# fault id -> (class, context, the pattern key that must fire, a fragment its fix must contain or None)
FAULTS = {
    "fs-01": ("lambda_code_regression", ctx(
        [_lam("checkout", "Traceback (most recent call last):"), _lam("checkout", "KeyError: 'sku'"),
         "CONFIG lambda warden-pg-fs-checkout timeout=10s memory=256MB env=[TABLE_NAME,REDIS_HOST] version=7 alias_live=7",
         "CODE warden-pg-fs-checkout app.py:42 in handler: KeyError: 'sku'",
         "SOURCE warden-pg-fs-checkout app.py:40 | def handler(event, context):",
         "SOURCE warden-pg-fs-checkout app.py:41 |     body = json.loads(event['body'])",
         "SOURCE warden-pg-fs-checkout app.py:42 >|     sku = body['sku']"],
        {"lambda_errors__checkout": 40.0, "apigw_5xx": 40.0},
        [{"kind": "lambda", "service": "warden-pg-fs-checkout", "at": "2026-09-26T09:58:00Z", "version": "7",
          "previous": "6"}]),
        "code_error_after_deploy", "update-alias --function-name warden-pg-fs-checkout --name live --function-version 6"),
    "fs-02": ("lambda_timeout_too_low", ctx(
        [_lam("checkout", "Task timed out after 1.00 seconds"),
         "CONFIG lambda warden-pg-fs-checkout timeout=1s memory=256MB env=[TABLE_NAME,REDIS_HOST] version=6 alias_live=6"],
        {"lambda_timeout_s__checkout": 1.0, "lambda_duration_max_ms__checkout": 1001.0, "lambda_errors__checkout": 30.0}),
        "fn_timeout", "update-function-configuration --function-name warden-pg-fs-checkout --timeout 3"),
    "fs-03": ("lambda_throttled", ctx(
        [], {"lambda_throttles__checkout": 120.0, "lambda_reserved_concurrency__checkout": 0.0,
             "lambda_invocations__checkout": 0.0}),
        "fn_throttled", "put-function-concurrency --function-name warden-pg-fs-checkout --reserved-concurrent-executions 4"),
    "fs-04": ("lambda_bad_env", ctx(
        [_lam("checkout", "botocore.errorfactory.ResourceNotFoundException: An error occurred (ResourceNotFoundException) "
                          "when calling the PutItem operation: Requested resource not found"),
         ("CONFIG lambda warden-pg-fs-checkout timeout=10s memory=256MB "
         "env=[TABLE_NAME=warden-pg-fs-cartz,REDIS_HOST=warden-pg-fs-redis.abc123.cache.amazonaws.com] version=6")],
        {"lambda_errors__checkout": 25.0}),
        "missing_resource", '"TABLE_NAME":"warden-pg-fs-carts"'),
    "fs-05": ("lambda_iam_missing", ctx(
        [_lam("checkout", "botocore.exceptions.ClientError: An error occurred (AccessDeniedException) when calling the "
                          f"PutItem operation: User: arn:aws:sts::{ACCT}:assumed-role/warden-pg-fs-checkout-role/"
                          "warden-pg-fs-checkout is not authorized to perform: dynamodb:PutItem on resource: "
                          f"arn:aws:dynamodb:{REGION}:{ACCT}:table/warden-pg-fs-carts because no identity-based "
                          "policy allows the dynamodb:PutItem action")],
        {"lambda_errors__checkout": 25.0}),
        "access_denied", "iam put-role-policy --role-name warden-pg-fs-checkout-role"),
    "fs-06": ("sqs_poison_message", ctx(
        ["QUEUE warden-pg-fs-orders visible=0 in_flight=0 dlq=warden-pg-fs-orders-dlq dlq_visible=14 max_receive=3",
         _lam("order-processor", "Traceback (most recent call last):"),
         "CODE warden-pg-fs-order-processor app.py:18 in handler: json.decoder.JSONDecodeError: Expecting value"],
        {"dlq_visible__orders": 14.0, "lambda_errors__order-processor": 42.0}),
        "dead_letters", None),
    "fs-07": ("sqs_consumer_disabled", ctx(
        ["ESM warden-pg-fs-order-processor <- warden-pg-fs-orders State=Disabled BatchSize=5 LastProcessingResult=OK"],
        {"lambda_esm_enabled__order-processor": 0.0, "sqs_visible__orders": 120.0}),
        "consumer_off", "update-event-source-mapping --uuid"),
    "fs-08": ("sns_delivery_blocked", ctx(
        ["POLICY sqs warden-pg-fs-notifications allows_sns_topic=warden-pg-fs-order-events:no"],
        {"sns_notifications_failed": 12.0}),
        "topic_delivery_refused", "sqs set-queue-attributes --queue-url"),
    "fs-09": ("dynamodb_throttling", ctx(
        ["TABLE warden-pg-fs-carts billing=PROVISIONED rcu=1 wcu=1 status=ACTIVE"],
        {"ddb_write_throttle_events": 300.0, "ddb_consumed_wcu": 1.0, "ddb_provisioned_wcu": 1.0}),
        "table_throttled", "ReadCapacityUnits=1,WriteCapacityUnits=3"),
    "fs-10": ("redis_unreachable", ctx(
        [_lam("reconciler", "redis.exceptions.TimeoutError: Timeout connecting to server "
                            "warden-pg-fs-redis.abc123.cache.amazonaws.com:6379"),
         "REPLGROUP warden-pg-fs-redis node_type=cache.t4g.micro sgs=[sg-0redis]",
         "SG sg-0redis ingress tcp/6379 from=[]",
         "APPSG ecs/warden-pg-fs-orders-api sgs=[sg-0ecs]",
         ("CONFIG lambda warden-pg-fs-reconciler timeout=90s memory=256MB reserved_concurrency=none "
          "env=[RECONCILE_LOOKUP=by_id] sgs=[sg-0lambda] version=3 alias_live=-")],
        {"lambda_errors__reconciler": 5.0}),
        "cache_unreachable", ("authorize-security-group-ingress --group-id sg-0redis --protocol tcp --port 6379 "
                              "--source-group sg-0ecs")),
    "fs-11": ("redis_memory_pressure", ctx(
        ["REPLGROUP warden-pg-fs-redis node_type=cache.t4g.micro sgs=[sg-0redis]"],
        {"redis_memory_pct": 97.0, "redis_evictions": 5400.0}),
              "cache_memory", "--cache-node-type cache.t4g.small"),
    "fs-12": ("aurora_connection_exhaustion", ctx(
        [_lam("order-processor", 'psycopg2.OperationalError: connection to server failed: FATAL:  sorry, too many '
                                 'clients already')],
        {"connections_used_pct": 1.0, "aurora_connections": 90.0}),
        "db_connections_refused", "pg_terminate_backend"),
    "fs-13": ("aurora_lock_contention", ctx(
        ["postgres blocked session: pid=5123 waiting 300s on pid(s) 4077: UPDATE orders SET status = $1 WHERE id = $2"],
        {"locks_waiting": 1.0}),
        "db_lock", "WHERE b.pid IN (4077)"),
    "fs-14": ("aurora_write_to_reader", ctx(
        [_lam("order-processor", RO_ERR), f"CODE warden-pg-fs-order-processor app.py:30 in save: {RO_ERR}",
         "QUEUE warden-pg-fs-orders visible=3 in_flight=0 dlq=warden-pg-fs-orders-dlq dlq_visible=6 max_receive=3",
         ("CONFIG lambda warden-pg-fs-order-processor timeout=30s memory=256MB "
         "env=[DB_HOST=warden-pg-fs-aurora.cluster-ro-cabc123.ap-south-2.rds.amazonaws.com,DB_NAME=shop] version=3")],
        {"dlq_visible__orders": 6.0, "lambda_errors__order-processor": 18.0}),
        "db_write_on_reader", "warden-pg-fs-aurora.cluster-cabc123.ap-south-2.rds.amazonaws.com"),
    "fs-15": ("aurora_failover_pinned_endpoint", ctx(
        [f"EVENT aurora warden-pg-fs-aurora {TS} Completed failover to DB instance: warden-pg-fs-aurora-2",
         "CLUSTER aurora warden-pg-fs-aurora writer=warden-pg-fs-aurora-2 readers=[warden-pg-fs-aurora-1] status=available",
         _lam("order-processor", RO_ERR)],
        {"lambda_errors__order-processor": 18.0}),
        "db_pinned_after_failover",
        "failover-db-cluster --db-cluster-identifier warden-pg-fs-aurora --target-db-instance-identifier warden-pg-fs-aurora-1"),
    "fs-16": ("aurora_slow_query", ctx(
        [("postgres long-running query: pid=7311 running 140s user=app app=order-processor client=10.42.0.50: "
         "SELECT id, total FROM orders WHERE customer_ref = $1")],
        {"long_running_queries": 1.0, "aurora_acu_utilization_pct": 95.0}),
        "db_long_query", "CREATE INDEX CONCURRENTLY IF NOT EXISTS warden_orders_customer_ref_idx ON orders (customer_ref);"),
    "fs-17": ("ecs_bad_image", ctx(
        [_ecs("task 7f stopped: CannotPullContainerError: pull image manifest has been retried 5 time(s): failed to "
              "resolve ref warden-pg-fs-app:does-not-exist: not found")], {}, [ECS_DEPLOY]),
        "task_image_pull", "--task-definition warden-pg-fs-orders-api:11"),
    "fs-18": ("ecs_secret_access_denied", ctx(
        [_ecs("task 8a stopped: ResourceInitializationError: unable to pull secrets or registry auth: execution "
              "resource retrieval failed: unable to retrieve secret from asm: AccessDeniedException: User: "
              f"arn:aws:sts::{ACCT}:assumed-role/warden-pg-fs-ecs-exec/8a is not authorized to perform: "
              f"secretsmanager:GetSecretValue on resource: arn:aws:secretsmanager:{REGION}:{ACCT}:secret:"
              "warden-pg-fs-db-app-AbCdEf because no identity-based policy allows the action")]),
        "task_secret_denied", "--role-name warden-pg-fs-ecs-exec"),
    "fs-19": ("alb_health_check_wrong", ctx(
        [("TARGET warden-pg-fs-orders 10.42.0.12:8080 unhealthy Target.ResponseCodeMismatch: Health checks failed "
         "with these codes: [404]"),
         "TARGETGROUP warden-pg-fs-orders health_path=/healthz port=traffic-port matcher=200"],
        {"alb_unhealthy_hosts": 2.0, "alb_healthy_hosts": 0.0}),
        "lb_health_check", "--health-check-path /health"),
    "fs-20": ("ecs_oom", ctx(
        [_ecs("task 9c stopped: OutOfMemoryError: Container killed due to memory usage (exit code 137)")],
        {}, [ECS_DEPLOY]),
        "task_oom", "--task-definition warden-pg-fs-orders-api:11"),
    "fs-21": ("db_iam_auth_revoked", ctx(
        [_ecs(PAM_ERR), "TASKROLE ecs/warden-pg-fs-orders-api role=warden-pg-fs-orders-api-task"],
        {"alb_target_5xx": 40.0}),
        "db_iam_auth_refused", "iam put-role-policy --role-name warden-pg-fs-orders-api-task"),
    "fs-22": ("k8s_config_crashloop", ctx(
        [_k8s("catalog-api", "EVENT BackOff Pod/catalog-api-7d9-abcde: Back-off restarting failed container app"),
         _k8s("catalog-api", "catalog-api-7d9-abcde/app (previous) 2026-09-26T09:59:00Z ValueError: invalid literal "
                             "for int() with base 10: 'eight'")],
        {"crashloop_containers__catalog-api": 2.0, "pods_ready__catalog-api": 0.0}),
        "crashloop", None),
    "fs-23": ("k8s_missing_secret_key", ctx(
        [_k8s("catalog-api", "EVENT Failed Pod/catalog-api-7d9-abcde: Error: couldn't find key CATALOG_SIGNING_KEY in "
                             "Secret shop/catalog-secret"),
         _k8s("catalog-api", "STATUS catalog-api-7d9-abcde/app: now waiting: CreateContainerConfigError")],
        {"pods_ready__catalog-api": 0.0}),
        "secret_key_missing", None),
    "fs-24": ("k8s_readiness_probe_wrong", ctx(
        [_k8s("catalog-api", 'EVENT Unhealthy Pod/catalog-api-7d9-abcde: Readiness probe failed: Get '
                             '"http://10.42.0.33:9999/ready": dial tcp 10.42.0.33:9999: connect: connection refused')],
        {"pods_ready__catalog-api": 0.0}),
        "probe", "kubectl -n shop rollout undo deploy/catalog-api"),
    "fs-25": ("k8s_unschedulable_requests", ctx(
        [_k8s("cart-worker", "EVENT FailedScheduling Pod/cart-worker-5f8-xyz12: 0/1 nodes are available: "
                             "1 Insufficient cpu.")]),
        "unschedulable", "kubectl -n shop rollout undo deploy/cart-worker"),
    "fs-26": ("k8s_image_pull", ctx(
        [_k8s("catalog-api", 'EVENT Failed Pod/catalog-api-9b1-qwert: Failed to pull image "app:nope": not found'),
         _k8s("catalog-api", "EVENT BackOff Pod/catalog-api-9b1-qwert: Back-off pulling image: ImagePullBackOff")],
        {"pods_ready__catalog-api": 1.0}),
        "image_pull", "kubectl -n shop rollout undo deploy/catalog-api"),
    "fs-27": ("eventbridge_rule_disabled", ctx(
        ["RULE warden-pg-fs-reconcile-5m State=DISABLED schedule=rate(5 minutes)"],
        {"rule_enabled__reconcile-5m": 0.0, "rule_invocations__reconcile-5m": 0.0}),
        "schedule_off", "aws events enable-rule --name warden-pg-fs-reconcile-5m --region ap-south-2"),
}

# Patterns a fault may legitimately raise beside its own: the same evidence read another true way.
EXTRA_OK = {
    "fs-01": {"deploy"}, "fs-12": {"db_pool"}, "fs-17": {"deploy"}, "fs-20": {"deploy"},
    "fs-22": {"deploy"}, "fs-24": set(), "fs-26": {"deploy"},
}

# ---------------------------------------------------------------- the harness allow-list (section 6)

_MUTATIONS = {
    "lambda": {"update-alias", "update-function-configuration", "put-function-concurrency",
               "update-event-source-mapping"},
    "dynamodb": {"update-table"}, "ecs": {"update-service"}, "elbv2": {"modify-target-group"},
    "events": {"enable-rule"}, "sqs": {"set-queue-attributes"}, "rds": {"failover-db-cluster"},
    "iam": {"put-role-policy"},
    # Not in section 6's example list: printed for fs-11 when a node type is known. The harness must
    # add it or record fix_not_allowed.
    "elasticache": {"modify-replication-group"},
    # fs-10: restoring the cache security group's ingress (the real harness checks the SG ids are the stack's).
    "ec2": {"authorize-security-group-ingress"},
}
_NAME_FLAGS = ("--function-name", "--table-name", "--cluster", "--service", "--queue-name", "--names",
               "--role-name", "--db-cluster-identifier", "--target-db-instance-identifier", "--replication-group-id",
               "--task-definition")
_KUBECTL = re.compile(r"^kubectl -n shop (rollout (undo|restart)|set|patch|scale|apply -f -) ")
_SQL_OK = re.compile(r"(?is)^(SELECT .*\bpg_(terminate|cancel)_backend\(|CREATE INDEX CONCURRENTLY |ALTER DATABASE \S+ SET )")


def allowed(entry: dict) -> str | None:
    """None when the harness would run it; otherwise why not."""
    cmd = entry["command"]
    if entry["kind"] == "sql":
        return None if _SQL_OK.match(cmd) and entry.get("target") == "writer" else f"sql not allowed: {cmd}"
    if cmd.startswith("kubectl "):
        return None if _KUBECTL.match(cmd) else f"kubectl not allowed: {cmd}"
    if not cmd.startswith("aws "):
        return f"not aws/kubectl/sql: {cmd}"
    calls = re.findall(r"\baws ([a-z0-9-]+) ([a-z0-9-]+)", cmd)
    if cmd.count(f"--region {REGION}") != len(calls):
        return f"an aws call without --region {REGION}: {cmd}"
    (svc, verb), *nested = calls
    if verb not in _MUTATIONS.get(svc, set()):
        return f"verb not allowed: {svc} {verb}"
    if any(not re.match(r"(get|list|describe)-", v) for _, v in nested):
        return f"a nested call that is not a read: {nested}"
    if "delete" in cmd:
        return "delete"
    if svc == "events" and not re.search(r"--name warden-pg-fs-", cmd):
        return "a rule outside warden-pg-fs-*"
    if svc == "iam" and not re.search(r"--role-name warden-pg-fs-", cmd):
        return "iam on a role outside warden-pg-fs-*"
    tokens = shlex.split(cmd.replace("$(", " ").replace(")\"", "\""))
    for flag, value in itertools.pairwise(tokens):
        if flag in _NAME_FLAGS and not value.startswith("warden-pg-fs-"):
            return f"{flag} {value} is not a warden-pg-fs-* resource"
    return None


def _fix_entries(fix: list[str]) -> list[dict]:
    return [{"kind": "sql" if re.match(r"(?i)(SELECT|CREATE|ALTER)\b", c) else "shell", "command": c,
             "target": "writer"} for c in fix]


@pytest.fixture(autouse=True)
def _region(monkeypatch):
    monkeypatch.setenv("AWS_REGION", REGION)


# ---------------------------------------------------------------- tests


def test_a_healthy_stack_detects_nothing():
    assert detect(alert(), ctx()) == []


@pytest.mark.parametrize("fid", sorted(FAULTS))
def test_each_fault_detects_its_own_class_with_an_aimed_fix(fid):
    _, context, key, fragment = FAULTS[fid]
    found = {p.key: p for p in detect(alert(), context)}
    assert key in found, f"{fid}: {sorted(found)}"
    pat = found[key]
    assert pat.seen and pat.likely_cause
    if fragment:
        assert any(fragment in c for c in pat.fix), (fid, pat.fix)
    else:
        assert pat.fix == [] and any(t.startswith("No command:") for t in pat.oncall), (fid, pat.oncall)
    for entry in _fix_entries(pat.fix):
        assert not _HOLE.search(entry["command"]), entry
        assert allowed(entry) is None, allowed(entry)


@pytest.mark.parametrize("fid", sorted(FAULTS))
def test_no_fault_raises_another_faults_pattern(fid):
    """The cross-check matrix: what a fault's evidence detects is its own class, plus only the
    listed legitimate extras - never the class of a different fault."""
    _, context, key, _ = FAULTS[fid]
    keys = {p.key for p in detect(alert(), context)}
    others = {k for f, (_, _, k, _) in FAULTS.items() if f != fid} - {key}
    assert not (keys & others) - EXTRA_OK.get(fid, set()), (fid, sorted(keys))


def test_every_fault_class_of_the_wave_is_covered():
    assert {cls for cls, *_ in FAULTS.values()} == {
        "lambda_code_regression", "lambda_timeout_too_low", "lambda_throttled", "lambda_bad_env",
        "lambda_iam_missing", "sqs_poison_message", "sqs_consumer_disabled", "sns_delivery_blocked",
        "dynamodb_throttling", "redis_unreachable", "redis_memory_pressure", "aurora_connection_exhaustion",
        "aurora_lock_contention", "aurora_write_to_reader", "aurora_failover_pinned_endpoint", "aurora_slow_query",
        "ecs_bad_image", "ecs_secret_access_denied", "alb_health_check_wrong", "ecs_oom",
        "db_iam_auth_revoked", "k8s_config_crashloop", "k8s_missing_secret_key",
        "k8s_readiness_probe_wrong", "k8s_unschedulable_requests", "k8s_image_pull", "eventbridge_rule_disabled"}


def test_the_code_regression_names_the_failing_line_for_developers():
    pat = next(p for p in detect(alert(), FAULTS["fs-01"][1]) if p.key == "code_error_after_deploy")
    assert "app.py:42 in handler (warden-pg-fs-checkout): KeyError: 'sku'" in pat.developers[0]
    assert "`sku = body['sku']`" in pat.developers[0]


def test_a_traceback_without_a_deploy_is_not_called_a_regression():
    assert "code_error_after_deploy" not in {p.key for p in detect(alert(), FAULTS["fs-06"][1])}


def test_the_timeout_is_computed_from_observed_duration_when_it_was_not_capped():
    c = ctx([_lam("checkout", "Task timed out after 3.00 seconds"),
             "CONFIG lambda warden-pg-fs-checkout timeout=3s memory=256MB env=[TABLE_NAME] version=6"],
            {"lambda_timeout_s__checkout": 3.0, "lambda_duration_max_ms__checkout": 2100.0})
    pat = next(p for p in detect(alert(), c) if p.key == "fn_timeout")
    assert pat.fix == [("aws lambda update-function-configuration --function-name warden-pg-fs-checkout "
                       "--timeout 5 --region ap-south-2")]
    assert "2 x the longest observed duration (2100 ms)" in pat.oncall[0]


def test_env_without_values_prints_no_update_that_would_wipe_the_environment():
    c = ctx([_lam("checkout", "ResourceNotFoundException: Requested resource not found")])
    pat = next(p for p in detect(alert(), c) if p.key == "missing_resource")
    assert pat.fix == [] and "replaces all of it" in pat.oncall[0]


def test_a_bad_env_that_arrived_with_a_version_is_rolled_back_not_patched():
    c = ctx([_lam("checkout", "ResourceNotFoundException: Requested resource not found"),
             "CONFIG lambda warden-pg-fs-checkout timeout=10s memory=256MB env=[TABLE_NAME] version=7 alias_live=7"],
            deploys=[{"kind": "lambda", "service": "warden-pg-fs-checkout", "at": TS, "version": "7", "previous": "6"}])
    pat = next(p for p in detect(alert(), c) if p.key == "missing_resource")
    assert pat.fix == [("aws lambda update-alias --function-name warden-pg-fs-checkout --name live "
                       "--function-version 6 --region ap-south-2")]


def test_throttling_without_a_reservation_is_the_account_limit_and_gets_no_command():
    pat = next(p for p in detect(alert(), ctx([], {"lambda_throttles__checkout": 9.0})) if p.key == "fn_throttled")
    assert pat.fix == [] and "regional concurrency limit" in pat.oncall[0]


def test_a_reader_endpoint_without_env_values_prints_no_command_and_says_why():
    c = ctx([_lam("order-processor", RO_ERR)])
    pat = next(p for p in detect(alert(), c) if p.key == "db_write_on_reader")
    assert pat.fix == [] and "not their values" in pat.oncall[0]


def test_the_sns_policy_is_valid_json_aimed_at_the_named_queue_and_topic():
    pat = next(p for p in detect(alert(), FAULTS["fs-08"][1]) if p.key == "topic_delivery_refused")
    attrs = json.loads(shlex.split(pat.fix[0])[-3])
    stmt = json.loads(attrs["Policy"])["Statement"][0]
    assert stmt["Resource"] == "arn:aws:sqs:ap-south-2:*:warden-pg-fs-notifications"
    assert stmt["Condition"]["ArnLike"]["aws:SourceArn"] == "arn:aws:sns:ap-south-2:*:warden-pg-fs-order-events"
    assert "get-queue-url --queue-name warden-pg-fs-notifications" in pat.fix[0]


def test_the_secret_grant_is_the_exact_action_and_survives_as_json():
    pat = next(p for p in detect(alert(), FAULTS["fs-18"][1]) if p.key == "task_secret_denied")
    doc = json.loads(shlex.split(pat.fix[0])[shlex.split(pat.fix[0]).index("--policy-document") + 1])
    assert doc["Statement"][0]["Action"] == "secretsmanager:GetSecretValue"
    assert doc["Statement"][0]["Resource"] == "arn:aws:secretsmanager:ap-south-2:*:secret:warden-pg-fs-db-app-*"
    assert ACCT not in " ".join(pat.fix)
    assert pat.fix[1].endswith("--force-new-deployment --region ap-south-2")
    assert "access_denied" not in {p.key for p in detect(alert(), FAULTS["fs-18"][1])}


def test_redis_memory_names_the_next_node_size_only_when_the_node_type_is_read():
    c = ctx(["REPLGROUP warden-pg-fs-redis node_type=cache.t4g.micro status=available"],
            {"redis_memory_pct": 97.0, "redis_evictions": 5400.0})
    pat = next(p for p in detect(alert(), c) if p.key == "cache_memory")
    assert pat.fix == [("aws elasticache modify-replication-group --replication-group-id warden-pg-fs-redis "
                       "--cache-node-type cache.t4g.small --apply-immediately --region ap-south-2")]
    assert allowed(_fix_entries(pat.fix)[0]) is None


def test_the_allow_list_mirror_refuses_what_section_6_refuses():
    bad = ["aws lambda delete-function-concurrency --function-name warden-pg-fs-checkout --region ap-south-2",
           "aws lambda update-alias --function-name other-fn --name live --function-version 1 --region ap-south-2",
           "aws lambda update-alias --function-name warden-pg-fs-checkout --name live --function-version 1",
           "aws iam put-role-policy --role-name admin --policy-name x --policy-document '{}' --region ap-south-2",
           "kubectl -n kube-system rollout undo deploy/coredns", "kubectl -n shop delete pod x"]
    for cmd in bad:
        assert allowed({"kind": "shell", "command": cmd}) is not None, cmd
    assert allowed({"kind": "sql", "command": "DROP TABLE orders;", "target": "writer"}) is not None


def test_with_no_region_known_no_region_is_invented(monkeypatch):
    monkeypatch.delenv("AWS_REGION")
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    pat = next(p for p in detect(alert(), FAULTS["fs-27"][1]) if p.key == "schedule_off")
    assert pat.fix == ["aws events enable-rule --name warden-pg-fs-reconcile-5m"]


def test_a_function_without_the_alias_gets_no_update_alias():
    """The stack backend writes `alias_live=-` when the alias does not exist: moving it would fail."""
    c = ctx([("CONFIG lambda warden-pg-fs-order-processor timeout=30s memory=256MB reserved_concurrency=none "
             "env=[DB_HOST] version=4 alias_live=-"),
             "CODE warden-pg-fs-order-processor app.py:9 in handler: KeyError: 'id'"],
            deploys=[{"kind": "lambda", "service": "warden-pg-fs-order-processor", "at": TS, "version": "4",
                      "previous": "3"}])
    pat = next(p for p in detect(alert(), c) if p.key == "code_error_after_deploy")
    assert pat.fix == [] and pat.oncall[0].startswith("No command:")


def test_the_crash_loop_advice_names_the_failing_deployment_not_the_label_list():
    pat = next(p for p in detect(alert(), FAULTS["fs-22"][1]) if p.key == "crashloop")
    assert "kubectl -n shop logs deploy/catalog-api --previous" in pat.oncall[0]
    assert "catalog-api,cart-worker" not in " ".join(pat.oncall)


def test_cache_ingress_names_only_the_missing_rules():
    """Only application SGs with no rule on the cache SG get one; an allowed SG is never re-added."""
    base = [_lam("reconciler", "redis.exceptions.TimeoutError: Timeout connecting to server x:6379"),
            "REPLGROUP warden-pg-fs-redis node_type=cache.t4g.micro sgs=[sg-0redis]",
            "APPSG ecs/warden-pg-fs-orders-api sgs=[sg-0ecs]", "APPSG eks/warden-pg-fs-eks sgs=[sg-0eks]"]
    pats = {p.key: p for p in detect(alert(), ctx(base + ["SG sg-0redis ingress tcp/6379 from=[sg-0ecs]"]))}
    fix = pats["cache_unreachable"].fix
    assert len(fix) == 1 and "--source-group sg-0eks" in fix[0] and "sg-0ecs" not in fix[0], fix
    full = {p.key: p for p in detect(alert(), ctx(base + ["SG sg-0redis ingress tcp/6379 from=[sg-0ecs,sg-0eks]"]))}
    assert full["cache_unreachable"].fix == []
    bare = {p.key: p for p in detect(alert(), ctx(base[:1]))}
    assert bare["cache_unreachable"].fix == []


def test_the_iam_login_grant_is_exactly_rds_db_connect_for_the_refused_user():
    pat = next(p for p in detect(alert(), FAULTS["fs-21"][1]) if p.key == "db_iam_auth_refused")
    tokens = shlex.split(pat.fix[0])
    doc = json.loads(tokens[tokens.index("--policy-document") + 1])
    assert doc["Statement"] == [{"Effect": "Allow", "Action": "rds-db:connect",
                                 "Resource": "arn:aws:rds-db:ap-south-2:*:dbuser:*/app"}]
    assert tokens[tokens.index("--role-name") + 1] == "warden-pg-fs-orders-api-task"
    assert pat.fix[0].endswith("--region ap-south-2") and len(pat.fix) == 1
    assert "stale_credentials" not in {p.key for p in detect(alert(), FAULTS["fs-21"][1])}


def test_an_iam_login_refusal_without_the_role_in_evidence_prints_no_command_and_says_which_line():
    pat = next(p for p in detect(alert(), ctx([_ecs(PAM_ERR)])) if p.key == "db_iam_auth_refused")
    assert pat.fix == [] and "TASKROLE ecs/<service> role=<name>" in pat.oncall[0]
    lam = next(p for p in detect(alert(), ctx([_lam("order-processor", PAM_ERR)])) if p.key == "db_iam_auth_refused")
    assert lam.fix == [] and lam.oncall[0].startswith("No command:")
    assert "code_error_after_deploy" not in {p.key for p in detect(alert(), ctx(
        [f"CODE warden-pg-fs-order-processor app.py:40 in _connect: {PAM_ERR}"],
        deploys=[{"kind": "lambda", "service": "warden-pg-fs-order-processor", "at": TS, "version": "4",
                  "previous": "3"}]))}, "a refused login is not a code regression"


def test_a_rotated_password_is_still_read_as_stale_credentials():
    """The pre-2026-09-26 fs-21 shape: no longer injected in Wave 4, still a pattern WARDEN knows."""
    c = ctx([_ecs('psycopg2.OperationalError: connection to server failed: FATAL:  password authentication failed '
                  'for user "app"'), "SECRET warden-pg-fs-db-app changed 2026-09-26T09:50:00Z (metadata only)"],
            {"secret_changed_age_s": 600.0},
            [{"kind": "secret", "service": "warden-pg-fs-db-app", "at": "2026-09-26T09:50:00Z", "version": "v2",
              "previous": "v1"}])
    pat = next(p for p in detect(alert(), c) if p.key == "stale_credentials")
    assert pat.fix == [("aws ecs update-service --cluster warden-pg-fs-ecs --service warden-pg-fs-orders-api "
                        "--force-new-deployment --region ap-south-2")]
