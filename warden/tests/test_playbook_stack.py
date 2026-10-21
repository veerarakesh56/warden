"""Wave 4: every fault class of demo-app/docs/FULLSTACK-LAB.md section 5 is detected from contract-shaped
evidence (demo-app/docs/FULLSTACK-LAB.md section 4, B/C/D), and its advice names what that evidence shows. The advice holds
no command (2026-10-16; warden/tests/test_no_commands.py): it used to carry exact fix commands, checked here
against a mirror of the harness allow-list.

The contexts below are built from the contract text, not from a live run: the stack backend is built
separately against the same contract. A healthy stack detects nothing; each fault detects its own
class and nothing that belongs to another fault.
"""

from __future__ import annotations

import re

import pytest

from warden.models import Alert, ContextBundle, Severity
from warden.playbook import detect

# A real redaction placeholder looks like <EMAIL_1> or <IPV4_1>; anything else in angle brackets is a
# hole. (warden/tests/test_report_structure.py's _HOLE, widened to labels with digits as redaction.py makes them.)
_HOLE = re.compile(r"<(?![A-Z][A-Z0-9]*_\d+>)[^>\n]{1,40}>")
ACCT = "0" * 12   # synthetic, so the redaction of account ids is exercised without writing one
TS = "2026-09-26T10:00:01Z"
REGION = "ap-south-2"

LABELS = {
    "app": "shop",
    "lambda": "warden-dev-checkout,warden-dev-order-processor,warden-dev-notifier,warden-dev-reconciler",
    "sqs": "warden-dev-orders,warden-dev-notifications", "dynamodb_table": "warden-dev-carts",
    "elasticache": "warden-dev-redis", "aurora_cluster": "warden-dev-aurora",
    "alb_target_group": "warden-dev-orders", "apigw": "warden-dev-api", "ecs_cluster": "warden-dev-ecs",
    "ecs_service": "warden-dev-orders-api", "namespace": "shop", "deployment": "catalog-api,cart-worker",
    "secret": "warden-dev-db-app", "sns_topic": "warden-dev-order-events",
    "eventbridge_rule": "warden-dev-reconcile-5m,warden-dev-traffic-1m",
}

BASE_LOGS = [
    "CONFIG lambda warden-dev-checkout timeout=10s memory=256MB env=[TABLE_NAME,REDIS_HOST] version=6 alias_live=6",
    "CONFIG lambda warden-dev-order-processor timeout=30s memory=256MB env=[DB_HOST,DB_SECRET] version=3",
    "ESM warden-dev-order-processor <- warden-dev-orders State=Enabled BatchSize=5 LastProcessingResult=OK",
    "QUEUE warden-dev-orders visible=0 in_flight=1 dlq=warden-dev-orders-dlq dlq_visible=0 max_receive=3",
    "POLICY sqs warden-dev-notifications allows_sns_topic=warden-dev-order-events:yes",
    "TABLE warden-dev-carts billing=PROVISIONED rcu=5 wcu=5 status=ACTIVE",
    "CLUSTER aurora warden-dev-aurora writer=warden-dev-aurora-1 readers=[warden-dev-aurora-2] status=available",
    "TARGETGROUP warden-dev-orders health_path=/health port=traffic-port matcher=200",
    "RULE warden-dev-reconcile-5m State=ENABLED schedule=rate(5 minutes)",
    "RULE warden-dev-traffic-1m State=ENABLED schedule=rate(1 minute)",
    f'LOG ecs/warden-dev-orders-api {TS} 10.42.0.7 - "GET /health HTTP/1.1" 200 2',
    f"LOG lambda/warden-dev-checkout {TS} START RequestId: 1 Version: 6",
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
    return f"LOG lambda/warden-dev-{fn} {TS} {msg}"


def _ecs(msg):
    return f"LOG ecs/warden-dev-orders-api {TS} {msg}"


def _k8s(dep, msg):
    return f"LOG k8s/shop/{dep} {msg}"


ECS_DEPLOY = {"kind": "ecs", "service": "warden-dev-orders-api", "at": "2026-09-26T09:55:00Z",
              "version": "warden-dev-orders-api:12", "previous": "warden-dev-orders-api:11"}
RO_ERR = "psycopg2.errors.ReadOnlySqlTransaction: cannot execute INSERT in a read-only transaction"
# What psycopg 3 prints when Aurora refuses an IAM token (the long host name comes first).
PAM_ERR = ('psycopg.OperationalError: connection failed: connection to server at "warden-dev-aurora.cluster-'
           'cabc123.ap-south-2.rds.amazonaws.com" (203.0.113.10), port 5432 failed: FATAL:  PAM authentication '
           'failed for user "app"')

# fault id -> (class, context, the pattern key that must fire, a fragment its advice must hold, or None)
FAULTS = {
    "fs-01": ("lambda_code_regression", ctx(
        [_lam("checkout", "Traceback (most recent call last):"), _lam("checkout", "KeyError: 'sku'"),
         "CONFIG lambda warden-dev-checkout timeout=10s memory=256MB env=[TABLE_NAME,REDIS_HOST] version=7 alias_live=7",
         "CODE warden-dev-checkout app.py:42 in handler: KeyError: 'sku'",
         "SOURCE warden-dev-checkout app.py:40 | def handler(event, context):",
         "SOURCE warden-dev-checkout app.py:41 |     body = json.loads(event['body'])",
         "SOURCE warden-dev-checkout app.py:42 >|     sku = body['sku']"],
        {"lambda_errors__checkout": 40.0, "apigw_5xx": 40.0},
        [{"kind": "lambda", "service": "warden-dev-checkout", "at": "2026-09-26T09:58:00Z", "version": "7",
          "previous": "6"}]),
        "code_error_after_deploy", "it served version 6 before"),
    "fs-02": ("lambda_timeout_too_low", ctx(
        [_lam("checkout", "Task timed out after 1.00 seconds"),
         "CONFIG lambda warden-dev-checkout timeout=1s memory=256MB env=[TABLE_NAME,REDIS_HOST] version=6 alias_live=6"],
        {"lambda_timeout_s__checkout": 1.0, "lambda_duration_max_ms__checkout": 1001.0, "lambda_errors__checkout": 30.0}),
        "fn_timeout", "3s = 3 x the current timeout"),
    "fs-03": ("lambda_throttled", ctx(
        [], {"lambda_throttles__checkout": 120.0, "lambda_reserved_concurrency__checkout": 0.0,
             "lambda_invocations__checkout": 0.0}),
        "fn_throttled", "the demand needs about 4 "),
    "fs-04": ("lambda_bad_env", ctx(
        [_lam("checkout", "botocore.errorfactory.ResourceNotFoundException: An error occurred (ResourceNotFoundException) "
                          "when calling the PutItem operation: Requested resource not found"),
         ("CONFIG lambda warden-dev-checkout timeout=10s memory=256MB "
         "env=[TABLE_NAME=warden-dev-cartz,REDIS_HOST=warden-dev-redis.abc123.cache.amazonaws.com] version=6")],
        {"lambda_errors__checkout": 25.0}),
        "missing_resource", "TABLE_NAME is `warden-dev-cartz`, the labelled table is `warden-dev-carts`"),
    "fs-05": ("lambda_iam_missing", ctx(
        [_lam("checkout", "botocore.exceptions.ClientError: An error occurred (AccessDeniedException) when calling the "
                          f"PutItem operation: User: arn:aws:sts::{ACCT}:assumed-role/warden-dev-checkout-role/"
                          "warden-dev-checkout is not authorized to perform: dynamodb:PutItem on resource: "
                          f"arn:aws:dynamodb:{REGION}:{ACCT}:table/warden-dev-carts because no identity-based "
                          "policy allows the dynamodb:PutItem action")],
        {"lambda_errors__checkout": 25.0}),
        "access_denied", "for role warden-dev-checkout-role"),
    "fs-06": ("sqs_poison_message", ctx(
        ["QUEUE warden-dev-orders visible=0 in_flight=0 dlq=warden-dev-orders-dlq dlq_visible=14 max_receive=3",
         _lam("order-processor", "Traceback (most recent call last):"),
         "CODE warden-dev-order-processor app.py:18 in handler: json.decoder.JSONDecodeError: Expecting value"],
        {"dlq_visible__orders": 14.0, "lambda_errors__order-processor": 42.0}),
        "dead_letters", "Redriving messages the consumer cannot parse"),
    "fs-07": ("sqs_consumer_disabled", ctx(
        ["ESM warden-dev-order-processor <- warden-dev-orders State=Disabled BatchSize=5 LastProcessingResult=OK"],
        {"lambda_esm_enabled__order-processor": 0.0, "sqs_visible__orders": 120.0}),
        "consumer_off", None),
    "fs-08": ("sns_delivery_blocked", ctx(
        ["POLICY sqs warden-dev-notifications allows_sns_topic=warden-dev-order-events:no"],
        {"sns_notifications_failed": 12.0}),
        "topic_delivery_refused", "Allow topic warden-dev-order-events in warden-dev-notifications's access policy"),
    "fs-09": ("dynamodb_throttling", ctx(
        ["TABLE warden-dev-carts billing=PROVISIONED rcu=1 wcu=1 status=ACTIVE"],
        {"ddb_write_throttle_events": 300.0, "ddb_consumed_wcu": 1.0, "ddb_provisioned_wcu": 1.0}),
        "table_throttled", "about 1 RCU / 3 WCU"),
    "fs-10": ("redis_unreachable", ctx(
        [_lam("reconciler", "redis.exceptions.TimeoutError: Timeout connecting to server "
                            "warden-dev-redis.abc123.cache.amazonaws.com:6379"),
         "REPLGROUP warden-dev-redis node_type=cache.t4g.micro sgs=[sg-0redis]",
         "SG sg-0redis ingress tcp/6379 from=[]",
         "APPSG ecs/warden-dev-orders-api sgs=[sg-0ecs]",
         ("CONFIG lambda warden-dev-reconciler timeout=90s memory=256MB reserved_concurrency=none "
          "env=[RECONCILER_FF_1=by_id] sgs=[sg-0lambda] version=3 alias_live=-")],
        {"lambda_errors__reconciler": 5.0}),
        "cache_unreachable", "sg-0redis has no inbound tcp/6379 rule from sg-0ecs"),
    "fs-11": ("redis_memory_pressure", ctx(
        ["REPLGROUP warden-dev-redis node_type=cache.t4g.micro sgs=[sg-0redis]"],
        {"redis_memory_pct": 97.0, "redis_evictions": 5400.0}),
              "cache_memory", "the next size, cache.t4g.small,"),
    "fs-12": ("aurora_connection_exhaustion", ctx(
        [_lam("order-processor", 'psycopg2.OperationalError: connection to server failed: FATAL:  sorry, too many '
                                 'clients already')],
        {"connections_used_pct": 1.0, "aurora_connections": 90.0}),
        "db_connections_refused", "can be ended without losing work"),
    "fs-13": ("aurora_lock_contention", ctx(
        ["postgres blocked session: pid=5123 waiting 300s on pid(s) 4077: UPDATE orders SET status = $1 WHERE id = $2"],
        {"locks_waiting": 1.0}),
        "db_lock", "terminate the BLOCKER"),
    "fs-14": ("aurora_write_to_reader", ctx(
        [_lam("order-processor", RO_ERR), f"CODE warden-dev-order-processor app.py:30 in save: {RO_ERR}",
         "QUEUE warden-dev-orders visible=3 in_flight=0 dlq=warden-dev-orders-dlq dlq_visible=6 max_receive=3",
         ("CONFIG lambda warden-dev-order-processor timeout=30s memory=256MB "
         "env=[DB_HOST=warden-dev-aurora.cluster-ro-cabc123.ap-south-2.rds.amazonaws.com,DB_NAME=shop] version=3")],
        {"dlq_visible__orders": 6.0, "lambda_errors__order-processor": 18.0}),
        "db_write_on_reader", "warden-dev-aurora.cluster-cabc123.ap-south-2.rds.amazonaws.com"),
    "fs-15": ("aurora_failover_pinned_endpoint", ctx(
        [f"EVENT aurora warden-dev-aurora {TS} Completed failover to DB instance: warden-dev-aurora-2",
         "CLUSTER aurora warden-dev-aurora writer=warden-dev-aurora-2 readers=[warden-dev-aurora-1] status=available",
         _lam("order-processor", RO_ERR)],
        {"lambda_errors__order-processor": 18.0}),
        "db_pinned_after_failover",
        "Failing back would make warden-dev-aurora-1"),
    "fs-16": ("aurora_slow_query", ctx(
        [("postgres long-running query: pid=7311 running 140s user=app app=order-processor client=10.42.0.50: "
         "SELECT id, total FROM orders WHERE customer_ref = $1")],
        {"long_running_queries": 1.0, "aurora_acu_utilization_pct": 95.0}),
        "db_long_query", "WARDEN never changes a schema"),
    "fs-17": ("ecs_bad_image", ctx(
        [_ecs("task 7f stopped: CannotPullContainerError: pull image manifest has been retried 5 time(s): failed to "
              "resolve ref warden-dev-app:does-not-exist: not found")], {}, [ECS_DEPLOY]),
        "task_image_pull", "ran task definition warden-dev-orders-api:11 before"),
    "fs-18": ("ecs_secret_access_denied", ctx(
        [_ecs("task 8a stopped: ResourceInitializationError: unable to pull secrets or registry auth: execution "
              "resource retrieval failed: unable to retrieve secret from asm: AccessDeniedException: User: "
              f"arn:aws:sts::{ACCT}:assumed-role/warden-dev-ecs-exec/8a is not authorized to perform: "
              f"secretsmanager:GetSecretValue on resource: arn:aws:secretsmanager:{REGION}:{ACCT}:secret:"
              "warden-dev-db-app-AbCdEf because no identity-based policy allows the action")]),
        "task_secret_denied", "secretsmanager:GetSecretValue"),
    "fs-19": ("alb_health_check_wrong", ctx(
        [("TARGET warden-dev-orders 10.42.0.12:8080 unhealthy Target.ResponseCodeMismatch: Health checks failed "
         "with these codes: [404]"),
         "TARGETGROUP warden-dev-orders health_path=/healthz port=traffic-port matcher=200"],
        {"alb_unhealthy_hosts": 2.0, "alb_healthy_hosts": 0.0}),
        "lb_health_check", "Restore it from the infrastructure code"),
    "fs-20": ("ecs_oom", ctx(
        [_ecs("task 9c stopped: OutOfMemoryError: Container killed due to memory usage (exit code 137)")],
        {}, [ECS_DEPLOY]),
        "task_oom", "ran task definition warden-dev-orders-api:11 before"),
    "fs-21": ("db_iam_auth_revoked", ctx(
        [_ecs(PAM_ERR), "TASKROLE ecs/warden-dev-orders-api role=warden-dev-orders-api-task"],
        {"alb_target_5xx": 40.0}),
        "db_iam_auth_refused", "warden-dev-orders-api-task, the task role"),
    "fs-22": ("k8s_config_crashloop", ctx(
        [_k8s("catalog-api", "EVENT BackOff Pod/catalog-api-7d9-abcde: Back-off restarting failed container app"),
         _k8s("catalog-api", "catalog-api-7d9-abcde/app (previous) 2026-09-26T09:59:00Z ValueError: invalid literal "
                             "for int() with base 10: 'eight'")],
        {"crashloop_containers__catalog-api": 2.0, "pods_ready__catalog-api": 0.0}),
        "crashloop", "crashed container's own last output"),
    "fs-23": ("k8s_missing_secret_key", ctx(
        [_k8s("catalog-api", "EVENT Failed Pod/catalog-api-7d9-abcde: Error: couldn't find key CATALOG_SIGNING_KEY in "
                             "Secret shop/catalog-secret"),
         _k8s("catalog-api", "STATUS catalog-api-7d9-abcde/app: now waiting: CreateContainerConfigError")],
        {"pods_ready__catalog-api": 0.0}),
        "secret_key_missing", "never reads secret values"),
    "fs-24": ("k8s_readiness_probe_wrong", ctx(
        [_k8s("catalog-api", 'EVENT Unhealthy Pod/catalog-api-7d9-abcde: Readiness probe failed: Get '
                             '"http://10.42.0.33:9999/ready": dial tcp 10.42.0.33:9999: connect: connection refused')],
        {"pods_ready__catalog-api": 0.0}),
        "probe", "If the probe changed in the last deploy, roll back"),
    "fs-25": ("k8s_unschedulable_requests", ctx(
        [_k8s("cart-worker", "EVENT FailedScheduling Pod/cart-worker-5f8-xyz12: 0/1 nodes are available: "
                             "1 Insufficient cpu.")]),
        "unschedulable", "rolling it back returns them to what fitted"),
    "fs-26": ("k8s_image_pull", ctx(
        [_k8s("catalog-api", 'EVENT Failed Pod/catalog-api-9b1-qwert: Failed to pull image "app:nope": not found'),
         _k8s("catalog-api", "EVENT BackOff Pod/catalog-api-9b1-qwert: Back-off pulling image: ImagePullBackOff")],
        {"pods_ready__catalog-api": 1.0}),
        "image_pull", "Roll back to the previous revision"),
    "fs-27": ("eventbridge_rule_disabled", ctx(
        ["RULE warden-dev-reconcile-5m State=DISABLED schedule=rate(5 minutes)"],
        {"rule_enabled__reconcile-5m": 0.0, "rule_invocations__reconcile-5m": 0.0}),
        "schedule_off", None),
}

# Patterns a fault may legitimately raise beside its own: the same evidence read another true way.
EXTRA_OK = {
    "fs-01": {"deploy"}, "fs-12": {"db_pool"}, "fs-17": {"deploy"}, "fs-20": {"deploy"},
    "fs-22": {"deploy"}, "fs-24": set(), "fs-26": {"deploy"},
}

def _advice(pat) -> str:
    return " ".join([pat.likely_cause, *pat.oncall, *pat.developers, *pat.platform, *pat.dba, *pat.prevention])


@pytest.fixture(autouse=True)
def _region(monkeypatch):
    monkeypatch.setenv("AWS_REGION", REGION)


# ---------------------------------------------------------------- tests


def test_a_healthy_stack_detects_nothing():
    assert detect(alert(), ctx()) == []


@pytest.mark.parametrize("fid", sorted(FAULTS))
def test_each_fault_detects_its_own_class_with_its_advice(fid):
    _, context, key, fragment = FAULTS[fid]
    found = {p.key: p for p in detect(alert(), context)}
    assert key in found, f"{fid}: {sorted(found)}"
    pat = found[key]
    assert pat.seen
    assert pat.likely_cause
    if fragment:
        assert fragment in _advice(pat), (fid, _advice(pat))


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
    assert "app.py:42 in handler (warden-dev-checkout): KeyError: 'sku'" in pat.developers[0]
    assert "`sku = body['sku']`" in pat.developers[0]


def test_a_traceback_without_a_deploy_is_not_called_a_regression():
    assert "code_error_after_deploy" not in {p.key for p in detect(alert(), FAULTS["fs-06"][1])}


def test_the_timeout_is_computed_from_observed_duration_when_it_was_not_capped():
    c = ctx([_lam("checkout", "Task timed out after 3.00 seconds"),
             "CONFIG lambda warden-dev-checkout timeout=3s memory=256MB env=[TABLE_NAME] version=6"],
            {"lambda_timeout_s__checkout": 3.0, "lambda_duration_max_ms__checkout": 2100.0})
    pat = next(p for p in detect(alert(), c) if p.key == "fn_timeout")
    assert "5s = 2 x the longest observed duration (2100 ms)" in pat.oncall[0]


def test_env_without_values_cannot_say_which_value_is_wrong():
    c = ctx([_lam("checkout", "ResourceNotFoundException: Requested resource not found")])
    pat = next(p for p in detect(alert(), c) if p.key == "missing_resource")
    assert "without their values; WARDEN cannot tell which value is wrong" in pat.oncall[0]


def test_a_bad_env_that_arrived_with_a_version_names_the_version_it_served_before():
    c = ctx([_lam("checkout", "ResourceNotFoundException: Requested resource not found"),
             "CONFIG lambda warden-dev-checkout timeout=10s memory=256MB env=[TABLE_NAME] version=7 alias_live=7"],
            deploys=[{"kind": "lambda", "service": "warden-dev-checkout", "at": TS, "version": "7", "previous": "6"}])
    pat = next(p for p in detect(alert(), c) if p.key == "missing_resource")
    assert pat.oncall[0].startswith("Alias `live` of warden-dev-checkout moved to version 7")
    assert "it served version 6 before" in pat.oncall[0]


def test_throttling_without_a_reservation_is_the_account_limit():
    pat = next(p for p in detect(alert(), ctx([], {"lambda_throttles__checkout": 9.0})) if p.key == "fn_throttled")
    assert "regional concurrency limit" in pat.oncall[0]


def test_a_reader_endpoint_without_env_values_names_no_endpoint():
    c = ctx([_lam("order-processor", RO_ERR)])
    pat = next(p for p in detect(alert(), c) if p.key == "db_write_on_reader")
    assert "writer endpoint `" not in _advice(pat), pat.oncall


def test_the_sns_advice_keeps_the_queues_other_statements():
    """Audit A6 (2026-10-16): the printed `set-queue-attributes` replaced the queue's whole policy, so every other
    statement was lost. The advice names the queue and the topic and says to add, not replace."""
    pat = next(p for p in detect(alert(), FAULTS["fs-08"][1]) if p.key == "topic_delivery_refused")
    assert "warden-dev-order-events" in pat.oncall[0]
    assert "warden-dev-notifications" in pat.oncall[0]
    assert "beside the statements it already has" in pat.oncall[0]


def test_a_denied_secret_read_names_only_what_to_compare():
    """Phase 0 (2026-09-27): WARDEN never writes IAM from a log line - the role, action and resource all
    come from text that whoever can write a log line controls. It names them, as advice."""
    pat = next(p for p in detect(alert(), FAULTS["fs-18"][1]) if p.key == "task_secret_denied")
    advice = " ".join(pat.oncall)
    assert "secretsmanager:GetSecretValue" in advice
    assert "warden-dev-ecs-exec" in advice
    assert "never writes IAM" in advice
    assert "access_denied" not in {p.key for p in detect(alert(), FAULTS["fs-18"][1])}


def test_an_attacker_shaped_denial_line_yields_no_grant():
    """The plant: a log line naming the ADMIN role and `iam:*` used to become `iam put-role-policy`."""
    line = _lam("checkout", f"User: arn:aws:sts::{ACCT}:assumed-role/OrganizationAccountAccessRole/x is not "
                            "authorized to perform: iam:* on resource: arn:aws:iam::*:*")
    for p in detect(alert(), ctx([line])):
        assert "put-role-policy" not in _advice(p), (p.key, _advice(p))
        if p.key == "access_denied":
            assert "never writes IAM from a log line" in p.oncall[0]


def test_redis_memory_names_the_next_node_size_only_when_the_node_type_is_read():
    c = ctx(["REPLGROUP warden-dev-redis node_type=cache.t4g.micro status=available"],
            {"redis_memory_pct": 97.0, "redis_evictions": 5400.0})
    pat = next(p for p in detect(alert(), c) if p.key == "cache_memory")
    assert pat.oncall[0].startswith("warden-dev-redis runs cache.t4g.micro; the next size, cache.t4g.small,")


def test_a_function_without_the_alias_names_no_alias_move():
    """The stack backend writes `alias_live=-` when the alias does not exist."""
    c = ctx([("CONFIG lambda warden-dev-order-processor timeout=30s memory=256MB reserved_concurrency=none "
             "env=[DB_HOST] version=4 alias_live=-"),
             "CODE warden-dev-order-processor app.py:9 in handler: KeyError: 'id'"],
            deploys=[{"kind": "lambda", "service": "warden-dev-order-processor", "at": TS, "version": "4",
                      "previous": "3"}])
    pat = next(p for p in detect(alert(), c) if p.key == "code_error_after_deploy")
    assert "served version" not in _advice(pat), pat.oncall


def test_the_crash_loop_advice_holds_no_command_and_no_label_list():
    """A8 (2026-10-16): the advice said `kubectl -n shop logs deploy/catalog-api --previous` - a read WARDEN had
    already made (the crashed output is in the report). It says what to read, in words."""
    pat = next(p for p in detect(alert(), FAULTS["fs-22"][1]) if p.key == "crashloop")
    assert "crashed container's own last output" in pat.oncall[0]
    assert "kubectl" not in _advice(pat)
    assert "catalog-api,cart-worker" not in _advice(pat)


def test_cache_ingress_names_only_the_missing_rules():
    """Only application SGs with no rule on the cache SG are named; an allowed SG is never named."""
    base = [_lam("reconciler", "redis.exceptions.TimeoutError: Timeout connecting to server x:6379"),
            "REPLGROUP warden-dev-redis node_type=cache.t4g.micro sgs=[sg-0redis]",
            "APPSG ecs/warden-dev-orders-api sgs=[sg-0ecs]", "APPSG eks/warden-dev-eks sgs=[sg-0eks]"]
    pats = {p.key: p for p in detect(alert(), ctx(base + ["SG sg-0redis ingress tcp/6379 from=[sg-0ecs]"]))}
    said = pats["cache_unreachable"].oncall[0]
    assert "no inbound tcp/6379 rule from sg-0eks -" in said, said
    assert "sg-0ecs" not in said, said
    full = {p.key: p for p in detect(alert(), ctx(base + ["SG sg-0redis ingress tcp/6379 from=[sg-0ecs,sg-0eks]"]))}
    assert full["cache_unreachable"].oncall[0].startswith("Every application security group already has")
    bare = {p.key: p for p in detect(alert(), ctx(base[:1]))}
    assert "security group" not in " ".join(bare["cache_unreachable"].oncall)


def test_a_refused_iam_login_names_only_the_role_and_user_to_compare():
    pat = next(p for p in detect(alert(), FAULTS["fs-21"][1]) if p.key == "db_iam_auth_refused")
    advice = " ".join(pat.oncall)
    assert "warden-dev-orders-api-task" in advice
    assert "rds-db:connect" in advice
    assert "user app" in advice
    assert "stale_credentials" not in {p.key for p in detect(alert(), FAULTS["fs-21"][1])}


def test_an_iam_login_refusal_without_the_role_in_evidence_says_which_line_is_missing():
    pat = next(p for p in detect(alert(), ctx([_ecs(PAM_ERR)])) if p.key == "db_iam_auth_refused")
    assert "TASKROLE ecs/<service> role=<name>" in pat.oncall[0]
    lam = next(p for p in detect(alert(), ctx([_lam("order-processor", PAM_ERR)])) if p.key == "db_iam_auth_refused")
    assert lam.oncall[0].startswith("The evidence does not carry")
    assert "code_error_after_deploy" not in {p.key for p in detect(alert(), ctx(
        [f"CODE warden-dev-order-processor app.py:40 in _connect: {PAM_ERR}"],
        deploys=[{"kind": "lambda", "service": "warden-dev-order-processor", "at": TS, "version": "4",
                  "previous": "3"}]))}, "a refused login is not a code regression"


def test_a_rotated_password_is_still_read_as_stale_credentials():
    """The pre-2026-09-26 fs-21 shape: no longer injected in Wave 4, still a pattern WARDEN knows."""
    c = ctx([_ecs('psycopg2.OperationalError: connection to server failed: FATAL:  password authentication failed '
                  'for user "app"'), "SECRET warden-dev-db-app changed 2026-09-26T09:50:00Z (metadata only)"],
            {"secret_changed_age_s": 600.0},
            [{"kind": "secret", "service": "warden-dev-db-app", "at": "2026-09-26T09:50:00Z", "version": "v2",
              "previous": "v1"}])
    pat = next(p for p in detect(alert(), c) if p.key == "stale_credentials")
    assert pat.oncall[0] == "New tasks of warden-dev-orders-api read the secret at start, so they get the current password."


# ⛔ Audit A-C-14: a value in the advice is never taken from application output. Whoever can make the app log a
# line (or send it a request) would choose the node size, or the health-check path, it names.
def test_node_type_comes_only_from_config():
    forged = _ecs("cache stats node_type=cache.r6g.2xlarge hits=1")
    no_config = next(p for p in detect(alert(), ctx([forged], {"redis_memory_pct": 97.0, "redis_evictions": 9.0}))
                     if p.key == "cache_memory")
    assert "next size" not in _advice(no_config), no_config.oncall
    assert "r6g" not in _advice(no_config), no_config.oncall
    both = ctx([forged, "REPLGROUP warden-dev-redis node_type=cache.t4g.micro sgs=[sg-0redis]"],
               {"redis_memory_pct": 97.0, "redis_evictions": 9.0})
    pat = next(p for p in detect(alert(), both) if p.key == "cache_memory")
    assert "the next size, cache.t4g.small," in pat.oncall[0], pat.oncall
    assert "r6g" not in _advice(pat), pat.oncall


def test_no_path_is_taken_from_application_logs():
    """The working health path used to come from an access-log line - which any client writes by
    requesting a path. The text says where the path must come from."""
    _, context, _, _ = FAULTS["fs-19"]
    planted = ctx([*context.logs, _ecs('10.0.0.9 - "GET /healthz/../admin?health HTTP/1.1" 200 2')],
                  dict(context.metrics))
    for c in (context, planted):
        pat = next(p for p in detect(alert(), c) if p.key == "lb_health_check")
        assert any(t.startswith("The target group checks") and "infrastructure code" in t for t in pat.oncall), pat.oncall
        assert "admin" not in _advice(pat)


def test_a_value_merely_containing_the_rds_suffix_is_not_an_rds_host():
    """CodeQL (2026-10-02): `".rds.amazonaws.com" in val` took `<reader>.rds.amazonaws.com.evil.example` for an RDS
    endpoint, and the advice would have pointed the function's database at another domain."""
    from warden.playbook import _RDS_HOST

    good = "warden-dev-aurora.cluster-ro-abc123.ap-south-2.rds.amazonaws.com"
    assert _RDS_HOST.fullmatch(good)
    for bad in (good + ".evil.example", good + ":5432", "evil.example/" + good, "x " + good):
        assert not _RDS_HOST.fullmatch(bad), bad


def test_a_deploy_beside_a_detected_pattern_is_listed_without_an_error_line():
    """A code deploy is the cheapest hypothesis whenever any pattern was found, error lines or not (a plant check
    found no test for it, S19)."""
    keys = [p.key for p in detect(alert(), ctx(metrics={"replica_lag_seconds": 45.0}, deploys=[ECS_DEPLOY]))]
    assert keys == ["replica_lag", "deploy"]
