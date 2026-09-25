# Wave 4 - interface contract between the stack backend, the report and the harness

Companion to `docs/WAVE4-FULLSTACK.md`. Four parts are built separately against this file; if code
and this file disagree, fix one of them in the same commit.

## A. Alert labels (harness -> WARDEN)

`app` (application name), and any of: `lambda` (comma-separated function names), `sqs` (queue names,
comma-separated), `dynamodb_table`, `elasticache` (replication group id), `aurora_cluster`,
`alb_target_group` (name), `apigw` (API name), `ecs_cluster`, `ecs_service`, `eks_cluster` (EKS cluster name), `namespace`,
`deployment` (comma-separated), `secret` (name), `sns_topic` (name), `eventbridge_rule`
(comma-separated). A DLQ is found from the queue's RedrivePolicy, never named in a label.

Environment given to WARDEN by the harness (never on argv): assumed-role AWS credentials of
`warden-pg-fs-reader`, `AWS_REGION=ap-south-2`, `KUBECONFIG` (token-only, SA `warden` in `shop`),
`WARDEN_STACK_DB_WRITER_DSN` and `WARDEN_STACK_DB_READER_DSN` (user `warden_ro`, sslmode=require).

## B. Metrics the stack backend emits (floats)

Absent when not measured - never zero-filled (an absent metric is not a zero, see P11's lag rule).

- lambda (per function; when several functions are labelled, keys are suffixed `__<short>` where
  `<short>` is the name without the `warden-pg-fs-` prefix, e.g. `lambda_errors__checkout`):
  `lambda_errors`, `lambda_throttles`, `lambda_invocations`, `lambda_duration_max_ms`,
  `lambda_timeout_s`, `lambda_memory_mb`, `lambda_reserved_concurrency` (only when set),
  `lambda_concurrent_executions`, `lambda_esm_enabled` (1/0, only for functions with an ESM)
- sqs (per queue, same suffix rule): `sqs_visible`, `sqs_in_flight`, `sqs_oldest_age_s`,
  `sqs_visibility_timeout_s`, `dlq_visible`, `sqs_max_receive_count`
- dynamodb: `ddb_provisioned_rcu`, `ddb_provisioned_wcu`, `ddb_consumed_rcu`, `ddb_consumed_wcu`,
  `ddb_read_throttle_events`, `ddb_write_throttle_events`, `ddb_throttled_requests`
- elasticache: `redis_memory_pct`, `redis_evictions`, `redis_curr_connections`,
  `redis_engine_cpu_pct`, `redis_replication_lag_s`, `redis_nodes_available`, `redis_nodes_total`
- aurora (AWS API + CloudWatch): `aurora_connections`, `aurora_replica_lag_ms`,
  `aurora_acu_utilization_pct`, `aurora_cpu_pct`, `aurora_deadlocks`, `aurora_members_available`;
  plus the existing PostgreSQL backend on the WRITER with its own names unchanged
  (`connections_active`, `max_connections`, `connections_used_pct`, `idle_in_transaction`,
  `long_running_queries`, `locks_waiting`, ...) and on the READER prefixed `reader_`
- alb: `alb_target_5xx`, `alb_elb_5xx`, `alb_unhealthy_hosts`, `alb_healthy_hosts`,
  `alb_target_response_time_s`
- apigw: `apigw_5xx`, `apigw_4xx`, `apigw_latency_ms`
- ecs: exactly what `AwsBackend.metrics` emits today
- k8s: exactly what `KubernetesBackend.metrics` emits today (per Deployment; with several, suffix
  `__<deployment>`)
- secrets: `secret_changed_age_s` (seconds between the secret's LastChangedDate and the alert)
- sns: `sns_notifications_failed`, `sns_notifications_delivered`
- eventbridge: `rule_enabled` (1/0; suffix rule for several), `rule_invocations`

## C. Log lines the stack backend emits (strings; redacted downstream like all evidence)

Every line starts with a tag so the report and the playbook can route it:

```
LOG lambda/warden-pg-fs-checkout 2026-09-26T10:00:01Z <original message>
LOG ecs/warden-pg-fs-orders-api ...            (from AwsBackend, re-tagged)
LOG k8s/shop/catalog-api ...                    (KubernetesBackend lines, re-tagged; its EVENT / STATUS / ROLLOUT lines keep their own prefix after the tag)
CONFIG lambda warden-pg-fs-checkout timeout=1s memory=256MB reserved_concurrency=0 env=[TABLE_NAME=warden-pg-fs-carts,DB_PASSWORD] version=7 alias_live=7
                                                (env: NAME=value when the name is not secret-looking and the value is plain; secret-looking names bare;
                                                 in-VPC functions also carry sgs=[sg-..])
ESM warden-pg-fs-order-processor <- warden-pg-fs-orders State=Disabled BatchSize=5 LastProcessingResult=OK
CODE warden-pg-fs-checkout app.py:42 in handler: KeyError: 'sku'
SOURCE warden-pg-fs-checkout app.py:40 | <source line>
SOURCE warden-pg-fs-checkout app.py:42 >| <the failing line>
QUEUE warden-pg-fs-orders visible=120 in_flight=5 dlq=warden-pg-fs-orders-dlq dlq_visible=14 max_receive=3
POLICY sqs warden-pg-fs-notifications allows_sns_topic=warden-pg-fs-order-events:no
TABLE warden-pg-fs-carts billing=PROVISIONED rcu=1 wcu=1 status=ACTIVE
EVENT elasticache warden-pg-fs-redis 2026-...Z <message>
REPLGROUP warden-pg-fs-redis node_type=cache.t4g.micro sgs=[sg-..]
SG sg-.. ingress tcp/6379 from=[sg-..]                       (the cache security group's sources)
APPSG ecs/warden-pg-fs-orders-api sgs=[sg-..]
APPSG eks/warden-pg-fs-eks sgs=[sg-..]
EVENT aurora warden-pg-fs-aurora 2026-...Z <message>        (DescribeEvents: failover, reboot, ...)
CLUSTER aurora warden-pg-fs-aurora writer=warden-pg-fs-aurora-1 readers=[warden-pg-fs-aurora-2] status=available
TARGET warden-pg-fs-orders 10.42.0.12:8080 unhealthy Target.ResponseCodeMismatch: Health checks failed with these codes: [404]
TARGETGROUP warden-pg-fs-orders health_path=/healthz port=traffic-port matcher=200
SECRET warden-pg-fs-db-app changed 2026-...Z (metadata only)
RULE warden-pg-fs-reconcile-5m State=DISABLED schedule=rate(5 minutes)
TOOL-PARTIAL <reader>: <reason>                                (a failed reader; also a tool_errors entry)
```

## D. Deploy records (`deploys()`), dicts

`{"kind": "lambda"|"ecs"|"k8s"|"secret", "service": <name>, "at": ISO-8601 Z, "version"|"image": ..., "previous": ...}`.
ECS records carry `version`/`previous` as `family:revision`, plus `image`/`previous_image`.
A Lambda alias `live` moving to a new version inside the window is a deploy; a secret changing is
reported with `kind: "secret"` (not a code deploy - P5 must not treat it as something to roll back).

## E. Fix commands in the report (report -> harness)

`build_report(...).data["fix_commands"]`: ordered list, each
`{"kind": "shell" | "sql", "command": <exact text>, "source": "runbook" | "pattern:<key>", "target": "writer" (sql only)}`.
Runbook fix first (only when an action was proposed and has a fix), then each detected pattern's
`fix` commands. No placeholders, ever: a command that cannot be aimed at a real name is not emitted.
The markdown report shows the same commands.

`Pattern` (src/warden/playbook.py) gains `fix: list[str]` - the commands that remove this pattern's
cause, separate from `oncall` advice text.

What the harness runs (`scenarios/ops_fullstack.py` `check_command` / `execute_fix`), so the report
knows what it may print:

- Shell commands are read as ONE bash line: `'...'` and `"..."` quoting (a JSON document inside
  single quotes survives intact), and a trailing `# comment` is dropped as bash would drop it.
  Shell arithmetic such as `$((CUR+1))` is a placeholder and is refused.
- A nested lookup `"$(aws <svc> get-*|list-*|describe-* ... --output text --region ap-south-2)"`
  may stand where the report cannot print a masked value (a UUID, an ARN, a queue URL). It must be
  one aws read on a `warden-pg-fs-*` resource (every name flag), with no `$`, backtick, `;`, `&`,
  `<`, `>` inside. The harness runs it (no shell), requires one plain token back
  (`[A-Za-z0-9:/._-]{1,256}`, not `None`), substitutes it, and checks the whole command again.
- SQL: one statement, optionally `;` and one trailing `-- comment`. Kills are
  `SELECT [pid,] pg_terminate_backend|pg_cancel_backend(pid) FROM pg_stat_activity [alias] WHERE ...`;
  the only subquery a WHERE may hold is `(SELECT unnest(pg_blocking_pids(w.pid)) FROM pg_stat_activity w)`.
- `aws ec2 authorize-security-group-ingress`: every `sg-...` named must belong to the stack (the
  cache SG or an application SG from `stack.json`). `aws elasticache modify-replication-group`:
  only `--replication-group-id warden-pg-fs-*`, `--cache-node-type`, `--apply-immediately`, `--region`.
