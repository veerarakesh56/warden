# Wave 4 - the full stack (design, registered before any run)

Status: **design, not yet run.** Written 2026-09-25, before any Wave 4 resource exists, so the fault
list, the pass criteria and the scoring cannot be tuned to what a run produced. Anything changed
after the first run is dated in this file.

## 1. What this wave asks

Waves 1-3 put one platform at a time in front of WARDEN. A company runs them together: an API on
Lambda writes to DynamoDB and a queue, a consumer writes to Aurora, a container API behind a load
balancer reads a cache, a cluster runs workers. Wave 4 builds that stack on AWS, breaks it in ~26
different ways - code, configuration, capacity, dependency/IAM/network, database - and measures four
things per fault:

| score | question |
|---|---|
| **Evidence** | did WARDEN read the signal that identifies this fault? (pre-registered assertion per fault) |
| **Diagnosis** | is the hypothesis/action in the fault's correct set? (rubric, `scenarios/scoring.yaml`) |
| **Gate** | is the verdict right for what was proposed? (2x2, as before) |
| **Fix** ⭐ new | when the fix WARDEN printed is applied **exactly as printed**, is the fault gone? |

⭐ **Who applies the fix.** WARDEN stays read-only - that is the property the benchmark exists to
protect. The harness plays the approving on-call engineer: it runs the fix commands from WARDEN's own
report, verbatim, through an allow-list (section 6), then checks recovery with the fault's
pre-registered verifier. It applies nothing for a `rejected` verdict (the gate said no), and records
`no_fix_printed` when the report prints no executable fix. After measuring, the harness restores the
baseline with its OWN revert, so a fix that did not work never leaves the next fault a broken stack.

One run per fault (the owner's choice, 2026-09-25): breadth over repeat-stability, which Waves 1-3
already measure.

## 1a. Three separate pipelines, and who presses what (owner, 2026-09-25)

| pipeline | owns | triggers | product |
|---|---|---|---|
| **infra** (`.github/workflows/infra.yml`) | `terraform/fullstack/` only | validate on a change to its files; apply/destroy only by manual dispatch | `stack.json` (`terraform output -json`) |
| **apps** (`.github/workflows/apps.yml`, `scripts/deploy_fullstack_apps.py`) | the code that runs ON the stack: Lambdas, the container image, `k8s/fullstack/`, the DB bootstrap SQL | test/build on a change to its files; deploy only by manual dispatch | running workloads |
| **tool** (`.github/workflows/ci.yml`) | WARDEN itself | any change outside the infra/apps directories | a tested WARDEN |

Each is usable alone: someone can take only the infra, only the apps, or only WARDEN. Terraform
never deploys application code (it creates functions with a placeholder and ignores code changes);
the apps pipeline and the harness read `stack.json` and never call terraform.

Operating sequence for this wave: infra up -> apps deployed -> **soak** until every component is
healthy and at least 30 minutes have passed -> for each fault, step by step and each step started by
the operator: `inject`, `diagnose` (WARDEN, with Claude through the `claude` CLI on the owner's Max
plan), `fix`, `verify`, `revert` -> after the last fault, **watch** for at least 30 minutes before
anything is destroyed, because some failures only appear after time -> destroy, then verify nothing
is left billing. WARDEN never starts itself.

## 2. The stack

Everything is named `warden-pg-fs-*` and tagged `Project=warden-fullstack`. The prefix is the one the
operator's permissions boundary already scopes IAM, S3 and pass-role to; the tag is what every
injector's guard checks before it touches anything.

Region `ap-south-2`. One VPC `10.42.0.0/16`: public subnets `10.42.0.0/24`, `10.42.1.0/24` (ALB, ECS
tasks with public IPs, EKS nodes, Aurora instances), private subnets `10.42.10.0/24`,
`10.42.11.0/24` (ElastiCache, in-VPC Lambdas). No NAT gateway: gateway endpoints for S3 and DynamoDB
(free), interface endpoints for Secrets Manager and SQS in one private subnet.

| component | name | shape |
|---|---|---|
| Container image | ECR `warden-pg-fs-app` | one Python image; `APP_ROLE` selects orders-api / catalog-api / cart-worker |
| Aurora PostgreSQL | cluster `warden-pg-fs-aurora`, instances `-aurora-1` (writer), `-aurora-2` (reader) | Serverless v2, 0.5-2 ACU, PostgreSQL 16, publicly accessible, SG: operator IP + app SGs |
| ElastiCache Redis | replication group `warden-pg-fs-redis` | primary + 1 replica, `cache.t4g.micro`, private subnets |
| DynamoDB | `warden-pg-fs-carts` | PROVISIONED 5 RCU / 5 WCU, no autoscaling (so a capacity fault is a capacity fault) |
| SQS | `warden-pg-fs-orders` (+ `-orders-dlq`, maxReceiveCount 3), `warden-pg-fs-notifications` (+ `-notifications-dlq`) | standard queues |
| SNS | `warden-pg-fs-order-events` | subscribed by the notifications queue |
| Lambda | `-checkout` (API, alias `live`), `-order-processor` (SQS orders, in VPC, Aurora writer), `-notifier` (SQS notifications), `-reconciler` (EventBridge 5 min, in VPC, Aurora reader + Redis), `-traffic` (EventBridge 1 min, load generator), `-ops` (in VPC, harness-only admin commands for Redis) | Python 3.12 |
| API Gateway | HTTP API `warden-pg-fs-api`, `POST /checkout`, `GET /health` -> checkout:live | |
| ALB | `warden-pg-fs-alb` -> target group `warden-pg-fs-orders` (ip, `/health`) | |
| ECS | cluster `warden-pg-fs-ecs`, service `warden-pg-fs-orders-api`, 2 Fargate tasks | DB password injected from Secrets Manager |
| EKS | cluster `warden-pg-fs-eks`, managed node group, **1 x t3.medium ON_DEMAND** (min 1, max 1) | add-ons: vpc-cni, coredns, kube-proxy, metrics-server |
| Kubernetes | namespace `shop`: Deployments `catalog-api` (2) and `cart-worker` (1); Services; ConfigMap `catalog-config`; Secret `catalog-secret`; HPA `catalog-api` (2-4); PodDisruptionBudget; ServiceAccount `warden` (the read-only identity) | |
| Secrets Manager | `warden-pg-fs-db-app`, `-db-catalog`, `-db-warden-ro` | Aurora credentials: `app` (orders-api, Lambdas), `catalog` (catalog-api, read-only - its own user so fs-21 has one victim), `warden_ro` (WARDEN, `pg_monitor` only). Changed 2026-09-25, before any run. |
| EventBridge | rules `warden-pg-fs-reconcile-5m`, `warden-pg-fs-traffic-1m` | |
| CloudWatch | one alarm per signal the faults below trip; the **alert source** | |
| Budget | raised to USD 50 for the account (owner, 2026-09-25) | |

Why t3.medium and not t3.small: a t3.small node takes 11 pods, and the system pods plus `shop` plus
headroom for a rollout does not fit. ON_DEMAND, not Spot: a Spot interruption mid-fault would be an
unplanned second fault.

## 3. WARDEN's identities for this wave (read-only, all of them)

- **AWS:** role `warden-pg-fs-reader`, assumed per run. Its policy is EXACTLY the read calls the
  stack backend makes, asserted in both directions by a test (as Wave 1's four were). No write, no
  `secretsmanager:GetSecretValue`, no `s3:GetObject` except the Lambda code download (section 5).
- **Kubernetes:** ServiceAccount `warden` in `shop`, bound to the six-read ClusterRole
  (`k8s/rbac.yaml`) by a RoleBinding. Token-only kubeconfig, as Wave 2.
- **Aurora:** database user `warden_ro` with `pg_monitor` only - fixing Wave 3's gap, where WARDEN
  read as the master user.
- **Redis:** none. ElastiCache is VPC-only; WARDEN reads it through CloudWatch and the ElastiCache
  API. Stated as a limit, not hidden.

## 4. How an alert reaches WARDEN

A CloudWatch alarm goes to ALARM. The harness turns it into WARDEN's Alertmanager-shaped alert: the
alarm name, its description (which names the symptom, **never the cause**), severity, and labels for
the resources that belong to that application - the service map a real team keeps in tags:
`lambda`, `sqs`, `dlq`, `dynamodb_table`, `elasticache`, `aurora_cluster`, `alb_target_group`,
`apigw`, `ecs_cluster`, `ecs_service`, `namespace`, `deployment`, `secret`, `sns_topic`,
`eventbridge_rule`. Every alert for an application carries the same map, whichever component
broke, so the labels never point at the fault.

## 5. The stack backend (`WARDEN_BACKEND=stack`)

One backend that reads every resource the labels name, each through its own reader, each isolated:
a failed reader is a `tool_errors` entry (P8), never silence.

| reader | reads (API) | metrics it emits (prefix) | logs/deploys |
|---|---|---|---|
| lambda | GetFunctionConfiguration, GetFunctionConcurrency, GetAlias, ListVersionsByFunction, ListEventSourceMappings, GetFunction (code, section 5a); CloudWatch Errors/Throttles/Invocations/Duration/ConcurrentExecutions | `lambda_*` | `/aws/lambda/<fn>` log lines in the window; a new published version / alias move = a deploy |
| sqs | GetQueueUrl, GetQueueAttributes (queue and its DLQ); CloudWatch ApproximateAgeOfOldestMessage | `sqs_*`, `dlq_*` | - |
| dynamodb | DescribeTable; CloudWatch ThrottledRequests, Read/WriteThrottleEvents, Consumed*CapacityUnits | `ddb_*` | - |
| elasticache | DescribeReplicationGroups, DescribeCacheClusters, DescribeEvents; CloudWatch DatabaseMemoryUsagePercentage, Evictions, CurrConnections, EngineCPUUtilization, ReplicationLag | `redis_*` | events as log lines |
| aurora | DescribeDBClusters, DescribeDBInstances, DescribeEvents (failover, reboot); CloudWatch DatabaseConnections, AuroraReplicaLag, ACUUtilization, CPUUtilization, Deadlocks; **plus the existing PostgreSQL backend on the writer and reader endpoints** as `warden_ro` | `aurora_*` + the postgres metrics | events and session lines |
| alb | DescribeTargetHealth; CloudWatch HTTPCode_Target_5XX_Count, HTTPCode_ELB_5XX_Count, UnHealthyHostCount, TargetResponseTime | `alb_*` | unhealthy-target reasons as lines |
| apigw | GetApi, GetIntegrations; CloudWatch 5xx, 4xx, Latency | `apigw_*` | - |
| ecs | the existing `AwsBackend` (services, deployments, failed tasks, task definitions, logs) | as today | as today |
| k8s | the existing `KubernetesBackend` (six reads) per Deployment in the labels | as today | as today |
| secrets | DescribeSecret (**metadata only**: LastChangedDate, LastRotatedDate, never the value) | `secret_*` | a change inside the window is reported like a deploy |
| sns | GetTopicAttributes, ListSubscriptionsByTopic; CloudWatch NumberOfNotificationsFailed | `sns_*` | - |
| eventbridge | DescribeRule (state, schedule) | `rule_enabled` | - |

**5a. Code-level evidence.** When a Lambda log carries a Python traceback, the reader parses the
innermost frame of the deployed code (`/var/task/<file>`, line, function, exception) and reads that
file from the function's deployment package (`lambda:GetFunction` returns a pre-signed URL for the
zip; downloading it is a read). The report shows the frame and the source lines around it. The
source goes through redaction like every other piece of evidence before it reaches the model. For
container workloads the traceback is shown; their source is inside an image WARDEN does not pull,
and the report says so.

## 6. Applying WARDEN's fix (harness side)

The harness takes the executable commands from the report's JSON (`runbook.fix`, then the detected
patterns' fix commands), and runs them only if every command passes the allow-list:

- `aws <service> <verb> ...` with `--region ap-south-2`, every resource named `warden-pg-fs-*`, and
  the verb in a per-service list of mutations a runbook may legitimately contain (e.g. `lambda
  update-alias`, `lambda update-function-configuration`, `lambda put-function-concurrency`,
  `dynamodb update-table`, `ecs update-service`, `elbv2 modify-target-group`, `events enable-rule`,
  `sqs set-queue-attributes`, `lambda update-event-source-mapping`, `rds failover-db-cluster`). Never
  `delete-*`, never IAM except `iam put-role-policy` on a `warden-pg-fs-*` role.
- `kubectl -n shop ...` with verbs `rollout undo|restart`, `set`, `patch`, `scale`, `apply -f -` of a
  manifest the report printed.
- SQL against the Aurora writer: `SELECT pg_terminate_backend|pg_cancel_backend ...`, `CREATE INDEX
  CONCURRENTLY`, `ALTER DATABASE ... SET` - through psycopg, as the master user.

A command outside the list is not run; the fault is recorded `fix_not_allowed` with the command, so
a report that prints something dangerous is visible rather than silently skipped.

Recovery is checked by the fault's own verifier (section 7) for up to its `recover_within`, then
the harness restores baseline with its own revert and runs the baseline gate before the next fault.

## 7. The faults

Fault class names are the rubric keys. "Signal" is the evidence assertion; "Fixed when" is the
verifier. Every injector refuses to act unless the target carries `Project=warden-fullstack`.

| id | class | injection | signal WARDEN must read | fixed when |
|---|---|---|---|---|
| fs-00 | healthy_control | nothing | - | nothing is broken |
| fs-01 | lambda_code_regression | publish checkout v(N+1) with a KeyError on a real payload field, move alias `live` | traceback frame `app.py:<line>` + a deploy (alias moved) | API 5xx rate back to 0; alias on a working version |
| fs-02 | lambda_timeout_too_low | checkout timeout 1 s; the DynamoDB call path takes ~2 s (injected latency flag) | `Task timed out after 1.00 seconds` + `lambda_timeout_s` | no timeouts for 3 min |
| fs-03 | lambda_throttled | reserved concurrency 0 on checkout | `lambda_throttles` > 0, `lambda_reserved_concurrency` = 0 | invocations succeed |
| fs-04 | lambda_bad_env | checkout `TABLE_NAME` points at a table that does not exist | `ResourceNotFoundException` + env var NAME in config | writes succeed |
| fs-05 | lambda_iam_missing | remove `dynamodb:PutItem` from checkout's role | `AccessDeniedException ... dynamodb:PutItem` | writes succeed |
| fs-06 | sqs_poison_message | messages the processor cannot parse; DLQ fills | `dlq_visible` > 0 + the processor's traceback | DLQ drained/redriven and processor healthy |
| fs-07 | sqs_consumer_disabled | disable the orders event source mapping | `sqs_visible` growing, ESM `State=Disabled` | backlog drains |
| fs-08 | sns_delivery_blocked | notifications queue policy no longer allows the topic | `sns_notifications_failed` > 0 | deliveries succeed |
| fs-09 | dynamodb_throttling | carts to 1 RCU / 1 WCU while traffic writes | `ddb_write_throttle_events` > 0, provisioned WCU = 1 | no throttles for 3 min |
| fs-10 | redis_unreachable | remove the app SGs from the Redis SG ingress | connection timeouts to the Redis endpoint in app logs | cache calls succeed |
| fs-11 | redis_memory_pressure | fill the cache with filler keys (via `-ops`) | `redis_memory_pct` high, `redis_evictions` rising | memory back under threshold, no evictions |
| fs-12 | aurora_connection_exhaustion | open idle sessions until `max_connections` | too-many-clients errors + pool usage | new connections succeed |
| fs-13 | aurora_lock_contention | a transaction holds a row lock the processor needs | blocked sessions + the blocker's pid | no waiters |
| fs-14 | aurora_write_to_reader | processor `DB_HOST` set to the reader endpoint | `cannot execute INSERT in a read-only transaction` | inserts succeed |
| fs-15 | aurora_failover_pinned_endpoint | processor pinned to instance endpoint of the writer; then failover | failover event + read-only errors | inserts succeed |
| fs-16 | aurora_slow_query | a missing index + a query path that scans (code flag) | long-running query + ACU/CPU up | query under threshold |
| fs-17 | ecs_bad_image | new task definition with a tag that does not exist | `CannotPullContainerError` + deploy | service at desired count on a good revision |
| fs-18 | ecs_secret_access_denied | remove `secretsmanager:GetSecretValue` from the execution role, force a deployment | `ResourceInitializationError ... secret` | tasks start |
| fs-19 | alb_health_check_wrong | target group health path `/healthz` (404) | UnHealthyHostCount + target reason `Target.ResponseCodeMismatch` | targets healthy |
| fs-20 | ecs_oom | orders-api memory 256 MiB with an allocation flag | exit code 137 / OutOfMemory | tasks stable |
| fs-21 | secret_rotated_stale_credentials | rotate the app DB password (DB + secret) without restarting orders-api | `password authentication failed` + secret changed in window | queries succeed |
| fs-22 | k8s_config_crashloop | `catalog-config` gets an invalid value; rollout restart | CrashLoopBackOff + the app's startup error | pods ready |
| fs-23 | k8s_missing_secret_key | `catalog-secret` loses a key the Deployment references | `CreateContainerConfigError` / `couldn't find key` | pods ready |
| fs-24 | k8s_readiness_probe_wrong | readiness probe on the wrong port | 0 ready, probe failures in events | pods ready |
| fs-25 | k8s_unschedulable_requests | cart-worker requests 8 CPU on a 2-CPU node | `FailedScheduling ... Insufficient cpu` | pod running |
| fs-26 | k8s_image_pull | catalog-api image tag that does not exist | `ImagePullBackOff` + deploy | pods ready on the previous image |
| fs-27 | eventbridge_rule_disabled | disable the reconcile rule | `rule_enabled = 0` + no invocations in window | reconciler invoked again |

## 8. What this wave cannot claim

- One run per fault: no stability claim. A fault fixed once may not be fixed on a second run.
- The harness applying the fix is a stand-in for a human who would also read the report. A fix that
  works when applied verbatim is the strongest thing measurable here; it is not "WARDEN fixed it".
- The faults were designed by the same people who built the tool, as in every wave. Their text is
  registered here first so it cannot be tuned to the outcome.
- ElastiCache is read only through AWS APIs and CloudWatch.
