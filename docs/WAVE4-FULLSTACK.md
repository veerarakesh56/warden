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
tasks with public IPs, EKS nodes), private subnets `10.42.10.0/24`, `10.42.11.0/24` (ElastiCache,
in-VPC Lambdas). One NAT gateway in the first public subnet gives the private subnets their way to
Aurora, which is OUTSIDE the VPC (section 9); gateway endpoints for S3 and DynamoDB (free),
interface endpoints for Secrets Manager and SQS in one private subnet. Changed 2026-09-26: Aurora
was in the public subnets and there was no NAT gateway.

| component | name | shape |
|---|---|---|
| Container image | ECR `warden-pg-fs-app` | one Python image; `APP_ROLE` selects orders-api / catalog-api / cart-worker |
| Aurora PostgreSQL | cluster `warden-pg-fs-aurora`: the writer instance AWS names (recorded in `stack.json` as `aurora_writer_instance`), reader `-aurora-2` | **Express configuration** (2026-09-26, section 9): Serverless v2, 0.5-2 ACU, the default PostgreSQL version, no VPC - reached only through the Aurora internet access gateway (5432, IPv4) - and IAM database authentication only. Created by `terraform/fullstack/aurora_express.py`, not terraform |
| ElastiCache Redis | replication group `warden-pg-fs-redis` | primary + 1 replica, `cache.t4g.micro`, private subnets |
| DynamoDB | `warden-pg-fs-carts` | PROVISIONED 5 RCU / 5 WCU, no autoscaling (so a capacity fault is a capacity fault) |
| SQS | `warden-pg-fs-orders` (+ `-orders-dlq`, maxReceiveCount 3), `warden-pg-fs-notifications` (+ `-notifications-dlq`) | standard queues |
| SNS | `warden-pg-fs-order-events` | subscribed by the notifications queue |
| Lambda | `-checkout` (API, alias `live`), `-order-processor` (SQS orders, in VPC, Aurora writer), `-notifier` (SQS notifications), `-reconciler` (EventBridge 5 min, in VPC, Aurora reader + Redis), `-traffic` (EventBridge 1 min, load generator), `-ops` (in VPC, harness-only admin commands for Redis) | Python 3.12 |
| API Gateway | HTTP API `warden-pg-fs-api`, `POST /checkout`, `GET /health` -> checkout:live | |
| ALB | `warden-pg-fs-alb` -> target group `warden-pg-fs-orders` (ip, `/health`) | |
| ECS | cluster `warden-pg-fs-ecs`, service `warden-pg-fs-orders-api`, 2 Fargate tasks | task role `warden-pg-fs-orders-api-task` signs IAM database tokens as `app`; `DB_USER` injected from the metadata secret, so the execution role still resolves a secret at start (fs-18) |
| EKS | cluster `warden-pg-fs-eks`, managed node group, **1 x m7i-flex.large ON_DEMAND** (min 1, max 1; was t3.medium, changed 2026-09-26, section 9) | add-ons: vpc-cni, coredns, kube-proxy, metrics-server, eks-pod-identity-agent |
| Kubernetes | namespace `shop`: Deployments `catalog-api` (2) and `cart-worker` (1); Services; ConfigMap `catalog-config`; Secret `catalog-secret` (`CATALOG_SIGNING_KEY`, which catalog-api requires at start); HPA `catalog-api` (2-4); PodDisruptionBudget; ServiceAccount `catalog-api` (EKS Pod Identity -> role `warden-pg-fs-catalog-pod`); ServiceAccount `warden` (the read-only identity) | |
| Secrets Manager | `warden-pg-fs-db-app` | Connection **metadata** only - `username` app, `dbname`, `port`, `host`, `reader` (filled by `aurora_express.py`); no password exists. `-db-catalog` and `-db-warden-ro` removed 2026-09-26 (section 9). |
| NAT | one NAT gateway + Elastic IP in the first public subnet; the private route table's default route | the in-VPC Lambdas' way to Aurora. ⚠ Single AZ (section 9). Added 2026-09-26. |
| EventBridge | rules `warden-pg-fs-reconcile-5m`, `warden-pg-fs-traffic-1m` | |
| CloudWatch | one alarm per signal the faults below trip; the **alert source** | |
| Budget | raised to USD 50 for the account (owner, 2026-09-25) | |

Why m7i-flex.large: the Free plan admits only Free Tier eligible instance types (section 9); a
t3.small node takes 11 pods, and the system pods plus `shop` plus headroom for a rollout does not
fit, so the eligible type with room is m7i-flex.large (2 vCPU, 8 GiB, 29 pods). ON_DEMAND, not Spot:
a Spot interruption mid-fault would be an unplanned second fault.

## 3. WARDEN's identities for this wave (read-only, all of them)

- **AWS:** role `warden-pg-fs-reader`, assumed per run. Its policy is EXACTLY the read calls the
  stack backend makes, asserted in both directions by a test (as Wave 1's four were), plus ONE grant
  that is not a call: `rds-db:connect` as `warden_ro` (the database login below; the test names it
  as its only exception). No write, no `secretsmanager:GetSecretValue`, no `s3:GetObject` except the
  Lambda code download (section 5).
- **Kubernetes:** ServiceAccount `warden` in `shop`, bound to the six-read ClusterRole
  (`k8s/rbac.yaml`) by a RoleBinding. Token-only kubeconfig, as Wave 2.
- **Aurora:** database user `warden_ro` with `pg_monitor` only - fixing Wave 3's gap, where WARDEN
  read as the master user. Since 2026-09-26 it logs in with an IAM token that the harness signs with
  the ASSUMED READER ROLE's credentials, never the operator's: the reader role's `rds-db:connect` is
  what lets WARDEN in. No password exists.
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
  CONCURRENTLY`, `ALTER DATABASE ... SET` - through psycopg, as the master user `postgres` with an
  IAM token signed by the operator's credentials (2026-09-26).
- An `iam put-role-policy` document may name `arn:aws:rds-db:ap-south-2:*:dbuser:*/app` or `.../catalog`
  (the application users, action `rds-db:connect` only - never `postgres` or `warden_ro`): the
  cluster id in that ARN is masked in reports, so the user name is the scope (2026-09-26).

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
| fs-21 | db_iam_auth_revoked | remove `rds-db:connect` from orders-api's task role (its only inline policy, so the policy goes), force a deployment. **Changed 2026-09-26, before any fault ran** (section 9): was `secret_rotated_stale_credentials`, rotating a password that express configuration no longer has | `PAM authentication failed for user "app"` in the ECS logs + `TASKROLE ecs/warden-pg-fs-orders-api role=...` | ECS steady, ALB healthy, no target 5xx for 3 min |
| fs-22 | k8s_config_crashloop | `catalog-config` gets an invalid value; rollout restart | CrashLoopBackOff + the app's startup error | pods ready |
| fs-23 | k8s_missing_secret_key | `catalog-secret` loses a key the Deployment references (since 2026-09-26 `CATALOG_SIGNING_KEY`, not a password) | `CreateContainerConfigError` / `couldn't find key` | pods ready |
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

## 9. 2026-09-26 - Free-plan constraints (changed after the first apply, before any fault ran)

**What happened.** The first real `terraform apply` of `terraform/fullstack` created about 76
resources and failed on two:

- `aws_rds_cluster.aurora`: `FreeTierRestrictionError: To use Aurora clusters with free plan accounts
  you need to set WithExpressConfiguration.`
- `aws_eks_node_group.this` (t3.medium): `The specified instance type is not eligible for Free Tier`.

The account is on the AWS Free plan and the owner's decision is to stay on it. Nothing had been
deployed onto the stack and no fault had been injected, so no measurement depends on anything below.
Every change is listed with its reason.

**Aurora: express configuration, created by a script.** The Free plan creates Aurora only "with
express configuration", and the Terraform AWS provider (6.66.0, and main) cannot set it. So
`terraform/fullstack/aurora_express.py` (INFRA pipeline, stdlib + boto3) creates the cluster after
`terraform apply` and deletes it before `terraform destroy` (`create` / `status` / `destroy`; it
refuses any cluster not named `warden-pg-fs-*`; a second `create` only refreshes the records).
Express configuration fixes, and the stack now lives with:

- one Aurora Serverless writer instance named by AWS - the script records it as
  `aurora_writer_instance`, which the harness's baseline and fs-15 read; the reader `-aurora-2`
  (promotion tier 1, another AZ) is added by the script; capacity set to 0.5-2 ACU as before;
- **no VPC association**: the only way in is the Aurora internet access gateway (PostgreSQL wire
  protocol, 5432, IPv4), which cannot be disabled. The Aurora security group, its ingress rules and
  the DB subnet group are gone; access control is IAM alone;
- **IAM database authentication only**: no master password, no Secrets Manager credentials. The
  master user is `postgres` (it holds `rds_iam`). Every login is a 15-minute token from
  `generate_db_auth_token`, authorised by `rds-db:connect`;
- the default engine version (was pinned to 16.14; it can be upgraded later), the default parameter
  group, an AWS-owned encryption key, no RDS Proxy.

The alarms name the cluster by its literal id `warden-pg-fs-aurora`; the Aurora keys of
`stack.json` (`aurora_cluster`, `aurora_writer_endpoint`, `aurora_reader_endpoint`,
`aurora_instance_endpoints`, `aurora_writer_instance`, `db_name`, `db_master_username`) are merged in
by the script, not written by `terraform output`.

**No password anywhere.** The `random_password` resources, the `db_master_password` variable, the
password outputs, `WARDEN_FS_DB_MASTER_PASSWORD` (harness, deploy tool, infra CI secret) and every
`PASSWORD` in `bootstrap.sql` are gone. `bootstrap.sql` creates `app`, `catalog` and `warden_ro` as
LOGIN roles and grants each `rds_iam`; table grants are unchanged; `warden_ro` still gets
`pg_monitor` only. Who may log in as whom - each grant scoped by database user
(`arn:aws:rds-db:ap-south-2:<account>:dbuser:*/<user>`: the cluster's resource id is only known
after the script runs, so the user name is the scope):

| database user | logged in by | grant lives in |
|---|---|---|
| `app` | order-processor Lambda role; orders-api's NEW ECS task role `warden-pg-fs-orders-api-task` | `lambda.tf` (Sid `ConnectAsApp`), `ecs.tf` |
| `catalog` | reconciler Lambda role (it reads the reader); catalog-api through EKS Pod Identity, role `warden-pg-fs-catalog-pod` | `lambda.tf` (Sid `ConnectAsCatalog`), `eks.tf` |
| `warden_ro` | WARDEN - the token is signed by the harness with the assumed `warden-pg-fs-reader` credentials | `reader.tf` (the reader-policy test's one named exception: not an API call) |
| `postgres` | the operator only: `bootstrap-db` and the harness's admin connection | `terraform/proving-ground/operator-policy.json` (Sid `PgLogin`) |

The permissions boundary gained `rds-db:connect` (the owner applies it) - every `warden-pg-fs-*`
role carries it, so without it none of these grants would take effect.

**Secrets Manager.** `warden-pg-fs-db-app` stays and holds connection METADATA only
(`username` app, `dbname`, `port`, `host`, `reader`; the script fills the endpoints). It stays
because the in-VPC Lambdas fall back to it (terraform leaves `DB_HOST` empty - it cannot know the
endpoints; fs-14/fs-15 still set `DB_HOST`), and because orders-api's task definition still injects
`DB_USER` from it: the execution role must still resolve a secret at task start, or fs-18 (that
grant removed) would stop nothing. `-db-catalog` and `-db-warden-ro` were removed: with no password
they held nothing that `stack.json` and the ConfigMap do not already carry.

**NAT gateway.** Aurora is now outside the VPC, so the in-VPC Lambdas (order-processor,
reconciler) need internet egress: one NAT gateway + Elastic IP in `public[0]`, default route of the
private route table to it. ECS tasks and EKS nodes already had public IPs. ⚠ **Known weakness:** one
NAT is a single-AZ dependency - if that AZ fails, the in-VPC Lambdas lose the database while
everything else keeps running. Accepted for a benchmark stack (a second NAT doubles its cost);
recorded as a **Helios validation point**: a single NAT on the only path from a subnet group to a
dependency is exactly the kind of single point of failure a failure simulator should flag.
Cost: about USD 0.06/hour plus data processed. The operator's `WardenFullstackOperator` policy gains
`ec2:AllocateAddress` / `CreateNatGateway` (and their deletes, under the project-tag condition) and
may pass roles to `pods.eks.amazonaws.com`.

**EKS node: m7i-flex.large.** Free Tier eligible types in ap-south-2 are t3/t4g/t8i micro and small,
c7i-flex.large and m7i-flex.large. The small types hold too few pods (section 2); m7i-flex.large
(2 vCPU, 8 GiB, 29 pods) is the eligible type with room. Still 2 vCPU, so fs-25 (8 CPU requested) is
still unschedulable. catalog-api now logs in through **EKS Pod Identity** (add-on
`eks-pod-identity-agent`, ServiceAccount `shop/catalog-api`, association in `eks.tf`); the image
gained boto3 to sign tokens.

**Faults.**

- **fs-21 redesigned** - there is no password to rotate. New class `db_iam_auth_revoked`: remove
  `rds-db:connect` from orders-api's task role (reusing the fs-18 mechanism: the policy is deleted
  when it becomes empty), force a deployment. The tasks start and answer `/health`; every new login
  as `app` fails with `PAM authentication failed for user "app"`, so `/orders` returns 500 behind the
  ALB. Revert restores the policy and forces a deployment; verify: ECS steady, ALB healthy, no
  target 5xx for 3 min. The class is APPENDED to `scenarios/scoring.yaml` (`escalate_to_human`; no
  ActionKind edits IAM); `secret_rotated_stale_credentials` stays untouched and unused, so any
  earlier grading re-scores byte-identically.
- **fs-23** still removes a key the Deployment references: `catalog-secret` now holds
  `CATALOG_SIGNING_KEY` (generated at deploy, sent over stdin), which catalog-api refuses to start
  without - no longer a password.
- **fs-12** holds sessions until the server refuses; on Serverless v2 `max_connections` depends on
  the capacity, and the holder reads it at run time - unchanged.
- **fs-14 / fs-15 / fs-16** unchanged: `DB_HOST` override, failover to the reader, slow query on
  the reader. The baseline accepts an empty `DB_HOST` (the metadata secret's host).
- Every IAM revert (fs-05, fs-18, fs-21) now also deletes any inline policy the role did not have
  before the inject - WARDEN's fix adds its own `warden-restore-*` policy, and the next fault must
  start from exactly the baseline.

**WARDEN.** A new playbook pattern `db_iam_auth_refused` reads `PAM authentication failed for user
X`. Its fix is `aws iam put-role-policy` giving `rds-db:connect` for user X back to the role that
signs the tokens - printed only when the evidence NAMES that role. For an ECS service the stack
backend now emits `TASKROLE ecs/<service> role=<name>` from the task definition
(`ecs:DescribeTaskDefinition`, already granted); without it, and for a Lambda, no command is printed
and the report says which line would be needed. The harness allow-list accepts that grant only for
the application users (`app`, `catalog`) and only as `rds-db:connect`.

**Not verifiable without AWS** (checked on the first apply, recorded here when known): the express
cluster's endpoint names follow the classic `<cluster>.cluster-<id>` / `.cluster-ro-` scheme that
the writer-endpoint fix and the harness guard rely on; `aws:RequestedRegion` (the boundary's region
condition) is present when Aurora authorises `rds-db:connect`; Pod Identity credentials reach a pod
that does not mount its ServiceAccount token; express configuration accepts `Tags` and
`DatabaseName` on `CreateDBCluster`, and a later `ModifyDBCluster` of the Serverless v2 capacity;
the writer instance express creates is named with the cluster id as prefix (otherwise the operator
policy, which scopes `rds:*` to `db:warden-pg-fs-*`, cannot delete it); `CreateDBInstance` accepts
an `AvailabilityZone` for the reader; an instance endpoint is reachable through the internet access
gateway (fs-15 pins `DB_HOST` to one); `FailoverDBCluster` works on an express cluster (fs-15).

**Found by review before the apply (2026-09-26):** the EKS Pod Identity agent calls
`eks-auth:AssumeRoleForPodIdentity` with the node role, a separate service prefix the boundary did not
allow - catalog-api would have had no AWS credentials at baseline. The boundary now allows it.

**Checked on the first apply (2026-09-26, before any fault ran).** Answers to the list above:

- Endpoints follow `<cluster>.cluster-<id>` and `.cluster-ro-<id>` - yes.
- A boundary-limited role can use `rds-db:connect`, and Pod Identity credentials reach a pod that does not mount its token - yes: catalog-api reads the Aurora reader with an IAM token from its Pod Identity role.
- `Tags` on `CreateDBCluster` - accepted.
- `DatabaseName` - **rejected**. The database is created by the apps pipeline's `bootstrap-db` step, which connects to `postgres` first.
- `ModifyDBCluster` of the capacity - accepted (0.5-2 ACU).
- The writer is named `<cluster>-instance-1` - inside the operator's `db:warden-pg-fs-*` scope.
- The reader was created in a different AZ from the writer - yes.
- **Still unverified until the preflight:** an instance endpoint reached through the gateway (fs-15), and `FailoverDBCluster` on an express cluster (fs-15).

Found by the first real deploy, each fixed with a test (commits `d669cf0`, `fb4583a`, `1f5e603`):

- `CreateDBCluster` in express configuration is authorised against `subgrp:default` and needs `rds:EnableInternetAccessGateway`, an action AWS's policy validators do not list.
- Terraform's `default_tags` make event-source-mapping creation call `lambda:TagResource` on `event-source-mapping:*`.
- The CloudWatch Observability add-on injected an OpenTelemetry agent into catalog-api, which the restricted Pod Security namespace refused. The pods now opt out by annotation.
- The Lambda zips lacked `typing_extensions`: pip evaluated markers for the local Python, not 3.12. The build now checks the dependency closure for 3.12.
- The harness read `~/.kube/config`, not the apps pipeline's kubeconfig.

**Alarms, measured on the idle stack.**

- The `aurora-cpu` alarm used the cluster's per-minute *Maximum*. On the idle express cluster that spikes to 100 from Aurora's own processes while the average is about 22, and it went to ALARM twice with no fault injected. It now uses the writer's *Average* (`Role=WRITER`).
- The Container Insights metrics `pod_status_ready` and `pod_status_running` exist with `{ClusterName, Namespace, PodName}` and arrive every minute.
- The `soak` step now needs an unbroken healthy streak of the minimum length. Before, it accepted "healthy at minute 30" after an earlier break.

**Preflight on the real stack (2026-09-26, 10:37-11:28 UTC).** Every fault fs-01..fs-27 was injected and
reverted once, and the whole-stack baseline was clean after each revert. What it found and settled:

- **fs-12 failed the first time, and the cause was the harness.**
  - One IAM-token TLS login through the express gateway takes ~0.26 s. Opening 844 sessions in series
    took 3.7 minutes, past the inject's 180 s ready timeout.
  - The revert then raced a holder that was still opening sessions.
  - The holder stopped at its own count (`max_connections`), which never proved the server was full.
  - Now it opens sessions in parallel and pushes past `max_connections` until it is refused. The revert
    polls. Measured on the rerun: 835 sessions accepted, then **59 refused** by the server (the real
    ceiling is below `max_connections` = 844), 832 held.
- **fs-15:** `FailoverDBCluster` works on an express cluster and fails back. The writer moved to
  `warden-pg-fs-aurora-2`, and the revert restored `-instance-1`. The pinned instance endpoint is
  exercised by the measured run.
- **fs-06 and fs-11** showed no symptom inside the preflight's check, as expected:
  - fs-06: the DLQ receives the poison message only after 3 receives x 120 s visibility.
  - fs-11: the preflight fills 50 MB. The measured run fills 400 MiB against a measured `maxmemory` of
    384 MiB, which crosses the 80% alarm.
- The preflight's own recovery path was wrong. `fullstack_cli revert` refuses a preflight fault, because
  the preflight records no inject step. It has `--revert --only fs-NN` now, and that path was used for real.
- `inject` now refuses a run with no recorded soak, so the owner's order is enforced, not remembered.
  **Evidence isolation across run directories is still manual.** The measured run does not know about
  the preflight's activity, so its first inject waits 18 minutes after the preflight's last revert (the
  same quiet gap it enforces between its own faults).

**The measured run, fs-00 (2026-09-26, 12:07-12:29 UTC), and what changed because of it.** Every item
below is also printed in the run's RESULTS.md section 7.

- **The first diagnose produced no report.** Every attempt of one model call hit the claude_cli
  provider's 45 s ceiling. The real three-call diagnosis takes ~69 s (measured once with a higher limit;
  that report was deleted unread). The claude_cli provider now defaults to 180 s. The retry was allowed
  only because no report existed. The failed attempt is kept in the record (`attempts_without_report`)
  and in the manifest's `resumes`.
- **The answer that was graded read another incident's evidence.** WARDEN's Kubernetes events and live
  pod logs had no time window, and its deploy history was 6 hours. So the healthy control read the
  preflight's rollouts and start-up readiness failures, and concluded (confidence 0.40, escalated) that
  an incident had already happened. Its action was `no_action`. That answer stands as recorded; it is
  not re-asked.
- **WARDEN's printed fix broke a healthy service, and the harness applied it, as the protocol says.**
  The probe pattern printed `kubectl -n shop rollout undo deploy/catalog-api` while 2/2 pods were Ready.
  The previous revision was the preflight's `does-not-exist` image, so catalog-api went to 1/2 ready.
  `verify` recorded it not fixed. fs-00 has no fault revert, and the harness undoes only SQL fix
  effects, so the operator rolled catalog-api back to revision 10 by hand. That repair is recorded as
  an operator note.
- **Changed before fs-01**, each with a test that fails without it:
  - WARDEN's k8s events and live pod logs reach back 15 min, like its CloudWatch reads.
  - `rollout undo` is printed only while the Deployment is failing now.
  - The harness pins every evidence window in WARDEN's environment: 15 min logs, 10 metrics,
    **30 deploy history**. The quiet gap between faults is therefore 33 minutes.
  - The change of isolation settings is written to the manifest and printed in the results.
- **After fs-02 (13:56 UTC): the Lambda rollback target.**
  - WARDEN took "previous" to be the numerically previous version. Each injected fault publishes one,
    so fs-01's fix aimed at version 6 (the preflight's fs-04 version). fs-02's fix aimed at 7, fs-01's
    broken version. It was applied and did not fix it: 27 of 27 invocations still erred.
  - Version 3 had served the traffic for hours. Lambda keeps no alias history, but its
    `ExecutedVersion` metric records it. The deploy record's `previous` is now the version that served
    the most `live` traffic in the 6 h before the current version was published.
  - The record says which basis it used. When no per-version traffic exists, it falls back to the
    numerically previous version.
  - Checked live: it gives 3 for both fs-01 and fs-02.
- **Harness fixes found by fs-01**, both with tests:
  - The verifiers called `cloudwatch:GetMetricStatistics`, which the operator is not granted. They now
    use `GetMetricData`. All 28 verifiers were run against the live baseline and return "fixed".
  - WARDEN's fix was rebuilt without `AWS_REGION`, so it came out without `--region` and the
    allow-list refused it. fs-01's `fix_not_allowed` is therefore a harness artefact; its record says
    so, and what the fix would have done.
- **fs-03 (14:29-14:52 UTC), an account limit, not a WARDEN defect.**
  - WARDEN diagnosed it correctly: reserved concurrency 0.
  - It printed `put-function-concurrency ... 4`, with its standing caveat that AWS keeps 10 concurrent
    executions unreserved. AWS refused it with `InvalidParameterValueException`. This Free-plan
    account's whole Lambda limit is 10, all of it the unreserved minimum, so no positive reservation
    exists here. Verify recorded it not fixed.
  - The fix that works on this account, `delete-function-concurrency`, is deliberately outside the
    allow-list: it lifts the function's cap, and section 6's "never `delete-*`" is tested with that
    exact command.
  - A change to print it was tried and withdrawn rather than weaken a deliberate safety rule mid-run.
    On an account with a normal limit (1000), WARDEN's printed fix applies.
