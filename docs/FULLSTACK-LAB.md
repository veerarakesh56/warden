# The full-stack lab

The full-stack lab is a small but realistic company stack on AWS that WARDEN is tested against. It runs a
shop's services on the platforms a real team mixes (Lambda, ECS, EKS, Aurora, DynamoDB, SQS, SNS, Redis), breaks
them in 27 different ways, one at a time, and records what WARDEN read, what it concluded, and what the gate
decided.

| Part | Where |
|---|---|
| The stack (infrastructure only) | `terraform/fullstack/` and `terraform/fullstack/aurora_express.py` |
| The applications that run on it | `scripts/deploy_fullstack_apps.py`, `manifests/shop/` (synced by Argo CD), `k8s/shop-pipeline/` |
| The fault catalogue | `scenarios/catalog/wave4-fullstack.yaml` (28 entries: a healthy control and 27 faults) |
| Inject, revert and "fixed when" checks | `scenarios/ops_fullstack.py` |
| The operator's step-by-step tool | `scenarios/fullstack_cli.py` |
| Grading | `scenarios/score.py` with the rubric `scenarios/scoring.yaml` ([SCORING.md](../scenarios/SCORING.md)) |
| WARDEN's evidence reader for it | `src/warden/aws_stack.py` (`WARDEN_BACKEND=stack`) |

The catalogue, the pass criteria and the rubric were written before any fault ran, so they could not be tuned to
what a run produced. Every later change is dated in the files themselves.

## 1. The stack

Everything belongs to one environment: the Terraform workspace is the environment, names are `warden-<env>-*`,
and every resource is tagged `Project=warden` and `Environment=<env>`. A workspace that is not an environment in
`src/warden/data/environments.yaml` is refused before anything is built.

| Component | Shape |
|---|---|
| Network | one VPC over two availability zones; private subnets for everything except the NAT gateway; one NAT gateway; free gateway endpoints for S3 and DynamoDB; interface endpoints for Secrets Manager and SQS |
| Lambda | `checkout` (the API, alias `live`), `order-processor` (SQS consumer, in the VPC, writes to Aurora), `notifier`, `reconciler` (every 5 minutes, in the VPC, reads Aurora and Redis), `traffic` (a load generator, every minute), `ops` (harness-only admin commands for Redis) |
| API Gateway | an HTTP API: `POST /checkout` (bearer token, from Secrets Manager) and `GET /health`, with access logs |
| ECS | `orders-api` on Fargate (2 tasks) behind an **internal** ALB |
| EKS | one cluster, a managed node group of 2 x m7i-flex.large (one per zone); namespace `shop` with `catalog-api` (2 replicas, HPA 2-4) and `cart-worker` |
| Aurora PostgreSQL | Serverless v2 in express configuration, 0.5-2 ACU, a writer and a reader; IAM database authentication only, so **no database password exists** |
| ElastiCache Redis | a primary and one replica, `cache.t4g.micro` |
| DynamoDB | `carts`, provisioned 5 RCU / 5 WCU with no autoscaling, so a capacity fault stays a capacity fault; point-in-time recovery on (any second of the last 35 days can be restored), deletion protection off so the stack can be destroyed on purpose |
| SQS / SNS | `orders` and `notifications` queues, each with a dead-letter queue; topic `order-events` |
| Secrets Manager | connection **metadata** for the app's database user (no password), the API token |
| EventBridge | the reconcile and traffic schedules |
| CloudWatch | one alarm per signal a fault trips: these alarms are the alert source |
| Budget | `warden-<env>-guard`, USD 50 a month by default |

[terraform/fullstack/README.md](../terraform/fullstack/README.md) has the apply and destroy commands, the network
table and the cost table (about USD 0.50 an hour while it is up).

### Why Aurora is not in Terraform, and why m7i-flex.large

The lab was built on an AWS Free plan account, which creates Aurora only "with express configuration". The
Terraform AWS provider cannot set that, so `aurora_express.py create` makes the cluster after `terraform apply`
and `aurora_express.py destroy` removes it before `terraform destroy`. Express configuration has no VPC: the
only way in is the Aurora internet access gateway (PostgreSQL on 5432), and IAM authentication is the control.
Every login is a 15-minute token authorised by `rds-db:connect` for one database user:

| Database user | Logged in by |
|---|---|
| `warden_<env>_app` | the order-processor Lambda and the orders-api ECS task role |
| `warden_<env>_catalog` | the reconciler Lambda, and catalog-api through EKS Pod Identity |
| `warden_<env>_ro` (`pg_monitor` only) | WARDEN, with a token signed by its own read-only role |
| `postgres` | the harness role only (bootstrapping the database and three faults that need the master user) |

The Free plan also admits only Free Tier eligible instance types. The smaller ones hold too few pods for the
system pods plus `shop` plus room for a rollout, so the EKS nodes are m7i-flex.large (2 vCPU, 8 GiB). They are
on-demand, not Spot: a Spot interruption in the middle of a fault would be a second, unplanned fault.

The one NAT gateway is a single-zone dependency for the in-VPC Lambdas' route to Aurora. That is accepted for a
lab and is a deliberate example of a single point of failure; a production stack runs one NAT per zone.

## 2. Three pipelines

| Pipeline | Owns | Runs |
|---|---|---|
| infra (`ci-infra.yml`; deploys through `deploy-<env>.yml`) | `terraform/fullstack/` | validates on a change; plans on a push to the environment's own branch; applies only a saved, reviewed plan |
| apps (`ci-apps.yml`, `scripts/deploy_fullstack_apps.py`) | the Lambdas, the container image, the shop's Kubernetes objects, the database bootstrap SQL | tests and builds on a change; deploys on a push to the environment's own branch (`on-merge-<env>.yml`), or by hand from that branch (`deploy-<env>.yml`) |
| tool (`ci-tool.yml`) | WARDEN itself | on any other change |

An environment deploys only from the branch of its own name, and `main` deploys nothing: `main` runs CI only. The
`dev` branch deploys dev; it is `main` fast-forwarded. The `prod` branch deploys prod, with a person's approval; it
is `dev` merged by pull request. A commit that did not come that way is refused before the job holds a credential
([SETUP.md section 4b](SETUP.md#4b-which-branch-deploys-what)).

Terraform never deploys application code: it creates the functions and the ECS service from placeholders and
ignores later code changes, so a re-apply never rolls the apps back. The apps pipeline and the harness read
`stack.json` (`terraform output -json`, kept outside the repository) and never call Terraform.

## 3. WARDEN's identities in the lab

WARDEN only reads here. Its identities:

- **AWS:** the role `warden-<env>-reader` (`terraform/fullstack/reader.tf`), assumed per run. Its policy is
  exactly the read calls the stack backend makes - `tests/test_aws_stack.py` checks this in both directions -
  plus one grant that is not an API call: `rds-db:connect` as the read-only database user. No write, no
  `secretsmanager:GetSecretValue`.
- **Kubernetes:** the ServiceAccount `warden` in `shop`, bound to the six-read ClusterRole in `k8s/rbac.yaml`,
  through a token-only kubeconfig.
- **Aurora:** the read-only database user above.
- **Redis:** none. ElastiCache is VPC-only, so WARDEN reads it through CloudWatch and the ElastiCache API. This
  is a stated limit.

## 4. The evidence contract

The harness, the stack backend and the report are built against this contract. If the code and this section
disagree, one of them is fixed in the same change.

### A. Alert labels

A CloudWatch alarm going to ALARM is turned into an Alertmanager-shaped alert: the alarm's name, its description
(which names the symptom, **never the cause**), a severity, and labels for every resource of the application: `app`,
`lambda`, `sqs`, `dynamodb_table`, `elasticache`, `aurora_cluster`, `alb_target_group`, `apigw`, `ecs_cluster`,
`ecs_service`, `eks_cluster`, `namespace`, `deployment`, `secret`, `sns_topic`, `eventbridge_rule` (lists are
comma-separated). Every alert for an application carries the same full map, whichever component broke, so the
labels never point at the fault. A dead-letter queue is found from its queue's redrive policy, never from a label.

WARDEN is given (in its environment, never on the command line) the assumed reader role's credentials, the
Region, a token-only `KUBECONFIG`, and `WARDEN_STACK_DB_PRIMARY_RO_DSN` / `WARDEN_STACK_DB_REPLICA_RO_DSN`, whose
password is an IAM database token signed with the reader role's own credentials.

### B. Metrics

One reader per labelled resource, each isolated: a reader that fails becomes a `TOOL-PARTIAL <reader>: <reason>`
line and a `tool_errors` entry (policy P8 reads it), never silence. An unmeasured metric is absent, never zero.
When several functions, queues, rules or Deployments are labelled, metric names carry a `__<short name>` suffix.

| Reader | Metrics |
|---|---|
| lambda | `lambda_errors`, `lambda_throttles`, `lambda_invocations`, `lambda_duration_max_ms`, `lambda_timeout_s`, `lambda_memory_mb`, `lambda_reserved_concurrency` (only when set), `lambda_concurrent_executions`, `lambda_esm_enabled` |
| sqs | `sqs_visible`, `sqs_in_flight`, `sqs_oldest_age_s`, `sqs_visibility_timeout_s`, `dlq_visible`, `sqs_max_receive_count` |
| dynamodb | `ddb_provisioned_rcu`, `ddb_provisioned_wcu`, `ddb_consumed_rcu`, `ddb_consumed_wcu`, `ddb_read_throttle_events`, `ddb_write_throttle_events`, `ddb_throttled_requests` |
| elasticache | `redis_memory_pct`, `redis_evictions`, `redis_curr_connections`, `redis_engine_cpu_pct`, `redis_replication_lag_s`, `redis_nodes_available`, `redis_nodes_total` |
| aurora | `aurora_connections`, `aurora_replica_lag_ms`, `aurora_acu_utilization_pct`, `aurora_cpu_pct`, `aurora_deadlocks`, `aurora_members_available`, plus the PostgreSQL backend's own metrics on the writer and, prefixed `reader_`, on the reader |
| alb | `alb_target_5xx`, `alb_elb_5xx`, `alb_unhealthy_hosts`, `alb_healthy_hosts`, `alb_target_response_time_s` |
| apigw | `apigw_5xx`, `apigw_4xx`, `apigw_latency_ms` |
| ecs, k8s | what the ECS and Kubernetes backends emit elsewhere, unchanged |
| secrets | `secret_changed_age_s` (from metadata only) |
| sns | `sns_notifications_failed`, `sns_notifications_delivered` |
| eventbridge | `rule_enabled`, `rule_invocations` |

### C. Log lines

Every line starts with a tag, so the report and the playbook can route it. The tags are `LOG` (per function,
service or pod), `CONFIG` (a function's settings; secret-looking variable names shown bare), `ESM` (an event
source mapping), `CODE` and `SOURCE` (the innermost frame of a Python traceback and the deployed source lines
around it, read from the function's package), `QUEUE`, `POLICY`, `TABLE`, `EVENT` (ElastiCache and Aurora
events), `REPLGROUP`, `SG`, `APPSG`, `TASKROLE` (the role that signs a service's database tokens), `CLUSTER`,
`TARGET`, `TARGETGROUP`, `SECRET` (a change, metadata only), `RULE` and `TOOL-PARTIAL`. All of it is redacted
before it reaches the model, like every other piece of evidence.

### D. Deploy records

`{"kind": "lambda" | "ecs" | "k8s" | "secret", "service", "at", "version" or "image", "previous"}`. A Lambda alias
moving to a new version inside the window is a deploy; its `previous` is the version that served the most traffic
in the six hours before. A secret change is recorded with `kind: "secret"`: it is not a code deploy, and nothing
treats it as something to roll back.

## 5. The faults

Every injector refuses to act unless the target is named `warden-<env>-*` **and** its own tag API says
`Project=warden` (for Kubernetes, the namespace label). Every inject saves the exact prior state before its first
write, and its revert puts that state back; a revert with nothing saved does nothing. Faults are real: real
configuration, capacity, IAM, sessions and locks.

| id | class | injection | the signal WARDEN must read | fixed when |
|---|---|---|---|---|
| fs-00 | healthy_control | nothing | - | nothing is broken |
| fs-01 | lambda_code_regression | publish a checkout version that raises `KeyError` on a real field, move alias `live` | the traceback frame and the alias move | API errors back to 0 |
| fs-02 | lambda_timeout_too_low | checkout timeout 1 s while a call takes about 2 s | `Task timed out` and `lambda_timeout_s` | no timeouts for 3 minutes |
| fs-03 | lambda_throttled | reserved concurrency 0 on checkout | `lambda_throttles`, `lambda_reserved_concurrency` = 0 | invocations succeed |
| fs-04 | lambda_bad_env | checkout's table name points at a table that does not exist | `ResourceNotFoundException` and the variable's name | writes succeed |
| fs-05 | lambda_iam_missing | remove `dynamodb:PutItem` from checkout's role | `AccessDenied ... dynamodb:PutItem` | writes succeed |
| fs-06 | sqs_poison_message | messages the processor cannot parse | `dlq_visible` and the processor's traceback | DLQ drained, processor healthy |
| fs-07 | sqs_consumer_disabled | disable the orders event source mapping | a growing backlog, `State=Disabled` | the backlog drains |
| fs-08 | sns_delivery_blocked | the notifications queue policy stops allowing the topic | `sns_notifications_failed` | deliveries succeed |
| fs-09 | dynamodb_throttling | carts to 1 RCU / 1 WCU under traffic | write throttles, provisioned WCU 1 | no throttles for 3 minutes |
| fs-10 | redis_unreachable | remove the apps' security groups from Redis's ingress | connection timeouts in app logs | cache calls succeed |
| fs-11 | redis_memory_pressure | fill the cache with filler keys | `redis_memory_pct` high, evictions rising | memory back under the threshold |
| fs-12 | aurora_connection_exhaustion | open sessions until the server refuses | too-many-clients errors | new connections succeed |
| fs-13 | aurora_lock_contention | a transaction holds a row lock the processor needs | blocked sessions and the blocker's pid | no waiters |
| fs-14 | aurora_write_to_reader | the processor's `DB_HOST` set to the reader | `cannot execute INSERT in a read-only transaction` | inserts succeed |
| fs-15 | aurora_failover_pinned_endpoint | pin the processor to the writer's instance endpoint, then fail over | the failover event and read-only errors | inserts succeed |
| fs-16 | aurora_slow_query | a query path that scans | a long-running query, ACU and CPU up | the query under its threshold |
| fs-17 | ecs_bad_image | a task definition with an image tag that does not exist | `CannotPullContainerError` and the deploy | the service at desired count on a good revision |
| fs-18 | ecs_secret_access_denied | remove `secretsmanager:GetSecretValue` from the execution role, force a deployment | `ResourceInitializationError` naming the secret | tasks start |
| fs-19 | alb_health_check_wrong | target group health path `/healthz` (404) | unhealthy hosts, `Target.ResponseCodeMismatch` | targets healthy |
| fs-20 | ecs_oom | orders-api memory 256 MiB with an allocation flag | exit code 137 / OutOfMemory | tasks stable |
| fs-21 | db_iam_auth_revoked | remove `rds-db:connect` from the orders-api task role, force a deployment | `PAM authentication failed` and the `TASKROLE` line | no target 5xx for 3 minutes |
| fs-22 | k8s_config_crashloop | an invalid value in `catalog-config`, rollout restart | CrashLoopBackOff and the start-up error | pods ready |
| fs-23 | k8s_missing_secret_key | `catalog-secret` loses a key the Deployment references | `CreateContainerConfigError` | pods ready |
| fs-24 | k8s_readiness_probe_wrong | readiness probe on the wrong port | 0 ready, probe failures | pods ready |
| fs-25 | k8s_unschedulable_requests | cart-worker requests 8 CPU on 2-CPU nodes | `FailedScheduling ... Insufficient cpu` | pod running |
| fs-26 | k8s_image_pull | a catalog-api image tag that does not exist | `ImagePullBackOff` and the deploy | pods ready on the previous image |
| fs-27 | eventbridge_rule_disabled | disable the reconcile rule | `rule_enabled = 0`, no invocations | the reconciler runs again |

Sessions for fs-12 and fs-13 are held by a detached holder process, each named
`application_name = warden-bench-hold-<fault>`, so a revert can always end them, under a statement timeout so it
cannot hang.

## 6. Running it

The harness runs as its own role, `warden-<env>-harness`, which exists only for the environments in
`fault_environments` and which only the read-only operator role may assume. Nothing runs in a loop: each step is
a separate command started by a person, and everything a later step needs is written to a run directory outside
the repository (`$WARDEN_FS_RUN`).

```bash
python -m scenarios.fullstack_cli soak              # wait until every component is healthy for 30 minutes
python -m scenarios.fullstack_cli inject fs-07      # save the prior state, break it, wait for the alarm
python -m scenarios.fullstack_cli diagnose fs-07    # run WARDEN as the reader identity, save its report
python -m scenarios.fullstack_cli fix fs-07         # record the fix outcome from the gate's verdict
python -m scenarios.fullstack_cli verify fs-07      # poll the fault's "fixed when" check
python -m scenarios.fullstack_cli revert fs-07      # put the exact prior state back, wait for the baseline
python -m scenarios.fullstack_cli status            # every fault's steps, and the stack's health now
python -m scenarios.fullstack_cli watch             # after the last fault: 30 minutes of health checks
python -m scenarios.fullstack_cli destroy-check     # exits 0 only after a full watch since the last activity
python -m scenarios.fullstack_cli score             # grade the run directory
```

The waits cannot be skipped: `inject` refuses a run with no soak of at least 30 minutes, `watch` refuses fewer
than 30 minutes, and `destroy-check` refuses until a full watch began after the run's last activity. Some damage
only shows later (a dead-letter queue fills after three receives; a rollout stalls). Between faults the harness
keeps a quiet gap longer than WARDEN's evidence windows, so one fault's evidence cannot leak into the next.

**The harness applies no fix.** It used to run the fix commands an approved report printed, through an
allow-list. A security review on 2026-09-27 found the allow-list could be bypassed (the AWS CLI accepts
abbreviated flags, so `--prof admin` ran as another profile), and the capability was removed rather than
patched. Since 2026-10-16 the report prints no command at all: a fix is a typed plan from WARDEN's catalogue,
applied by WARDEN's own remediation workflow after a signed approval. The lab's `fix` step therefore records
`execution_disabled` for an approved fix, `blocked_by_gate` for a rejected one and `not_approved` otherwise.

Tear-down: `aurora_express.py destroy` first (Terraform does not know the cluster exists), then
`terraform destroy`, then `python scripts/account_sweep.py`, which must end clean.

## 7. Status and what the lab has shown

- **2026-09-26:** a preflight injected and reverted every fault fs-01 to fs-27 once on the real stack, with a
  clean baseline after each revert. The measured run then ran fs-00 to fs-05 and was **stopped at the owner's
  decision**; the stack was destroyed. **No full-stack score is published**, and none is claimed.
- What those six faults found, each fixed with a test: WARDEN's Kubernetes events and pod logs had no time
  window, so the healthy control read the preflight's rollouts; the Lambda rollback target was the numerically
  previous version rather than the one that had served traffic; the log reader kept the oldest lines of a window
  and dropped the ones naming the cause (fs-05); one refused Aurora query discarded every database metric read
  before it. fs-03 showed an account limit, not a WARDEN fault: a Free-plan account's whole Lambda concurrency is
  the unreserved minimum, so no positive reservation can be set there. fs-04 was the first fault diagnosed and
  fixed end to end.
- Since then the stack has been rebuilt per environment (`warden-<env>-*`), the harness has its own role, the
  shop's Kubernetes objects are synced by Argo CD, and fixes go through the signed-approval workflow instead of
  the harness.

## 8. What the lab cannot claim

- One run per fault: no claim about repeat stability.
- The faults were designed by the people who built WARDEN. Registering them before any run limits tuning; it
  does not remove that bias.
- Redis is read only through AWS APIs and CloudWatch.
- It is one company-shaped stack in one Region. It says nothing about stacks it does not resemble.
