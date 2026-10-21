# Runbook: WARDEN is down

What a person does when WARDEN itself is not working: alarms are not being diagnosed, no report reaches Slack, or
WARDEN's own alarms page. For every other way WARDEN can be the incident (a bad fix, injected text, a strange model,
a tampered record), use [RUNBOOK-WARDEN-INCIDENT.md](RUNBOOK-WARDEN-INCIDENT.md).

Everything below is written from what the code and Terraform build today ([the runtime module](../terraform/modules/warden-runtime/),
[its root](../terraform/runtime/main.tf), [the runtime workflow](../.github/workflows/runtime.yml)). Anything not built yet is marked **planned**. Every `warden`
command here is checked against the real command line, and every AWS name against the Terraform that makes it, by
[tests/test_runbook_warden_down.py](../tests/test_runbook_warden_down.py).

Names below use the runtime environment `ops` (environments.yaml `runtime:`). Give every time in UTC and IST
(UTC+05:30).

## 1. What WARDEN is made of (so you know what can be down)

| Part | What it is | Where |
|---|---|---|
| Workers | Six ECS Fargate services in the cluster `warden-ops-runtime`, one per trust zone: `warden-ops-core` (workflows, audit steps, heartbeat), `warden-ops-read` (evidence), `warden-ops-llm` (the model, the daily synthetic incident), `warden-ops-notify` (Slack, GitHub), `warden-ops-act` (the only one that changes anything), `warden-ops-critic` (Eldane, the AI critic: reviews plans, approves in `dev` only) | [compute.tf](../terraform/modules/warden-runtime/compute.tf) |
| Temporal Cloud | Holds every workflow's state; the workers and Lambdas reach it with API keys | outside AWS; `connect` in [runtime.py](../src/warden/runtime.py) |
| Front door Lambdas | `warden-ops-alarm` (CloudWatch alarm changes and service events), `warden-ops-alertmanager` (Alertmanager and Datadog webhooks), `warden-ops-approval` (the approval page and records page), `warden-ops-actor-use` (actor-role sessions), `warden-ops-ack` (answers Slack's button note) | [frontdoor.tf](../terraform/modules/warden-runtime/frontdoor.tf), [witness.tf](../terraform/modules/warden-runtime/witness.tf) |
| Pager | `warden-ops-pager`: says every self-alarm's page again in Slack and by email every 15 minutes until an approver acknowledges it with a passkey; no image, no VPC, no database | [paging.tf](../terraform/modules/warden-runtime/paging.tf) |
| Lost-alarm queue | `warden-ops-alarm-dlq`: an alarm change EventBridge could not deliver to the `alarm` Lambda after 8 retries within an hour lands here and is kept 14 days | [frontdoor.tf](../terraform/modules/warden-runtime/frontdoor.tf) |
| Audit | The audit database `warden-ops-audit`: an Aurora PostgreSQL cluster, or one RDS PostgreSQL instance on the AWS Free plan; checkpoints anchored to an S3 bucket with Object Lock | [aurora.tf](../terraform/modules/warden-runtime/aurora.tf), [anchors.tf](../terraform/modules/warden-runtime/anchors.tf) |
| Kill switch | A row in the audit, checked inside every apply right before the change | [bounds.py](../src/warden/bounds.py), [activities.py](../src/warden/activities.py) |
| Logs | `/warden/ops/worker` (one stream prefix per zone) and `/aws/lambda/warden-ops-<name>`, kept 90 days | [compute.tf](../terraform/modules/warden-runtime/compute.tf), [frontdoor.tf](../terraform/modules/warden-runtime/frontdoor.tf) |

## 2. How you find out

| Sign | What it means |
|---|---|
| The alarm `warden-ops-heartbeat-missing` pages | For two 5-minute periods the `core` worker has not completed a round trip through Temporal, or some zone (`read`, `llm`, `notify`, `act`, `critic`) has had no worker polling its queue: the core service, a zone's worker or its Temporal key, Temporal, the network or the clock is broken. The `heartbeat missed` line in `/warden/ops/worker` names the zone. Missing data counts as failure. |
| The alarm `warden-ops-synthetic-missing` pages | The daily shadow incident (`llm` zone) has not passed for 25 hours: the model, its key, or the diagnosis path is broken. |
| The alarm `warden-ops-alarm-dlq` pages | At least one alarm change was not handled: EventBridge could not deliver it, or the `alarm` (or `actor-use`) Lambda failed on it through every retry (section 5, Temporal). Those alarms were **not** diagnosed. While the runtime is paused, an actor-role session lands here on purpose: treat it as suspicious ([the incident runbook](RUNBOOK-WARDEN-INCIDENT.md)). |
| A watched alarm is red in CloudWatch but no Slack thread exists | The `alarm` Lambda, Temporal, the `notify` zone or Slack is broken. |
| A plan waits but the approval link does not open | The `warden-ops-approval` Lambda, the HTTP API `warden-ops-front` or the audit is broken. |
| The alarm `warden-ops-worker-errors` pages | A worker, in any zone, logged an ERROR or CRITICAL line. Read `/warden/ops/worker` around that time. |
| A page says a worker task stopped (the rule `warden-ops-worker-stopped`) | A worker task in one of the six zones exited or never started, other than for a deploy. |
| The alarm `warden-ops-lambda-errors` or `warden-ops-lambda-throttles` pages | A front door Lambda, Slack's answer or the pager itself failed or was throttled. Read the function's log first: Lambda retries an `alarm` event twice, and a retry that worked leaves nothing to do; one that failed every retry is in `warden-ops-alarm-dlq` (section 5, Temporal). |
| The alarm `warden-ops-model-provider-unavailable`, `warden-ops-model-daily-cap` or `warden-ops-model-budget` pages | The model provider is unavailable, a daily model limit is reached, or an incident spent its model budget: incidents go to a person on the rules alone (section 5, the model). |
| The alarm `warden-ops-audit-db-cpu`, `warden-ops-audit-db-connections` or `warden-ops-audit-db-storage` pages | The audit database is overloaded, out of connections or filling up (section 5, the audit). |
| The alarm `warden-ops-killswitch-on` pages | The kill switch went on, by a person or by WARDEN's breaker: nothing is applied until it is reset. |
| The alarm `warden-ops-unapproved-actor` or `warden-ops-approvers-changed` pages | An actor role was used without an approval on the record, or the approver list was written. Treat it as a security incident ([the incident runbook](RUNBOOK-WARDEN-INCIDENT.md)). |
| A page says a Temporal key is near its end | Rotate the key before it ends (section 5, Temporal). |

These pages go to WARDEN's own SNS topic (SSM `/warden/ops/tf/page_topic_arn`), never to WARDEN's intake, so they
work while WARDEN is down. Each one reaches the pager, which says it again in Slack and by email every 15 minutes
(the email through the alarm `warden-ops-page-repeat`) until an approver acknowledges it with a passkey on the
approval page (`/p`). The pager has no image, no VPC and no database: a dead worker or audit does not silence it.

**Gaps you must know about (honest, today):**

- **A zone that hangs while it still polls.** A zone whose task stops, whose worker stops polling its queue, or
  that logs an error, pages. A worker that still polls but never finishes its work, and logs nothing, does not:
  incidents start and then wait. Check every zone (section 5).
- **The watched environments' own alarms do not page anyone directly.** In this install their CloudWatch alarms have
  no alarm actions (`terraform/fullstack` sets none); they reach people only through WARDEN's Slack report. With
  WARDEN down, someone must look at the alarms by hand (section 3).
- **Paused on purpose.** Between test windows the runtime may be paused (SSM `/warden/ops/tf/paused` = `true`): no
  worker runs, the alarm intake is off and the self-alarms send nothing. That is not an outage. Check it first:

```
aws ssm get-parameter --name /warden/ops/tf/paused --query Parameter.Value --output text
```

## 3. First 10 minutes: people take over the incidents

1. **Look at the alarms yourself.** In each watched environment's Region, open CloudWatch, Alarms, "In alarm", and
   the Datadog monitors. Treat every alarm in ALARM as unhandled.

   ```
   aws cloudwatch describe-alarms --state-value ALARM --query "MetricAlarms[].[AlarmName,StateUpdatedTimestamp]" --output table
   ```

2. **Read the lost-alarm queue.** Every message is an alarm change WARDEN never saw. Handle each one by hand.

   ```
   aws sqs get-queue-url --queue-name warden-ops-alarm-dlq
   aws sqs receive-message --queue-url <queue-url> --max-number-of-messages 10 --visibility-timeout 900
   ```

   Reading a message does not remove it: after 15 minutes it shows again. Once a message is handled, delete it with
   the `ReceiptHandle` that came with it, and receive again until no message is left:

   ```
   aws sqs delete-message --queue-url <queue-url> --receipt-handle <receipt-handle>
   ```

3. **Page people by hand when needed.** WARDEN's own topic reaches its owner:

   ```
   aws sns publish --topic-arn <page-topic-arn> --subject "WARDEN down: incidents handled by hand" --message "<what is happening, times in UTC and IST>"
   ```

   The topic's ARN is the value of SSM `/warden/ops/tf/page_topic_arn`. For anyone else, use your team's usual
   channel; WARDEN has no other paging path today.

4. **Handle the incident without WARDEN.** The fixes in WARDEN's catalogue are ordinary AWS and Kubernetes actions
   (restart, scale, roll back); a person with the right access can do them as before WARDEN existed. Write down what
   you did, with times in UTC and IST, so it can be compared with the audit afterwards.

## 4. Decide whether to stop changes

If WARDEN may be half-working (for example `act` runs but `read` or the audit does not), stop all changes first:

```
warden killswitch on --approver <your-id> --key ~/.warden/<your-id>.pem
```

This opens the approval page; your passkey turns the switch on. Go on only when the page says the switch is **on**.
If the page does not open, or opens but does not confirm the switch is on, stop the only worker that changes
anything instead (this does not depend on WARDEN):

```
aws ecs update-service --cluster warden-ops-runtime --service warden-ops-act --desired-count 0
aws ecs wait services-stable --cluster warden-ops-runtime --services warden-ops-act
aws ecs describe-services --cluster warden-ops-runtime --services warden-ops-act --query "services[].[desiredCount,runningCount]"
```

The first command only asks ECS to scale down; a running task can still act until it stops. Treat changes as stopped
only when the last command shows `0` and `0`. If the update fails, or the count does not reach `0`, do not go on:
stop the task by hand (ECS console, the service, Tasks, Stop), and if that also fails, page the AWS account's owner.
Approved plans then wait; nothing is applied until the count is set back.

A second kill switch does not depend on WARDEN at all (B18): an IAM deny on each watched environment's actor role,
`warden-<env>-actor`, that refuses every AWS call unless the role's tag says `off`. A person with `iam:TagRole` turns
it on from their own machine or CloudShell:

```
python scripts/iam_kill_switch.py on --env <env>
python scripts/iam_kill_switch.py status --env <env>
```

It covers AWS fixes only (a Kubernetes fix is authorised by the cluster), and it protects nothing unless its policy
is attached to the role: `status` says so and fails when it is not. It has not yet been proven in a live window.

On a laptop set up for the cloud runtime (`WARDEN_APPROVAL_RP_ID` set, no `WARDEN_AUDIT_DSN`), `warden killswitch
status` refuses rather than read the laptop's own file, which says nothing about the cloud; the approval page is
where the cloud's switch is read.

## 5. Find which part is down

**Workers.** Running and desired count of every zone:

```
aws ecs describe-services --cluster warden-ops-runtime --services warden-ops-core warden-ops-read warden-ops-llm warden-ops-notify warden-ops-act warden-ops-critic --query "services[].[serviceName,runningCount,desiredCount]" --output table
aws logs tail /warden/ops/worker --since 30m --log-stream-name-prefix core
```

Read the stopped tasks' reason in the ECS console (service, Tasks, Stopped). Common causes seen so far: a secret that
was set or rotated but not yet read (workers read secrets when they start), the account's Fargate vCPU limit during a
deploy, and the deployment circuit breaker rolling a zone back.

**Temporal Cloud.** The worker logs show connection errors; the heartbeat alarm fires. While Temporal is unreachable:

- running workflows are not lost - their state is in Temporal and they continue when it is back;
- a new alarm change makes the `alarm` Lambda fail (it cannot reach Temporal). Lambda retries it twice, for up to 6
  hours; an event that failed every retry goes to `warden-ops-alarm-dlq` (the function's on-failure destination,
  `frontdoor.tf`), whose alarm pages - the same queue that holds what EventBridge could not deliver (8 retries
  within an hour). Not yet tried live: assume alarms during a Temporal outage were not diagnosed, read the queue,
  and check the alarms by hand (section 3);
- the worker refuses to start if it cannot check its clock against Temporal within 90 seconds (register O6).

Check Temporal Cloud's own status page and your namespace in its web UI. An expired or revoked API key looks the same
as an outage: each zone reads its own key from Secrets Manager (`warden/ops/temporal-api-key-<zone>`), and the three
front door Lambdas that reach Temporal (alarm, alertmanager, approval) share one, `warden/ops/temporal-api-key` (owner
decision 2026-10-20, for cost). After a zone's key is replaced, restart (section 6). A Lambda reads its secrets when a
new instance of it starts, so a warm instance keeps the old key until it is replaced.

**Lambdas.** Errors are in their logs:

```
aws logs tail /aws/lambda/warden-ops-alarm --since 1h
aws logs tail /aws/lambda/warden-ops-approval --since 1h
```

**The audit database.** Every step writes the audit, so with it down nothing moves:

```
aws rds describe-db-clusters --db-cluster-identifier warden-ops-audit --query "DBClusters[].[Status,Endpoint]"
```

On the AWS Free plan it is one instance instead:

```
aws rds describe-db-instances --db-instance-identifier warden-ops-audit --query "DBInstances[].[DBInstanceStatus,Endpoint.Address]"
```

It keeps automated backups with point-in-time recovery (`audit_db_backup_days`, at least 7 days outside the AWS Free
plan) and deletion protection. A restore has not been drilled yet ([register O4b](FAILURE-MODES.md)): a restore drill is **planned**. Do
not restore over the running database; restore to a new one and keep the old one as evidence.

**The model.** With the model unreachable (provider down, key expired, budget spent) WARDEN does not stop: it
escalates every incident to a person on its rules alone, with policy `P0-MODEL-UNAVAILABLE` (register M19). Reports
still reach Slack. Replace the key `warden/ops/anthropic-api-key` if it expired, then restart.

**Slack.** With the `notify` zone or Slack down, incidents are diagnosed and recorded but nobody is told. The records
page (`/r` on the approval domain) still lists them, for people on the approver or viewer list.

**A whole AWS Region.** WARDEN's runtime runs in one Region (environments.yaml `aws_region`). There is no standby in a
second Region. If that Region is down, WARDEN is down with it: people handle incidents by hand until it is back.

## 6. Bring it back

All deploys go through `.github/workflows/runtime.yml`, run by hand from the branch `dev` into the GitHub Environment
`ops`, which needs its reviewer's approval. Choose the action:

| Situation | Action |
|---|---|
| A secret was set or rotated; a zone is stuck | `restart`: a fresh deployment of every zone's service, the same image; fails unless all are stable again |
| The shared `warden/ops/temporal-api-key` was set or rotated | `restart` for the zones, **and** new instances of the three front door Lambdas that read it - a warm one keeps the old key. Any change to a function's configuration makes Lambda start new instances (AWS's Lambda guide; not tried live); a new description does it, and the next `apply` sets it back. Run the commands below the table, and stop if a wait fails |
| The runtime was paused | set SSM `/warden/ops/tf/paused` to `false`, then `apply` |
| Infrastructure drifted or was changed by hand | `plan`, read it, then `apply` |
| A bad image | `apply` from a `dev` commit whose image works (only an image this workflow built, signed and attested is deployed) |

After a rotation of the shared key, for each front door Lambda in turn:

```
aws lambda update-function-configuration --function-name warden-ops-alarm --description "temporal key rotated <UTC time>"
aws lambda wait function-updated --function-name warden-ops-alarm
aws lambda update-function-configuration --function-name warden-ops-alertmanager --description "temporal key rotated <UTC time>"
aws lambda wait function-updated --function-name warden-ops-alertmanager
aws lambda update-function-configuration --function-name warden-ops-approval --description "temporal key rotated <UTC time>"
aws lambda wait function-updated --function-name warden-ops-approval
```

Without GitHub Actions, one zone can be restarted from the AWS CLI (same task definition, no new image):

```
aws ecs update-service --cluster warden-ops-runtime --service warden-ops-core --force-new-deployment
```

To put `act` back after section 4 set it to 0, use the count the stack sets: the value of SSM
`/warden/ops/tf/worker_instances`, or 2 when that parameter does not exist (the stack's default).

```
aws ssm get-parameter --name /warden/ops/tf/worker_instances --query Parameter.Value --output text
aws ecs update-service --cluster warden-ops-runtime --service warden-ops-act --desired-count <worker-instances>
```

## 7. After it is back

1. `warden-ops-heartbeat-missing` is OK again; every zone's running count equals its desired count, and no zone's
   desired count is 0 (`warden-ops-act` included, if section 4 stopped it); SSM `/warden/ops/tf/paused` is `false`.
2. The kill switch is in the state you expect. For the cloud runtime the approval page shows it, and every trip,
   on a link your own key signs:

   ```
   warden killswitch link --approver <your-id> --key ~/.warden/<your-id>.pem
   ```

   (`warden killswitch status` reads only an audit this machine reaches.) Reset it only with your passkey on that
   page, after reading every trip it lists ([RUNBOOK-WARDEN-INCIDENT.md, section 4](RUNBOOK-WARDEN-INCIDENT.md#4-after-the-incident)).
3. The record is whole:

   ```
   warden audit verify --db <audit.db> --public-key <audit.pub> --anchor-bucket <bucket>
   ```

4. Every message in `warden-ops-alarm-dlq` was handled by a person, then deleted (section 3, step 2), and the
   queue is empty: all three counts below are `0` - messages waiting, messages received but not yet deleted (in
   flight, hidden for up to 15 minutes), and delayed ones. If any is not `0`, wait for the hidden ones to show again
   and handle them:

   ```
   aws sqs get-queue-attributes --queue-url <queue-url> --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible ApproximateNumberOfMessagesDelayed
   ```

   The counts are approximate: treat the queue as clear only when two checks at least 15 minutes apart both show `0`
   for all three. WARDEN does not replay these messages itself. (The `alarm` Lambda takes the same EventBridge
   event, so it can be invoked by hand with a message's body; this has not been tried live.)
5. Alarms that went into ALARM during the outage and are still in ALARM: CloudWatch sends a change only once, so
   WARDEN will not see them again until they change state. Handle them by hand.
6. Write down what happened (times in UTC and IST, what was down, how long, which incidents people handled) and add
   anything new to [the failure-mode register](FAILURE-MODES.md) with a test.
