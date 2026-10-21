# Data retention: what WARDEN keeps, where, and for how long

This page lists every place WARDEN's cloud runtime writes data, read from the code and the Terraform as they are on
`main` today ([the runtime module](../terraform/modules/warden-runtime/), [its root](../terraform/runtime/main.tf),
[audit.py](../src/warden/audit.py), [activities.py](../src/warden/activities.py)). Where a value is set per install
(in SSM Parameter Store under `/warden/<env>/tf/`), the table gives the module's default and says so. Anything not
built yet is marked **planned**.

## In short

- **The audit is kept forever.** WARDEN only ever adds rows to it; no code deletes or changes one, and the hash chain
  and signatures would show it if anything did. Removing old rows is a person's decision, made by hand.
- **Logs are kept 90 days**, the lost-alarm queue 14 days.
- **The audit's tamper-proof copies** (checkpoint anchors) and AWS's own record (the CloudTrail witness) cannot be
  deleted by anyone, the account's root included, for `anchor_retention_days` - **1 day by default today**. Raising
  every audit retention to at least 180 days is **planned** (B19, in progress).
- WARDEN does not send its data anywhere but the places below.

## What is stored where

| Data | Where | Kept for | Set in |
|---|---|---|---|
| The audit: every incident's alarm (its text redacted), the evidence exactly as the model was shown it (redacted, untrusted text reduced to facts), the diagnosis, its checks, every plan, approval, refusal, change, check, rollback and kill-switch trip, and who approved what | The audit database `warden-<env>-audit`, encrypted at rest: an Aurora PostgreSQL cluster, or one RDS PostgreSQL instance on the AWS Free plan; on a laptop, a SQLite file (`WARDEN_AUDIT_DB`, default `~/.warden/audit.db`) | Until a person deletes it: nothing in WARDEN removes a row | [audit.py](../src/warden/audit.py) |
| The model's prompts and answers | Not stored as text. The diagnosis row keeps SHA-256 hashes of the system text, the prompt and the answer, with the model id and version | As the audit | [graph.py](../src/warden/graph.py) `node_diagnose` |
| Discussion in Slack | The audit keeps who asked (Slack user id), when, the channel and thread, the question's length and what WARDEN's answer cited - not the words of the question or the answer | As the audit | [activities.py](../src/warden/activities.py) `discuss.*` rows |
| Spend on the model | Calls, tokens, cost and each request's time in milliseconds per incident, in the audit | As the audit | `incident.llm_spend` rows (`latency_ms`: one entry per request, retries included); Eldane's `eldane.call` rows (`latency_ms`) |
| Audit backups | The audit database's automated backups, with point-in-time recovery | `audit_db_backup_days`: 7 by default and at least 7, except 1 allowed on the AWS Free plan | [aurora.tf](../terraform/modules/warden-runtime/aurora.tf), [variables.tf](../terraform/modules/warden-runtime/variables.tf) |
| The audit's final snapshot | Taken when the audit database is deleted (`warden-<env>-audit-final`) | Until a person deletes it | [aurora.tf](../terraform/modules/warden-runtime/aurora.tf) |
| Checkpoint anchors (a signed hash of the audit at a point) | S3 bucket `warden-<env>-anchors-...`, Object Lock in COMPLIANCE mode, versioned, KMS-encrypted | Locked for `anchor_retention_days` (default 1); no lifecycle rule, so kept after that until someone deletes them | [anchors.tf](../terraform/modules/warden-runtime/anchors.tf) |
| CloudTrail witness (AWS's own record of the account's management events, including every actor-role session and audit signature) | Trail `warden-<env>-witness`, S3 bucket `warden-<env>-witness-...`, Object Lock in COMPLIANCE mode, log file validation on | Locked for `anchor_retention_days` (default 1); no lifecycle rule | [witness.tf](../terraform/modules/warden-runtime/witness.tf) |
| Worker logs (all five zones) | CloudWatch Logs `/warden/<env>/worker` | 90 days | [compute.tf](../terraform/modules/warden-runtime/compute.tf) |
| Lambda logs | CloudWatch Logs `/aws/lambda/warden-<env>-<name>` (alarm, alertmanager, approval, actor-use, migrate) | 90 days | [frontdoor.tf](../terraform/modules/warden-runtime/frontdoor.tf), [migrate.tf](../terraform/modules/warden-runtime/migrate.tf) |
| Approval and records page access log: request id, the caller's IP address, time, method, route, status, size, latency | CloudWatch Logs `/aws/vendedlogs/warden-<env>-front-access` | 90 days | [frontdoor.tf](../terraform/modules/warden-runtime/frontdoor.tf) |
| Alarm changes that never reached WARDEN | SQS queue `warden-<env>-alarm-dlq` | 14 days | [frontdoor.tf](../terraform/modules/warden-runtime/frontdoor.tf) |
| Workflow state (each incident's and each fix's steps) | Temporal Cloud. Every payload is encrypted by WARDEN's codec before it leaves the worker, so Temporal holds only ciphertext | The Temporal Cloud namespace's retention, set in Temporal Cloud, outside this repository | [codec.py](../src/warden/codec.py) |
| Who may approve: names, public keys, enrolled passkeys' public keys, tiers, Slack user ids | SSM Parameter Store `/warden/<env>/approvers` (nothing in it is secret); every change of it is recorded in the audit | Until changed | [runtime_base.py](../src/warden/runtime_base.py) |
| Secrets (model key, Temporal keys, Slack and GitHub tokens, webhook secrets) | AWS Secrets Manager, `warden/<env>/<name>` | Until replaced; a deleted secret can be restored for 7 days | [secrets.tf](../terraform/modules/warden-runtime/secrets.tf) |
| The audit's signing key | AWS KMS; it never leaves KMS | A key scheduled for deletion waits 30 days | [kms.tf](../terraform/modules/warden-runtime/kms.tf) |
| Approvers' break-glass keys (Ed25519) | The approver's own machine (`WARDEN_KEY_DIR`, default `~/.warden`) | The approver's choice | [audit.py](../src/warden/audit.py) |

## What leaves WARDEN

| Destination | What is sent | Who keeps it, and for how long |
|---|---|---|
| The model provider (Anthropic) | The redacted evidence and the question, for each diagnosis, review or chat answer | The provider, under its own terms; WARDEN does not set it |
| Slack | Reports, approval requests (a link, never the plan's secrets), answers in the discussion channel | The Slack workspace's retention settings |
| GitHub | One issue per applied change (the change record), with the plan's hash and the audit's head | Until someone deletes the issue |
| The page topic (SNS) | WARDEN's own alarms about itself | Delivered and not kept by WARDEN |

Every text that leaves goes through the outbound gate first ([gate.py](../src/warden/gate.py)), which removes
secrets it recognises and withholds a message that still carries one. Masking works from known patterns: a secret in
a format no pattern knows is not caught.

## Deleting data

- **One incident.** Not built: the audit is append-only and its hash chain would break. Removing data from it means
  rebuilding the chain and its anchors by hand. Planned only if a legal need arises.
- **Everything.** Tearing down the runtime with Terraform deletes the logs, the queue, the services and the Lambdas.
  The audit database has deletion protection and leaves a final snapshot; the anchor and witness buckets cannot be
  emptied until their objects' lock ends. Secrets wait 7 days and the KMS key 30.

## Planned

- At least 180 days of audit retention (B19, in progress). For the audit database's backups the owner decided on
  2026-10-20: automated backups raised to 35 days, plus one AWS Backup copy a month kept 180 days, in a vault in the
  same Region with an AWS-managed key, no copy to another Region, and a switch to turn it off. This page will be
  updated with the built values when that change merges.
