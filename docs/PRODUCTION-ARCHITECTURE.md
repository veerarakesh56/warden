# How WARDEN runs in AWS

In the cloud, WARDEN is a set of services, each with its own machine identity. It starts when an alarm
fires, holds no person's credentials and no long-lived access key, and pages a person when it cannot do
its job. Everything on this page is defined in `infra/terraform/runtime` (the network and the environment's
settings) and `infra/terraform/modules/warden-runtime` (the services). How the pieces fit inside the code is in
[`ARCHITECTURE.md`](ARCHITECTURE.md); every outside component and its price is in
[`SYSTEM-COMPONENTS.md`](SYSTEM-COMPONENTS.md); setting it up is in [`SETUP.md`](SETUP.md).

**Design principle: Meta's "Agents Rule of Two."** An agent should have at most two of three properties:
it reads untrusted input, it reaches sensitive data, it changes state. WARDEN has the first two, and
changes state **only through a signed human approval** of an exact plan. Detectors are tripwires, never
gates: published adaptive attacks beat every detector, so the architecture carries the protection.

## The loop

```
 CloudWatch alarms (state ALARM)          Prometheus Alertmanager
      |                                         |
 EventBridge rule (retries, then a              API Gateway HTTP API (throttled)
 dead-letter queue that pages)                  |  bearer secret, size caps, still-firing check
      |                                         |
      +--> alarm Lambda --> intake <-- alertmanager Lambda
                  groups repeats, holds expected-down alarms, sends flapping alarms
                  and storms to a person, caps open incidents
      |
 Temporal Cloud namespace
      |  one API key per trust zone; every payload AES-256-GCM encrypted by WARDEN (codec.py)
      |
      +--> core worker    the workflows, verify, the gate, the signed audit
      +--> read worker    that environment's reader role, per incident (SourceIdentity = inc-<id>)
      +--> llm worker     the model API key only; redacted, typed facts in; 6 calls and US$0.25 per incident
      +--> notify worker  Slack (one message per incident), change records; PagerDuty, Teams, webhooks if set
      +--> act worker     no standing role; a per-plan actor session of at most 900 s
      ^
 Slack button --> approval page (API Gateway + Lambda on <your-domain>)
                  Sign in with Slack, then a passkey (WebAuthn) over the exact plan hash
                  --> a signal to the RemediationWorkflow, which re-verifies it
```

## When it starts

- **Automatically.** A CloudWatch alarm of a watched environment enters ALARM; an EventBridge rule hands
  it to the alarm Lambda, which goes through intake. Alertmanager posts to the HTTP API. A service's own
  failure events (for example an ECS service's error events or an RDS failover) are read the same way.
  Nothing polls.
- **By hand.** An engineer or another agent can start a diagnosis through the MCP tools or the CLI.

## What is deployed

| Part | Resource |
|---|---|
| Network | a VPC over two availability zones: private subnets for the workers, the Lambdas and the audit database; one NAT gateway by default (`nat_gateways = 2` for production); a free S3 gateway endpoint |
| Workers | ECS on Fargate, one service per trust zone, in the private subnets |
| Front door | Lambdas behind EventBridge (alarms, service events, actor-role use) and an API Gateway HTTP API (Alertmanager, the approval page), all from the one runtime image. Each Lambda has its own role, `warden-<env>-<name>-lambda`, reading exactly the secrets its handler reads (`settings.LAMBDA_SECRETS`): the internet-facing approval page cannot read the webhook's Datadog keys, and actor-use reads none |
| WARDEN's record | Aurora PostgreSQL Serverless v2 (scales to zero and pauses after an hour idle); the schema and an append-only writer login are created by a migrate Lambda after each apply |
| Audit signing | an AWS KMS Ed25519 key that only the signer may use; each checkpoint is also written to an S3 bucket under Object Lock (COMPLIANCE mode) |
| Witness | a CloudTrail trail of management events into its own Object Lock bucket: the record WARDEN does not write |
| Health | a heartbeat alarm that pages when the workers' round trips through Temporal stop, and a daily synthetic incident through the whole diagnosis path that pages when it fails |
| Pause | `/warden/<env>/tf/paused = true` removes compute, the NAT route and alarm intake between uses; the data stays |

The runtime is one deployment, the `ops` environment, that watches the application environments listed in
`watched_environments`. It is deployed by its own manual pipeline (`.github/workflows/warden-runtime-deploy.yml`).

## How each part gets access (no keys anywhere)

- **Workers** each have their own ECS task role. AWS issues short-lived credentials and rotates them.
- **Per incident**, the read worker assumes that environment's reader role with `SourceIdentity=inc-<id>`.
- **Per approved plan**, the act worker receives an actor session (`identity.py`): at most 900 seconds,
  session tags naming the approvers, the incident and the plan, and a session policy that allows only the
  plan's actions on the plan's exact resources. An EventBridge rule on CloudTrail sends every use of an
  actor role to the `actor-use` Lambda, which pages if the audit shows no approval for it.
- **Configuration** lives in SSM Parameter Store under `/warden/<env>/`. **Every secret** lives in Secrets
  Manager as `warden/<env>/<name>`. Terraform creates the empty slots; a person sets each value, so no
  secret value is ever in Terraform state. Each worker reads only its own zone's secrets.
- **The audit database** is reached as `warden_audit_writer`, which may only SELECT and INSERT and signs in
  with an IAM token, not a password.
- **CI** has no AWS keys. GitHub's OIDC token is exchanged for a per-environment deploy role
  (`infra/iam/templates`).

## Human approval

- **Tiers.** T1: one small, reversible change to one resource. T2: service-level, reversible. T3:
  irreversible, IAM, network or Terraform.
- **Every tier needs a signed approval of the exact plan.** On the approval page the person signs in with
  Slack, proves it with a passkey, and for T2 and T3 types the target before signing. T3 also needs a
  cooling-off time and a device-bound passkey.
- **More than one approver.** The approver list can require approvals from different people per tier.
  With a single approver, one person decides a change alone; the records say so.
- **Break-glass.** `warden approve` with the approver's Ed25519 key.

## The model

The llm worker calls **Claude Sonnet 5.5 (`claude-sonnet-5-5`) through the Anthropic API**, with the key
read from Secrets Manager (`warden/<env>/anthropic-api-key`). That is the code's default
(`warden/src/warden/data/providers.yaml`: provider `anthropic`, default model `claude-sonnet-5-5`); an install can
choose another provider and model with `/warden/<env>/tf/model_provider` and `/warden/<env>/tf/model`.
The code also supports Amazon Bedrock, Gemini and OpenAI-compatible endpoints, but the runtime module
grants no Bedrock access and creates no slot for another provider's key (owner, 2026-10-09: the Anthropic API
only); a slot comes back only with a zone that reads it.

A model is used only after it passes WARDEN's replay qualification on recorded incidents, never because of
a public leaderboard; the deploy refuses a model that is not on the qualified list. The results are in
[`BENCHMARKS.md`](../warden/docs/BENCHMARKS.md). The model sees only redacted, typed facts. Each incident may make at most
6 model calls and spend at most US$0.25 in the cloud, and a daily cap applies across incidents.

If there is no model, the budget is spent, or the provider is down, WARDEN produces a **rules-only report
and hands the incident to a person** instead of guessing.

## Observability and records

- **One correlation id**, `inc-<id>`, runs through the workflow, the STS session's SourceIdentity, the
  signed audit, the Slack message and the PagerDuty `dedup_key`.
- **Records pages** on the approval page's domain show every incident, its plan, who approved or denied it
  and how it ended, read from the signed audit.
- **Change records.** Each applied change can open a GitHub issue (`WARDEN_CHANGE_REPO`).
- **Tracing.** OpenTelemetry spans for each run; send them to any OTLP collector.

## Operations

[`OPERATIONS.md`](../warden/docs/OPERATIONS.md) covers rotating every secret and key.
[`RUNBOOK-WARDEN-INCIDENT.md`](../warden/docs/RUNBOOK-WARDEN-INCIDENT.md) covers what to do when WARDEN itself is the
incident.

## Limits

- **It has been run in one AWS account.** Environments are separated by name (`warden-<env>-*`), the
  `Environment` tag, the parameter path and a permissions boundary per environment. Separate accounts per
  environment are the stronger setup; that has not been tried.
- **The Temporal codec server is not built.** The Temporal web UI therefore shows payloads as encrypted.
- **No automatic tier.** Every fix needs a person, in every environment, until measured shadow results earn
  an automatic tier; none has.
