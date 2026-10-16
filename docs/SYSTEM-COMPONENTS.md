# Outside components and their cost

Every component WARDEN relies on that it did not write, what it is used for, and what it costs. Choices are
made on quality first; a paid component is used when it is the right production choice, and its price is
listed. AWS prices are for ap-south-2 (Hyderabad) unless marked otherwise; check them for your own region.

Status: **IN USE** (the code uses it by default or in the cloud runtime) · **SUPPORTED** (works when you
configure it) · **OPTIONAL** (an extra you can turn on).

## 1. The model

| Component | Used for | Status | Notes |
|---|---|---|---|
| Anthropic API, Claude Sonnet 5.5 (`claude-sonnet-5-5`) | the diagnosis | IN USE | the default provider and model (`src/warden/data/providers.yaml`); key from Secrets Manager |
| Anthropic API, Claude Opus 5.5 | the diagnosis | SUPPORTED | measured below WARDEN's qualification bar on 2026-10-15, so refused until it passes |
| Amazon Bedrock | the diagnosis, inside AWS | SUPPORTED | `WARDEN_PROVIDER=bedrock` with an inference-profile id; must pass the qualification first |
| Google Gemini, OpenAI-compatible endpoints (Groq, OpenRouter, local Ollama) | the diagnosis | SUPPORTED | must pass the qualification first |
| `claude` CLI | local development and benchmarks | SUPPORTED | a subscription instead of API credit; never in the cloud runtime |

## 2. Orchestration and agent interface

| Component | Used for | Status |
|---|---|---|
| Temporal Cloud and the `temporalio` SDK | durable incident and remediation workflows, approvals as signals, timers, retries | IN USE |
| Temporal dev server (MIT) | local runs and tests | IN USE (local) |
| MCP Python SDK (MIT) | WARDEN's tools for other agents | IN USE |

## 3. Guardrails and safety

| Component | Used for | Status |
|---|---|---|
| WARDEN's own verifier, grounding, quarantine and outbound gate | the deterministic decision; untrusted text as typed facts; nothing unsafe leaves | IN USE |
| Meta Llama Prompt Guard 2 (Meta community licence, gated download) | an extra injection tripwire on untrusted lines, run locally | OPTIONAL (`WARDEN_TRIPWIRE`) |
| py_webauthn (BSD-3-Clause) | verifying passkey approvals | IN USE |
| `cryptography` | Ed25519 signatures, AES-256-GCM payload encryption | IN USE |
| `markdown-it-py` | CommonMark parsing in the outbound gate | IN USE |

## 4. Identity, access and secrets

| Component | Used for | Status | Cost |
|---|---|---|---|
| AWS IAM and STS | task roles, per-incident reader sessions, per-plan actor sessions, permissions boundaries | IN USE | free |
| GitHub OIDC to AWS | CI and deploys with no AWS keys | IN USE | free |
| SSM Parameter Store, standard tier | plain per-environment configuration (`/warden/<env>/`) | IN USE | free up to 10,000 parameters |
| AWS Secrets Manager | every secret (`warden/<env>/<name>`) | IN USE | priced below |
| AWS KMS (Ed25519) and S3 Object Lock | audit signing and its external anchors | IN USE | priced below |
| Slack OpenID Connect sign-in | which person is at the approval page | IN USE | free |

## 5. Supply chain and code security

| Component | Status | Cost |
|---|---|---|
| pip-audit, bandit, zizmor (CI) | IN USE | free |
| Dependabot (with a cooldown), actions pinned to commit SHAs | IN USE | free |
| cosign keyless signing of the runtime image | IN USE | free |
| `scripts/check_publishable.py` (WARDEN's own secret and account-id scanner) | IN USE | free |
| CodeQL (GitHub's default setup) | IN USE | free on public repositories |
| GitHub secret scanning and push protection | OPTIONAL | free on public repositories |

## 6. Evidence sources and observability

| Component | Used for | Status | Cost |
|---|---|---|---|
| CloudWatch metrics, alarms and Logs (incl. Logs Insights) | evidence; alarms start incidents | IN USE | priced below |
| CloudTrail event history and a management-event trail | which change came before the alarm; the witness of actor sessions | IN USE | event history free; trail priced below |
| RDS Performance Insights (API) | database load by wait type | IN USE | priced below |
| AWS X-Ray | trace summaries for the incident's service | SUPPORTED | priced below |
| Datadog (Logs, Spans, metrics) | evidence from a company's Datadog; the one observability tool WARDEN's own runtime reads (owner: Datadog only) | SUPPORTED | your Datadog plan |
| Grafana Loki, Tempo, Prometheus | evidence from a company's Grafana stack; not in WARDEN's own runtime (no secret slot), set in the process environment by an adopter | SUPPORTED | your Grafana plan |
| OpenTelemetry | WARDEN's own traces | IN USE | free |

## 7. Notifications and records

| Component | Status | Cost |
|---|---|---|
| Slack (bot messages; Socket Mode for the discussion channel) | IN USE | free tier is enough |
| Microsoft Teams and generic webhooks | SUPPORTED | free |
| PagerDuty Events API v2 | SUPPORTED | priced below |
| GitHub Issues, one per applied change | SUPPORTED | free |

## 8. Infrastructure

| Component | Used for | Status |
|---|---|---|
| Terraform (BUSL; OpenTofu is the open alternative) | all AWS infrastructure | IN USE |
| Helios (Apache-2.0) | checks Terraform plans before apply in the infra pipeline | IN USE |
| ECS on Fargate, Aurora PostgreSQL Serverless v2, Lambda, API Gateway, EventBridge, NAT gateway | the cloud runtime (see `PRODUCTION-ARCHITECTURE.md`) | IN USE |

## 9. Prices

Read on the dates shown. AWS prices come from AWS's Price List files for ap-south-2
(`pricing.us-east-1.amazonaws.com/offers/v1.0/aws/<Service>/current/ap-south-2/index.json`) unless the
row says otherwise; other vendors from their own pricing pages. **UNCERTAIN** marks anything the source did
not state plainly. Most rows were read on 2026-09-28; check each before you rely on it.

| Component | Price | Notes |
|---|---|---|
| Anthropic API, Claude Sonnet 5.5 | $2 input / $10 output per 1M tokens (read 2026-10-15) | the default model; an incident in the cloud may spend at most US$0.25 |
| Anthropic API, Claude Opus 5.5 | $4 input / $20 output per 1M tokens (read 2026-10-15) | supported, not qualified |
| Temporal Cloud, Actions | $50 per 1M; volume tiers down to $25 per 1M | temporal.io/pricing, docs.temporal.io/cloud/pricing |
| Temporal Cloud, storage | active $0.042/GBh; retained $0.00105/GBh | |
| Temporal Cloud, plans | Developer: no base fee; Business: greater of $500/month or 10% of usage | UNCERTAIN: the docs attach "10% of usage" to Developer; the pricing page says "no base monthly fee" |
| Temporal Cloud, High Availability | 2x Actions and storage | docs; the pricing page shows no price |
| Temporal Cloud, trial | $150 credits for 90 days | for a new account |
| Aurora PostgreSQL Serverless v2 | $0.18 per ACU-hour (I/O-Optimized: $0.24) | auto-pause to 0 ACU on PostgreSQL 16.3, 15.7, 14.12, 13.15 or later; storage is still billed while paused; resume takes about 15 s |
| Aurora storage and I/O | $0.11/GB-month + $0.22 per 1M I/O (I/O-Optimized: $0.248/GB-month, no I/O charge) | backup beyond the free allowance: $0.023/GB-month |
| ECS on Fargate | per vCPU-hour and per GB-hour | UNCERTAIN: not re-read for this page; check the Fargate pricing page for your region |
| NAT gateway | $0.056/h + $0.056/GB processed | billed per AZ |
| VPC interface endpoint (PrivateLink) | $0.013 per endpoint per AZ per hour + $0.01/GB | gateway endpoints (S3, DynamoDB) are free |
| KMS | $1 per key per month; asymmetric requests $0.15 per 10k; 20k requests/month free | UNCERTAIN: Ed25519 (ECC_NIST_EDWARDS25519) is not named on the page |
| Secrets Manager | $0.40 per secret per month + $0.05 per 10k calls | |
| CloudTrail | first copy of management events to S3: free; data events $0.10 per 100k | the S3 storage is billed separately |
| S3 Standard | $0.025/GB-month (first 50 TB) | Object Lock has no separate SKU; retained versions are billed as storage |
| CloudWatch Logs | $0.67/GB ingested; $0.03/GB-month stored | 5 GB free |
| CloudWatch Logs Insights | $0.005 per GB scanned (list price, read 2026-10-03) | WARDEN runs one query per log group per incident, over the alert time +/- 15 min. UNCERTAIN: the ap-south-2 rate was not stated |
| RDS Performance Insights (API) | free: 7 days of data and 1M API requests a month (read 2026-10-03) | WARDEN reads `db.load` by wait-event type per Aurora member. Longer retention is CloudWatch Database Insights, paid, not used |
| CloudWatch metrics and alarms | $0.30 per custom metric-month; $0.10 per standard alarm-month | 10 of each free |
| CloudWatch GetMetricData | $0.01 per 1,000 metrics requested; no free tier (read 2026-10-03) | every evidence read of a metric; a few dozen per incident |
| CloudWatch API requests | $0.01 per 1,000 requests after 1 million free a month (read 2026-10-10) | ListMetrics, DescribeAlarms and DescribeAlarmHistory: a few per incident. CloudTrail LookupEvents is free (event history) |
| S3 requests | $0.0004 per 1,000 GET requests, S3 Standard (read 2026-10-10; AWS's page does not say how a bucket-configuration read is classed - taken as GET) | GetBucketVersioning: the state read of an alarmed bucket, one per incident |
| SQS requests | $0.40 per 1M (standard queues); first 1M a month free (read 2026-10-03) | the evidence reader's queue reads |
| SNS requests | $0.50 per 1M API requests; first 1M a month free (read 2026-10-03) | the evidence reader's subscription list |
| X-Ray | $5 per 1M traces stored; $0.50 per 1M retrieved | 100k stored free |
| API Gateway HTTP API | $1.05 per 1M requests | |
| Lambda | $0.20 per 1M requests + $0.0000166667 per GB-second (Arm: $0.0000133334) | 1M requests and 400k GB-s free |
| EventBridge | AWS events on the default bus: free; custom events $1.00 per 1M | UNCERTAIN: Scheduler is $1.54 per 1M in the ap-south-2 Price List vs $1.00 in the page example |
| PagerDuty | Free (up to 5 users); Professional $25/user/month ($21 annual) | |

**What it costs to run.** While the runtime is up, the hourly costs are mainly the NAT gateway, the
Fargate tasks (one per trust zone) and Aurora when it is not paused. Fixed costs while the resources exist
are the KMS key, the Secrets Manager secrets, and Aurora and S3 storage. Model tokens are on top, capped
per incident and per day. Pausing the runtime (`/warden/<env>/tf/paused = true`) removes the compute and
the NAT route between uses.
