# Every outside component of the WARDEN system: free, paid, and the free alternative

Sections 1-9 were checked on 2026-09-27, under the earlier rule of **free or open-source only**. The
owner replaced that rule on 2026-09-28 with **quality first** (section 10). **Section 11 has the live
prices, checked 2026-09-28 UTC / 2026-09-29 IST, for the components chosen since.** Where a row in sections 1-9 disagrees
with sections 10-11, sections 10-11 win.

AWS prices are US list prices, and ap-south-2 can differ. The AWS Free plan is USD 200 of credits
over 6 months; "PAID" in AWS rows means it spends those credits.

Status: **IN USE** today · **PLANNED** (v2 plan phase) · **OPTIONAL** (free, adopt later if wanted) ·
**NOT USED** (paid, replaced by the free alternative shown).

## 1. The AI itself

| Component | What it does for WARDEN | Status | Cost | Free alternative / note |
|---|---|---|---|---|
| Claude via the `claude` CLI on Claude Max | the one diagnosis call per incident | IN USE | owner's flat subscription; no per-call cost | — |
| Anthropic API | same model, pay per token | pluggable, not used | PAID per token | Claude Max CLI |
| Google Gemini API | alternative model | pluggable (key test pending) | free tier with rate limits, then PAID | — |
| OpenAI-compatible (Groq, local Ollama) | alternative models | pluggable | Groq free tier; Ollama free, runs locally (needs RAM) | — |
| Amazon Bedrock | alternative models on AWS | one smoke test later | PAID per token | Claude Max CLI |

## 2. Orchestration: "AI decides what, workflow controls how"

| Component | Role | Status | Cost | Paid thing it replaces |
|---|---|---|---|---|
| **Temporal** (MIT), self-hosted dev server | durable incident / remediation / infra workflows; approvals as signals; retries; timers | IN USE: RemediationWorkflow (Phase 2, step 5) | FREE | Temporal Cloud (PAID); Kestra Enterprise (PAID; Kestra OSS is also free) |
| LangGraph (MIT) | the old pipeline graph | REMOVED in Phase 2 (the same nodes run as Temporal activities) | FREE | — |
| MCP Python SDK (MIT) | WARDEN's tools exposed to agents (the Kestra "flows as agent tools" pattern) | IN USE; becomes the workflow surface in Phase 2 | FREE | — |

## 3. Guardrails, grounding, safety

| Component | Role | Status | Cost | Paid thing it replaces |
|---|---|---|---|---|
| WARDEN verifier P1–P16 (own code) | deterministic gate: the model never decides | IN USE | FREE | — |
| Quarantine + evidence ids + grounding (own code) | untrusted text reaches the model only as typed facts; every claim cites evidence | IN USE | FREE | Lakera Guard (PAID SaaS), Azure Prompt Shields (PAID) |
| Outbound gate G2/G3/G5 (own code) | strips links and images, blocks leaked secrets, marks unverifiable claims | IN USE | FREE | ZeroDrift Anchor (PAID SaaS) |
| Decision component `decide.py` (own code, scikit-learn BSD) | calibrated "is this answer right?" | PLANNED, Phase 3 | FREE | TypeSafe Jev / System One (PAID) |
| Llama Prompt Guard 2 (Meta community licence, gated download) **or** PIGuard (MIT) | extra injection tripwire on log lines | OPTIONAL | FREE; big CPU model download | Lakera / Azure (PAID) |
| Microsoft Presidio (MIT) | better personal-data detection than regex | OPTIONAL | FREE | — |
| HHEM-2.1-open (Apache-2.0) | checks a claim against its cited evidence | OPTIONAL | FREE (the newer HHEM-2.3 is PAID) | — |

## 4. Evals and red-teaming

| Component | Role | Status | Cost |
|---|---|---|---|
| Own replay tool (`scripts/replay_diagnose.py`) + frozen rubrics | same evidence, today's pipeline, scored | IN USE | FREE |
| Own injection corpus (`tests/test_injection_corpus.py`) | 14 payload families, every CI run | IN USE | FREE |
| Inspect AI (MIT, UK AISI) + AgentDojo | pass^k evals, public injection benchmark | PLANNED, Phase 3 | FREE |
| garak (Apache-2.0) | more attack payloads for the corpus | OPTIONAL | FREE |
| promptfoo red team | adaptive attacks | NOT USED: remote generation by default, OpenAI-owned | free core |

## 5. Identity, access, secrets

| Component | Role | Status | Cost | Paid alternative avoided |
|---|---|---|---|---|
| AWS IAM, STS, permissions boundary | least privilege; just-in-time 15-minute roles in Phase 4 | IN USE / PLANNED | FREE | Teleport Enterprise (PAID). Teleport Community is free but heavy to self-host |
| GitHub OIDC → AWS role | CI has no AWS keys at all | IN USE | FREE | — |
| **IAM Roles Anywhere** (own CA; certificate in the Windows store via `aws_signing_helper`) | replaces the laptop's long-lived access key, with no password (the owner rejected console passwords) | PLANNED (W0-now, owner steps prepared; TPM key and certificate made 2026-09-28) | FREE ("no additional cost", AWS, checked 2026-09-28) | IAM Identity Center is **not possible** in this lab: it needs AWS Organizations, which ends the Free plan |
| IAM Access Analyzer, **external access** | finds anything reachable from outside the account | IN USE (created 2026-09-27) | FREE. Its unused-access and internal-access types are PAID; not used | — |
| **SSM Parameter Store, standard tier** | per-environment **plain configuration** (not secrets) | IN USE (Terraform reads `/warden/<env>/tf/*`; `settings.py` loader) | FREE (up to 10,000 parameters) | — |
| **AWS Secrets Manager** | **every secret and sensitive value**: Slack tokens and webhooks, the Temporal API keys and payload key, the audit-key passphrase, DB credentials, model keys (owner decision D5, 2026-09-28) | PLANNED (G3 loader, W0-now owner step) | **PAID, ≈ $0.40 per secret per month** plus API calls; accepted by the owner for quality | — |
| GitHub Environments + environment variables | per-environment CI config (one environment per AWS environment, plus `ops` for WARDEN's own runtime); required reviewers for prod tiers | CODE READY (`infra.yml`/`apps.yml` take an environment input); environments not created yet | FREE on a public repo | — |
| GitHub secret scanning + push protection | blocks a pushed secret | available | FREE on public repos | — |
| Ed25519 signed, hash-chained audit (`cryptography`, SQLite) | tamper-evident audit: `src/warden/audit.py`, `warden audit keygen` and `verify` | IN USE (Phase 2, step 1) | FREE | KMS signing, S3 Object Lock (PAID; not used) |

## 6. Supply chain and code security

| Component | Status | Cost |
|---|---|---|
| pip-audit, bandit, zizmor (CI `security` job) | IN USE | FREE |
| Dependabot (7-day cooldown), actions pinned to commit SHAs | IN USE | FREE |
| `scripts/check_publishable.py` (own secret/account-id scanner) | IN USE | FREE |
| CodeQL | OPTIONAL | FREE on public repos (PAID on private) |
| gitleaks CLI | OPTIONAL | FREE |
| OpenSSF Scorecard | OPTIONAL | FREE |

## 7. Observability and "which change broke it"

| Component | Role | Status | Cost | Paid thing it replaces |
|---|---|---|---|---|
| OpenTelemetry (Apache-2.0) | traces of every run: cost, verdict, policies | IN USE | FREE | Datadog / New Relic (PAID) |
| CloudWatch metrics and logs | evidence WARDEN reads | IN USE in test windows | logs: 5 GB/month free, then PAID per GB | — |
| **CloudTrail event history** | who changed what in AWS, 90 days | PLANNED (change timeline) | FREE | CloudTrail Lake, AWS Config (PAID; never enabled) |
| CloudTrail trail → S3 (management events) | long-term copy, feeds EventBridge | PLANNED, Phase 4 window | cents per month | — |
| EventBridge rules → CloudWatch Logs `/warden/changes` | one change log: deploys, AWS Health, infra writes | PLANNED, Phase 4 window | AWS events free; within the logs free tier | — |
| GitHub Deployments + a commit stamp on images, tags, Lambda versions, k8s labels, OTel `vcs.*` | links a production change to its PR | PLANNED, Phase 2–3 | FREE | Cursor Rollouts (PAID, $40 per user per month) |
| kubernetes-event-exporter (Apache-2.0) | keeps k8s events (they expire after about 1h) | PLANNED when EKS is up | FREE | Robusta change tracking (PAID) |
| GlitchTip (MIT) | error tracking per release | OPTIONAL later | free, needs a small always-on box | Sentry SaaS (PAID); Sentry self-hosted needs 16 GB RAM |
| Grafana OSS, Loki, SigNoz, Apache DevLake | dashboards, DORA metrics | NOT NOW: each needs an always-on server | free software, server costs credits | — |
| EKS control-plane audit logs | — | **kept OFF** | PAID (GBs per day at $0.50/GB) | CloudTrail + k8s event exporter |

## 8. Infrastructure and infra policy

| Component | Role | Status | Cost |
|---|---|---|---|
| Terraform (BUSL, free to use) | all AWS infrastructure | IN USE | FREE; OpenTofu (MPL-2.0) is the fully open alternative |
| **Helios** (owner's own; Rust + Z3, Apache-2.0) | checks every Terraform plan before apply: `scripts/helios_gate.py` in the infra deploy (R56) | BUILT; first live run in the next infra window | FREE |
| AWS Budgets | spend alarm per stack | IN USE with each stack | FREE |
| AWS test stacks: EKS, NAT gateway, ALB, Aurora, ElastiCache, ECS Fargate | the real systems WARDEN is measured on | only during test windows | **PAID** from credits: about $0.50/hour while up; destroyed after every window |
| Lambda, SQS, DynamoDB on-demand, SNS, EventBridge, API Gateway | smaller parts of the test stack | test windows | mostly inside free tiers |

## 9. Notifications and ChatOps

| Component | Status | Cost | Paid alternative avoided |
|---|---|---|---|
| Slack incoming webhook | IN USE | FREE | — |
| GitHub Issues as the incident record | OPTIONAL | FREE | incident.io, PagerDuty (PAID) |

## 10. Decisions (owner, 2026-09-28; these replace the earlier "all free" list)

1. **Quality first.** Paid services are used when they are the production-correct choice; each is
   listed with its cost. This superseded the earlier free-only rule.
2. **Laptop access without a key:** IAM Roles Anywhere (W0-now). Identity Center is not possible in
   one Free-plan account, and console passwords were rejected.
3. **Temporal Cloud** instead of a self-hosted Temporal. **Secrets Manager** for every secret, SSM
   for plain config. **Bedrock Claude Sonnet 5** as the production model (owner, 2026-10-03, after WARDEN's
   replay qualification). **KMS Ed25519** for audit signing.
   **Passkeys** for approvals, on the owner's Cloudflare domain.
4. The prices for these choices are in section 11, checked live on 2026-09-28 UTC / 2026-09-29 IST. Rows in sections 1-9
   that still say "free-only" reflect the old rule.

## 11. Live prices, checked 2026-09-28 UTC / 2026-09-29 IST (region ap-south-2, Hyderabad)

Re-checked 2026-09-30 by the second independent review against freshly downloaded ap-south-2 Price List
files: every AWS price below matched. The Temporal Developer-plan conflict remains UNCERTAIN.

**Sources:**
- AWS prices come from AWS's own Price List files for ap-south-2
  (`pricing.us-east-1.amazonaws.com/offers/v1.0/aws/<Service>/current/ap-south-2/index.json`,
  published 2026-09-11 to 2026-09-28). The billing rules were checked on each service's pricing page.
- Other vendors come from their pricing pages.

Hyderabad costs more than the pricing pages' us-east-1 examples for several items. For example, NAT
is $0.056 here and $0.045 in the example; log ingestion is $0.67/GB here and $0.50 in the example.
**UNCERTAIN** marks anything the source did not state plainly. Re-check each price the day before a
window.

| Component | Price | Notes |
|---|---|---|
| Temporal Cloud, Actions | $50 per 1M; volume tiers down to $25 per 1M | temporal.io/pricing, docs.temporal.io/cloud/pricing |
| Temporal Cloud, storage | active $0.042/GBh; retained $0.00105/GBh | |
| Temporal Cloud, plans | Developer: no base fee; Business: greater of $500/month or 10% of usage | UNCERTAIN: the docs attach "10% of usage" to Developer; the pricing page says "no base monthly fee" |
| Temporal Cloud, High Availability | 2x Actions and storage | docs; the pricing page shows no price |
| Temporal Cloud, trial | $150 credits for 90 days | the owner's current plan |
| Aurora PostgreSQL Serverless v2 | $0.18 per ACU-hour (I/O-Optimized: $0.24) | **auto-pause to 0 ACU: yes** on PG >= 16.3 / 15.7 / 14.12 / 13.15. Storage is still billed while paused; resume takes about 15 s |
| Aurora PostgreSQL db.t4g.medium | $0.106/h (I/O-Optimized: $0.138) | |
| Aurora storage and I/O | $0.11/GB-month + $0.22 per 1M I/O (I/O-Optimized: $0.248/GB-month, no I/O charge) | backup beyond the free allowance: $0.023/GB-month |
| EC2 t4g.small / t4g.medium (Linux) | $0.0112/h / $0.0224/h | 2 AZs x 1 host doubles these |
| NAT gateway | $0.056/h + $0.056/GB processed | billed per AZ |
| VPC interface endpoint (PrivateLink) | $0.013 per endpoint per AZ per hour + $0.01/GB | gateway endpoints (S3, DynamoDB) are free |
| KMS | $1 per key per month; asymmetric requests $0.15 per 10k; 20k requests/month free | UNCERTAIN: Ed25519 (ECC_NIST_EDWARDS25519) is not named on the page |
| Secrets Manager | $0.40 per secret per month + $0.05 per 10k calls | |
| CloudTrail | first copy of management events to S3: free; data events $0.10 per 100k | the S3 storage is billed separately |
| S3 Standard | $0.025/GB-month (first 50 TB) | Object Lock has no separate SKU; retained versions are billed as storage |
| CloudWatch Logs | $0.67/GB ingested; $0.03/GB-month stored | 5 GB free |
| CloudWatch Logs Insights | $0.005 per GB scanned (list price, read 2026-10-03) | WARDEN runs one query per log group per incident, over alert time +/- 15 min (requirement R22). UNCERTAIN: the ap-south-2 rate was not stated |
| RDS Performance Insights (API) | free: 7 days of data and 1M API requests a month (read 2026-10-03) | WARDEN reads `db.load` by wait-event type per Aurora member (R22). Longer retention is CloudWatch Database Insights, paid, not used |
| CloudWatch metrics and alarms | $0.30 per custom metric-month; $0.10 per standard alarm-month | 10 of each free |
| CloudWatch GetMetricData | $0.01 per 1,000 metrics requested; no free tier (read 2026-10-03) | every evidence read of a metric; a few dozen per incident |
| CloudWatch API requests | $0.01 per 1,000 requests after 1 million free a month (read 2026-10-10) | ListMetrics and DescribeAlarms: the universal alarm reader, two per incident (G9-A2a). CloudTrail LookupEvents is free (event history) |
| SQS requests | $0.40 per 1M (standard queues); first 1M a month free (read 2026-10-03) | the evidence reader's queue reads |
| SNS requests | $0.50 per 1M API requests; first 1M a month free (read 2026-10-03) | the evidence reader's subscription list |
| X-Ray | $5 per 1M traces stored; $0.50 per 1M retrieved | 100k stored free |
| CloudWatch generative-AI observability | no separate charge stated; the underlying logs, spans and metrics are billed | UNCERTAIN |
| Bedrock, Claude Sonnet 5 | $2 input / $10 output per 1M tokens (Anthropic list price, read 2026-10-03) | **the production model** (D12, 2026-10-03). India geo profile `in.anthropic.claude-sonnet-5` ACTIVE from ap-south-2. UNCERTAIN: the geo SKU may be +10%; checked in W-B |
| Bedrock, Claude Fable 5.1 | $10 / $50 per 1M tokens | qualified on the replay set; not chosen (price) |
| Bedrock, Claude Opus 5.5 | $4 / $20 per 1M tokens | the earlier choice; failed WARDEN's replay qualification (2026-10-02) |
| API Gateway HTTP API | $1.05 per 1M requests | |
| Lambda | $0.20 per 1M requests + $0.0000166667 per GB-second (Arm: $0.0000133334) | 1M requests and 400k GB-s free |
| EventBridge | AWS events on the default bus: free; custom events $1.00 per 1M | UNCERTAIN: Scheduler is $1.54 per 1M in the ap-south-2 Price List vs $1.00 in the page example |
| PagerDuty | Free (up to 5 users); Professional $25/user/month ($21 annual) | |
| AWS DevOps Agent | $0.0083 per agent-second (about $30/h) | **not offered in ap-south-2 or ap-south-1**; the optional adapter would call another region |
| Langfuse | self-hosted: open source, infrastructure only; cloud from $0 (Hobby) | optional, customer-hosted |
| Cloudflare DNS (owner's domain) | $0 on the Free plan | D17 |

**Lab estimate.** The quantities are assumptions; change them to match the real module (G6).
- **Per running hour: about $0.27.** This assumes 2 x t4g.small ECS hosts, 1 NAT, 4 interface
  endpoints in each of 2 AZs, and Aurora at 0.5 ACU.
- **Fixed while resources exist: about $5.20 a month.** That is 2 KMS keys, 5 secrets, 10 GB of
  Aurora storage and 5 GB of S3.
- **Totals:**
  - a 40-hour test window comes to about $16 a month;
  - always on, it would be about $204 a month.
- **Not included:** data processing charges, logs beyond the free tier, and model tokens. For
  example, 10M input + 1M output tokens cost $30 on Sonnet 5, the production model. Temporal is covered
  by the trial's credits only until about 2026-12-27 (90 days from 2026-09-28). That is before the
  G6 windows, which will be paid (ROADMAP calendar).
