# Every outside component of the WARDEN system: free, paid, and the free alternative

Checked 2026-09-27. The owner's rule is **free or open-source only**. The one paid item is the Claude
Max subscription the owner already has. Anything marked **PAID** below is either not used, or used
only inside a short AWS test window on the AWS Free plan's credits and torn down after.

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
| **Temporal** (MIT), self-hosted dev server | durable incident / remediation / infra workflows; approvals as signals; retries; timers | PLANNED, Phase 2 | FREE | Temporal Cloud (PAID); Kestra Enterprise (PAID; Kestra OSS is also free) |
| LangGraph (MIT) | today's pipeline graph | IN USE, replaced by Temporal in Phase 2 | FREE | — |
| MCP Python SDK (MIT) | WARDEN's tools exposed to agents (the Kestra "flows as agent tools" pattern) | IN USE; becomes the workflow surface in Phase 2 | FREE | — |

## 3. Guardrails, grounding, safety

| Component | Role | Status | Cost | Paid thing it replaces |
|---|---|---|---|---|
| WARDEN verifier P1–P15 (own code) | deterministic gate: the model never decides | IN USE | FREE | — |
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
| **IAM Identity Center** | replaces long-lived access keys on the laptop with short sign-ins | PLANNED (secrets work) | FREE | — |
| IAM Access Analyzer, **external access** | finds anything reachable from outside the account | IN USE (created 2026-09-27) | FREE. Its unused-access and internal-access types are PAID; not used | — |
| **SSM Parameter Store, SecureString, standard tier** | per-environment config and secrets | PLANNED (secrets work) | FREE (up to 10,000 parameters; AWS-managed key) | **Secrets Manager: PAID, $0.40 per secret per month.** Used only where AWS rotates a secret for us (a database master password), and only while a stack is up |
| GitHub Environments + environment variables and secrets | per-environment CI config; required reviewers for prod tiers | IN USE (`fullstack`), expanding | FREE on a public repo | — |
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
| **Helios** (owner's own; Rust + Z3, MIT) | proves a Terraform plan safe before apply | PLANNED, Phase 5 | FREE |
| AWS Budgets | spend alarm per stack | IN USE with each stack | FREE |
| AWS test stacks: EKS, NAT gateway, ALB, Aurora, ElastiCache, ECS Fargate | the real systems WARDEN is measured on | only during test windows | **PAID** from credits: about $0.50/hour while up; destroyed after every window |
| Lambda, SQS, DynamoDB on-demand, SNS, EventBridge, API Gateway | smaller parts of the test stack | test windows | mostly inside free tiers |

## 9. Notifications and ChatOps

| Component | Status | Cost | Paid alternative avoided |
|---|---|---|---|
| Slack incoming webhook | IN USE | FREE | — |
| GitHub Issues as the incident record | OPTIONAL | FREE | incident.io, PagerDuty (PAID) |

## 10. What the owner decides next (all free)

1. **IAM Identity Center** instead of the access key on this laptop. You sign in through the browser
   about twice a day, and no key is left on disk.
2. **Optional tools**: an injection tripwire (Prompt Guard 2 or PIGuard), Presidio, HHEM. None is
   needed for safety today; each adds a second signal.
3. **Nothing paid is required anywhere.** If a paid item is ever proposed, it will be listed here
   first with its free alternative.
