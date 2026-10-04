# How WARDEN runs in the real world

In production, WARDEN is not run from anyone's laptop. It is a set of cloud services, each with its
own machine identity. It starts itself when an alarm fires, and it never holds a person's credentials
or a long-lived key. It is designed to run every day for years: highly available, upgradable,
backed up and observable.

This document is the **target design**, approved on 2026-09-28. [`ROADMAP.md`](ROADMAP.md) says which
group builds each part. [`SYSTEM-COMPONENTS.md`](SYSTEM-COMPONENTS.md) lists every component and its
cost. The honest status of what exists today is at the end.

**Design principle: Meta's "Agents Rule of Two."** An agent should have at most two of three
properties: it processes untrusted input, it reaches sensitive data, it changes state. WARDEN has
the first two, and changes state **only through a signed human approval** of an exact plan.
Detectors are tripwires, never gates. Research shows adaptive attacks beat every detector, so the
architecture carries the protection.

## The loop

```
 Monitoring: CloudWatch alarms · Prometheus Alertmanager · PagerDuty / incident webhooks
      │ state = ALARM only
      ▼
 EventBridge rule (retry + DLQ) ─► Intake Lambda ──┐    HTTP API (HMAC) ─► the same intake
                                  intake.accept:    │    dedupe by fingerprint, storms join the open
                                  incident, flapping escalates, an alarm inside an open verify
                                  window signals that remediation (no feedback loop), caps
      ▼
 Temporal Cloud namespace (aws-ap-south-2; HA replica ap-south-1 when enabled)
      │ API key per trust zone · payloads AES-256-GCM encrypted by WARDEN (codec) · codec server for the UI
      ├─► read worker    task role → that environment's reader role, 15 min, SourceIdentity=inc-<id>
      ├─► llm worker     ONE permission: bedrock:InvokeModel on the pinned Sonnet 5 profile;
      │                  typed, redacted facts only; ≤ 2 calls per incident (counted in the audit)
      ├─► core worker    grounding, policies P1–P16+, outbound gate, KMS-signed audit
      ├─► notify worker  Slack bot (thread per incident) · PagerDuty Events v2 · webhooks
      └─► act worker     never holds a standing role; receives a ≤ 900 s actor session minted by the
                         approval Lambda, with a session policy naming the exact target ARNs
      ▲
 Slack "Review" button ─► approval page (bhovix subdomain; passkey / WebAuthn over the plan hash)
                            └─► Approval Lambda: verifies the passkey, mints the actor session,
                                 sends a Temporal Update (validated before it enters history)
```

## When it starts

- **Automatically, in production.** A CloudWatch alarm enters ALARM, the EventBridge rule matches,
  and `intake.accept` starts or joins an incident. Alertmanager and incident-platform webhooks enter
  the same way through an HMAC-authenticated HTTP API. Nothing polls.
- **By hand.** An engineer or another agent asks through MCP (`start_incident_diagnosis`) or the CLI,
  and it goes through the same `intake.accept`. The benchmark harness is triggered by hand with
  Claude Max, for measurement only.

## Where it runs

| | A company | This lab |
|---|---|---|
| Accounts | an "ops" account plus one account per environment (the Terraform module supports multi-account) | **one AWS account, hardened** (owner decision): environments separated by name `warden-<env>-*`, the `Environment` tag, parameter path `/warden/<env>/`, and per-environment boundaries |
| Orchestration | Temporal Cloud (Business or Enterprise, HA namespace) | Temporal Cloud trial namespace in aws-ap-south-2 (created 2026-09-28) |
| Workers | ECS on an EC2 capacity provider, private subnets, 2 AZs, one service per trust zone (or EKS via a Helm chart) | the same, deployed **only in test windows until go-live** |
| WARDEN's own data | Aurora PostgreSQL (writer + reader), S3 blobs, S3 Object Lock anchors | Aurora Serverless v2 with auto-pause (verify live), plus the same S3 |
| Deploys | GitHub Actions → OIDC → per-environment deploy role; WARDEN itself through its own `runtime.yml` pipeline and `ops` environment | same |

## How each part gets access (no keys anywhere)

- **Workers:** each has its own ECS task role, with IMDS blocked from tasks. AWS issues short-lived
  credentials and rotates them.
- **Per incident:**
  - the read worker assumes that environment's **reader role**, with `SourceIdentity=inc-<id>`;
  - the **actor session** is minted only by the approval Lambda, after the passkey signature is
    verified, and carries session tags `approver=` and `incident=`;
  - an EventBridge-on-CloudTrail check pages on any actor-role use that has no matching signed
    approval.
- **Secrets:** plain configuration lives in SSM Parameter Store; **every secret lives in Secrets
  Manager** (owner decision, 2026-09-28), read at run time only by the worker that needs it.
- **Audit signing:** an AWS KMS Ed25519 key (`ECC_NIST_EDWARDS25519`) that only a dedicated signer
  role may use. Checkpoints are anchored to S3 Object Lock under another principal, and CloudTrail
  records every `kms:Sign` as an independent witness.
- **CI:** no AWS keys. GitHub's OIDC token is exchanged for the environment's deploy role.
- **People:**
  - A company signs people in through its own identity provider (IAM Identity Center where it uses
    AWS Organizations) and approves with passkeys.
  - This lab cannot use Identity Center, because it would need AWS Organizations and so end the Free
    plan.
  - The laptop operator moves to **IAM Roles Anywhere** (a certificate, no password, no stored key).
    This is being verified before the switch. No console password is used.
  - Teleport is an optional adapter for companies that already run it.

## Human approval

- **The tiers:**
  - T1 may be approved from Slack.
  - T2 and above need the approver's **passkey signature over the exact plan hash**, made on the
    approval page after typing the target.
  - T3 (irreversible, IAM, network, Terraform) also needs a cooling-off time and, for infrastructure,
    a Helios check.
- **Two-person rule.** Supported in code. The lab has a single approver, and says so.
- **Break-glass.** The CLI Ed25519 key, used with a short-lived Temporal user API key.

## The model in production

**Amazon Bedrock, Claude Sonnet 5** (`anthropic.claude-sonnet-5`, owner decision 2026-10-03), pinned
by id, through the India geo inference profile `in.anthropic.claude-sonnet-5`, so inference stays in
India (read live 2026-10-03). It was chosen by WARDEN's own replay of 30 recorded incidents, never by
public leaderboards: it passed the qualification bar at a fifth of Fable 5.1's price, and Opus 5.5 did
not pass. The input is only redacted, typed facts. A model change needs a new qualification
(register M20). The cost is about $0.05 per incident, assuming the geo profile is billed +10%; this is
checked in W-B.

If there is no model, the budget is exceeded, or the provider is down, WARDEN produces a
**rules-only report and pages a person** instead of guessing.

The Claude Max CLI remains the development and benchmark backend.

## Observability, audit, change timeline

- **Tracing.** OpenTelemetry end to end: Temporal's TracingInterceptor plus WARDEN's GenAI-convention
  spans, through an ADOT collector to CloudWatch / X-Ray. Langfuse is an optional, self-hosted add-on
  for companies.
- **One correlation id**, `inc-<id>`, runs through the workflow, the STS session and SourceIdentity,
  the signed audit, the Slack thread and PagerDuty `dedup_key`.
- **Change timeline.** GitHub Deployments, SHA stamping on everything deployed, and EventBridge →
  `/warden/changes`. A change is a *suspect*, never the cause.
- **WARDEN's own health.** A heartbeat with an external staleness page, a daily synthetic incident,
  and its own PagerDuty service.

## Operations

- **Upgrades:** Alembic migrations; Temporal worker versioning with in-flight replay tests.
- **Backups and restore:** backups plus point-in-time recovery, with a measured restore drill (RTO and
  RPO published).
- **Key rotation:** a table per secret.
- **The codec server** is not built yet. Every payload is bound to its namespace and workflow id
  (2026-09-30), so the server must receive the workflow id with each payload. Whether the Temporal
  web UI sends it is to be verified live in G6. If it does not, the UI shows payloads as refused
  rather than decrypting them unbound.
- **Data retention:** covered in `DATA-RETENTION.md`.
- **Threat model:** in `THREAT-MODEL.md`.

All of these are written in G6.

## What exists today (2026-10-04)

| Part | Status |
|---|---|
| Diagnosis, grounding, quarantine, verifier, outbound gate | built and reviewed; observe-mode policies P25-P28 |
| Temporal workflows, signed and passkey approvals, deny, tamper-evident audit (SQLite or PostgreSQL), bounds, catalogue, encrypted payloads | built |
| Per-environment names, IAM templates (deploy, platform reader, actor), Terraform workspaces | built |
| Temporal Cloud namespace | created (W-T, 2026-09-28) |
| Intake (alarm and Alertmanager Lambdas), the PostgreSQL audit, KMS signing and S3 anchors, the approval page, the Slack bot thread, PagerDuty (Events API v2), the Bedrock provider, the AWS write platform with per-plan actor sessions, the heartbeat and the daily synthetic incident | built and tested locally; first run in the cloud windows (W1-W2) |
| The runtime module (`terraform/modules/warden-runtime`): KMS, anchors, secrets, Aurora, identities, Lambdas, HTTP API, EventBridge, ECS on EC2, alarms | built and validated; not yet applied (W1-W2) |
| The change timeline across stages | not built (G6) |
| Calibration and shadow mode | the decider is built; it does not yet beat the base rate (G7, R44) |
| Helios gate | built in the infra deploy (R56); first live run in the next infra window |
