# How WARDEN runs in the real world

In production, WARDEN is not run from anyone's laptop. It is a set of cloud services, each with its
own machine identity. It starts itself when an alarm fires, and it never holds a person's credentials
or a long-lived key. This document is the target design; `docs/SYSTEM-COMPONENTS.md` lists what each
part costs.

## The loop

```
 Monitoring: CloudWatch alarms, Prometheus Alertmanager in EKS
      │ alarm state change / webhook
      ▼
 EventBridge rule ──► Intake Lambda (validates, dedupes, labels the environment)
      │ starts IncidentWorkflow(alert), workflow id inc-<alert_id> (a second alarm joins it)
      ▼
 Temporal (self-hosted, open source) + Postgres
      │ task queues, one worker type per trust zone
      ├─► read worker    task role → that environment's reader role, 15 min, SourceIdentity=inc-<id>
      ├─► llm worker     one model call; sees typed facts only, no credentials, no raw log text
      ├─► core worker    grounding, verifier P1–P15, outbound gate, signed audit; no cloud access
      ├─► notify worker  Slack; the only way out; webhook read from SSM
      └─► actor worker   only after a SIGNED approval: actor role, 15 min, session policy = exact ARNs
      ▲
 Slack "Approve" button ─► API Gateway ─► Approval Lambda (checks Slack's signature + approver list)
                                            └─► Temporal signal approve(plan_hash)
```

## When it starts

- **Automatically.** A CloudWatch alarm changes state, an EventBridge rule matches it, and the intake
  Lambda starts the workflow. An EKS Alertmanager webhook reaches the same intake through API
  Gateway. It is event-driven, so nothing polls.
- **By hand.** An engineer or another agent asks through MCP (`warden_diagnose_incident`) or the CLI.
  This starts the same workflow, with the same rules.

## Where it runs

| | A company | This lab (one AWS Free-plan account) |
|---|---|---|
| Accounts | an "ops/tooling" account in an AWS Organization, plus one account per environment | one account; environments separated by name (`warden-<env>-*`), tag `Environment=<env>` and parameter path `/warden/<env>/` |
| WARDEN itself | ECS Fargate services (or EKS Deployments) in the ops account, deployed by CI | the same, in the `ops` name space, **only during a test window**, then destroyed |
| Deploys | GitHub Actions → OIDC → `warden-<env>-deploy` role → Terraform. Pre-prod, qa-prod and prod need the owner's approval in GitHub | same |

## How each part gets access (no keys anywhere)

- **Workers:** each has its own ECS task role (or EKS Pod Identity). AWS issues short-lived
  credentials and rotates them itself.
- **Per incident:** the read worker assumes **that environment's reader role**, tagged with the
  incident id. Only after a signed approval does the actor worker assume an **actor role** for 15
  minutes, with a session policy naming the exact resources in the approved plan.
- **Secrets** (Slack webhook, a model API key if one is used) live in **SSM Parameter Store** under
  `/warden/<env>/env/…`. They are read at run time through the task role (`settings.py`), and only by
  the worker that needs each one. Nothing is on disk or in the repository.
- **CI** has no AWS keys. GitHub's OIDC token is exchanged for the environment's deploy role, which
  accepts only that GitHub environment.
- **People:**
  - A company signs people in with **IAM Identity Center**, and on-call engineers approve in Slack.
  - This lab can't use Identity Center: it needs AWS Organizations, which ends the Free plan.
    Development on the laptop uses the operator's existing, boundary-capped credentials. The
    real-world test is run **entirely from the cloud**: deploys through GitHub OIDC and each worker
    through its task role, with no laptop and no person's key involved.
  - WARDEN's code never sees which of the two is used. It only ever sees roles.

## The model in production

The lab uses the owner's Claude Max plan through the `claude` CLI, for development and benchmarks. A
real deployment's llm worker calls **Amazon Bedrock** (IAM-authenticated, no key) or the Anthropic API,
with a key in SSM. Both are **paid per token**. At about 5,000 input tokens per incident, that is
roughly $0.02–0.05 per incident at Sonnet-class prices. The one-call design and the quarantine's 62%
token cut keep it there.

Temporal lets a worker run anywhere that can reach the server. So in the lab's test windows, the llm
worker can run on the laptop with Claude Max for free, while every other worker runs in AWS.

## Tracing and audit

One correlation id, `inc-<id>`, runs through:
- the workflow id;
- the STS session name and SourceIdentity, so CloudTrail shows every call made for the incident;
- WARDEN's hash-chained, signed audit;
- the Slack message;
- the change timeline: "what changed just before this incident", linked to its commit and PR.

## What it costs

- **Always-on production:** Temporal, Postgres and a few small Fargate tasks come to roughly $30–60 a
  month, plus model tokens.
- **The lab:** pays nothing for this until a test window. It then deploys the runtime, runs a
  **production rehearsal** (fault → alarm → trigger → diagnosis → Slack → approve → fix → verify →
  audit) and destroys it.

## What exists today and what is planned

| Part | Status |
|---|---|
| Diagnosis, grounding, quarantine, verifier, gate, approval digest | built (v0.9.0 and the 2026-09-27 audit) |
| Per-environment names and the SSM loader (`environments.names`, `settings.py`) | built (Phase 1.5) |
| Per-environment IAM, Terraform workspaces, GitHub environments | Phase 1.5 |
| Temporal workflows, workers, Slack approval signal, signed audit | Phase 2 |
| Calibrated decision component, shadow mode | Phase 3 |
| AWS runtime module (intake, workers, reader/actor roles), change timeline in AWS, production rehearsal | Phase 4 |
| Helios check on every Terraform change | Phase 5 |
