# WARDEN

[![CI](https://github.com/veerarakesh56/warden/actions/workflows/ci.yml/badge.svg)](https://github.com/veerarakesh56/warden/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> AI incident-response orchestrator. **The model proposes. A deterministic verifier decides.
> Nothing here executes against infrastructure.**

**Status:** v0.5.1 — working, tested and deployable. 388 tests (10 against a live Kubernetes
cluster, 12 against five real database engines), a 31-case mutation check, and CI that asserts the
actual verdicts rather than the exit code.

| | |
|---|---|
| **Pipeline** | LangGraph: alert → evidence → redaction → RCA → typed proposal → deterministic gate |
| **Safety** | 9 policies, closed action enum, verified redaction, token/USD budget, real tool timeouts |
| **Evidence** | recorded fixtures · a live Kubernetes cluster · PostgreSQL, MySQL, Redis, MongoDB, SQL Server |
| **Remediation** | dry-run by default; opt-in live backends (restart/scale a Deployment, terminate stuck DB connections) behind their own least-privilege credentials |
| **Environments** | per-environment allow/deny, authorised principals, auto-remediate — unknown environments fail closed |
| **Reporting** | redacted Markdown/JSON report with a promotion plan → Slack, Teams or any webhook |
| **Integrations** | MCP server · OpenTelemetry GenAI conventions · Terraform ECS module |
| **Models** | provider-agnostic: Gemini (free tier), Ollama (local), Anthropic, OpenAI-compatible |

## The problem

71% of organisations are deploying AI agents. **Only 11% of those use cases reach production**, and
85% lack the process maturity to get there. The gap is not model quality — it is that an agent which
can act on production needs the things operations software has always needed: guardrails, evidence,
proportionality, an audit trail, a cost ceiling, and a human in the loop.

Ask an LLM to remediate an incident and it will always produce something. Given thin evidence it
does not say "I don't know" — it produces a confident, plausible action. In a chat assistant that is
a bug. In an operations tool it is an outage with a good explanation attached.

## What WARDEN does

```
alert → gather evidence → REDACT → analyse → propose → VERIFY → halt | escalate | await approval
                          ^^^^^^                       ^^^^^^
                          nothing unredacted           nothing the model said
                          reaches the model            is trusted
```

- **Evidence first.** Tools run deterministically *before* the model reasons. The model does not
  choose what to look at, because choosing the evidence is choosing the answer.
- **Redaction that is verified, not assumed — and cloud-neutral.** Emails (incl. URL-encoded `%40`),
  IPv4/IPv6, UUIDs, PEM private keys, connection-string passwords (Postgres/MySQL/Redis — so RDS,
  Cloud SQL and Azure SQL alike), JWTs and bearer tokens, and vendor credentials across **AWS**
  (ARN, permanent `AKIA` **and STS temporary `ASIA`** access keys, secret keys), **GCP** (`AIza`
  keys, `ya29.` OAuth tokens), **Azure** (storage `AccountKey`, SAS `sig`), plus GitHub/GitLab/Slack/
  Stripe keys, `password=`/`secret=` values and **financial identifiers (IBANs, payment-card numbers)**
  are masked before any token leaves the process — then the output is re-scanned and a surviving value
  raises. Stable placeholders mean the model can still tell that two log lines refer to the same host.
  It masks high-entropy *secrets* while deliberately preserving high-entropy *evidence* (git SHAs,
  trace/request ids) — an entropy backstop would erase the evidence an RCA needs, so coverage is
  format-based and curated.
- **Typed proposals.** The model returns a `RemediationProposal` from a **closed action enum** or
  the call fails. It cannot invent `delete_database`.
- **A deterministic gate.** Nine policies in plain Python decide what happens. No prompt, no
  probability. Each returns a policy id so a rejection can be explained without re-running anything.
- **A researched incident knowledge base.** 34 signatures, basic (OOMKilled, CrashLoopBackOff,
  ImagePullBackOff) to advanced (metastable failure, cache stampede, split-brain, retry storm,
  control-plane saturation), each carrying a deterministic detector and ranked fixes drawn only from
  the closed action enum. It grounds the model's hypothesis and drives the report's suggestions — and
  it is DATA (`data/incident_signatures.yaml`), so a new failure mode is one YAML block, not a code change.
- **Per-environment policy that fails closed.** `data/environments.yaml` sets, for each environment
  (staging, qa-staging, pre-prod, qa-prod, prod, dev), an allow/deny action list, the authorised
  principals, and whether WARDEN may auto-remediate at all. An unrecognised environment resolves to a
  restrictive default that can only escalate — widening the environment set can never loosen safety.
- **A four-way remediation gate.** A fix is applied only when *verdict × environment auto-remediate ×
  authorised principal × explicit approval* all hold — and even then only through a pluggable backend.
  The default is dry-run (changes nothing, records what it would do). A **real Kubernetes backend**
  (`WARDEN_REMEDIATION=live`) restarts or scales a Deployment for real — restart/scale only, clamped
  (never to zero, never past a ceiling), behind a **separate write-RBAC** ServiceAccount that can
  `patch deployments` and nothing else. Arming it is necessary, never sufficient: the gate still
  decides. staging/qa-staging can auto-apply after approval; pre-prod and above always hand off.
- **A report built to be promoted.** Every run can emit a redacted Markdown/JSON report with a
  promotion plan — the exact higher environments where the same fix is permitted — and push it to
  Slack, Teams or a webhook (redacted again on the way out, dry-run unless explicitly armed).
- **A budget that stops things.** Token and USD ceilings raise and halt the run.
- **Real timeouts.** Every context tool runs under a wall-clock deadline. A hung logging backend
  during an incident is the normal case, not the edge case — and a timed-out tool becomes *visible
  partial context* (policy `P8`) rather than a gap that looks like completeness.
- **OpenTelemetry tracing.** One span per node — `warden.run → tool.* → analyse → propose → verify` —
  carrying confidence, action, blast radius, verdict, policies fired, and **token cost per step**.
  Console exporter by default so it works with no collector; set `OTEL_EXPORTER_OTLP_ENDPOINT` to
  ship to a real backend.
- **A full audit trail.** Every node records what it saw and did.
- **Terraform to deploy it.** ECS Fargate task with a **read-only task role** — WARDEN can inspect
  infrastructure but not change it — and the API key passed by Secrets Manager ARN so it never
  enters Terraform state. See [`terraform/`](terraform/).

## Quickstart

```bash
docker compose up          # no API key needed - runs in mock mode
```

or

```bash
pip install -e ".[dev]"
WARDEN_MOCK=1 warden demo --verbose
```

### Running against a real model — including free ones

WARDEN is **not tied to a vendor**. That is a design position, not a cost saving: a safety layer that
only works against one model is not a safety layer, and incident logs are the kind of data plenty of
organisations cannot send to any third party at all.

```bash
# Google AI Studio - genuine free tier, no card
pip install -e ".[gemini]"
WARDEN_MOCK=0 WARDEN_PROVIDER=gemini GEMINI_API_KEY=... warden run --incident inc-001

# Fully local, no key, nothing leaves the machine
pip install -e ".[openai]"
WARDEN_MOCK=0 WARDEN_PROVIDER=ollama WARDEN_MODEL=llama3.1 warden run --incident inc-001

# Anthropic, Groq or OpenRouter
WARDEN_MOCK=0 WARDEN_PROVIDER=anthropic ANTHROPIC_API_KEY=... warden run --incident inc-001
WARDEN_MOCK=0 WARDEN_PROVIDER=groq GROQ_API_KEY=... OPENAI_API_KEY=$GROQ_API_KEY warden run
```

| `WARDEN_PROVIDER` | Key | Notes |
|---|---|---|
| `mock` | none | Deterministic, no network. Default in CI |
| `gemini` | `GEMINI_API_KEY` | **Free tier** |
| `ollama` | none | **Fully local** — nothing leaves the machine |
| `anthropic` | `ANTHROPIC_API_KEY` | |
| `openai` / `groq` / `openrouter` | `OPENAI_API_KEY` | One OpenAI-shaped client covers all three |

Providers report their own token usage; one that cannot is made to **over-estimate** rather than
return zero, because a budget fed zeros never fires.

## MCP — the policy gate as a tool for any agent

Most MCP servers hand an agent **more capability**. This one hands it a **constraint**.

```bash
pip install -e ".[mcp]"
warden-mcp                      # stdio transport
```

Any MCP client — Claude Desktop, an IDE agent, another orchestrator — gets four tools:

| Tool | What it does |
|---|---|
| **`verify_remediation`** | Runs the deterministic 9-policy gate over a proposed action and returns a binding verdict with the policy ids that fired. **No model involved in the decision.** |
| `redact_text` | Masks identifiers and verifies its own output. Use before putting logs in any prompt |
| `gather_incident_context` | Logs, metrics and deploys under a timeout — already redacted |
| `describe_policy` | The nine policies and the per-environment allow-list |

So an agent with no safety layer of its own can ask whether the action it is about to take is
allowed in production, and get an auditable answer with policy ids. The closed action enum is
published in the tool schema, so a client cannot name an action outside the set, and every
response carries `may_execute: false`.

Built on the official `mcp` Python SDK v2 (2026-07-28 spec, stateless core).

## Kubernetes — reading a live cluster

Point WARDEN at a cluster and the evidence comes from the real thing — pod status, events, container
log tails and Deployment rollout history — instead of recorded fixtures.

```bash
pip install -e ".[k8s]"
WARDEN_BACKEND=k8s warden run --incident inc-002      # reads the cluster your kubeconfig points at
```

**`KubernetesBackend`** satisfies the same three-method contract as the fixture backend — `logs`,
`metrics`, `deploys` — so nothing above it changed. It reads:

| | From | Note |
|---|---|---|
| **metrics** | pod status: restart counts, `OOMKilled` terminations, `CrashLoopBackOff`, readiness, memory limits | **Not a metrics server.** k3d does not ship one, so these are counts the kubelet already records, not CPU/memory %. They are also what an on-call engineer reads first |
| **logs** | the events stream (`OOMKilling`, `BackOff`, `Unhealthy`…) then container log tails | events first — they are the headline |
| **deploys** | the Deployment's `deployment.kubernetes.io/revision` and last Progressing time | reported only inside a window, so policy P5 is handed real evidence |

**Read-only by construction.** The module uses only `list_*`, `read_*` and
`read_namespaced_pod_log`; a test greps the source for any write verb. And **RBAC enforces the same
thing from the cluster's side** — see below.

### Deploying into the cluster it diagnoses

```bash
kubectl apply -k k8s/            # the DURABLE parts: namespace, ServiceAccount, ClusterRole, RoleBinding
kubectl create -f k8s/job.yaml   # one diagnosis (the Job uses generateName, so `create`, never `apply`)
```

The ClusterRole has **get / list only** — no `watch`, and no `create`, `update`, `patch`, `delete`.
It is bound with a **namespaced RoleBinding** per diagnosed namespace — never a ClusterRoleBinding. The
Job runs as **uid 10001, read-only root filesystem, all capabilities dropped**, under the
`restricted` Pod Security Standard.

**RBAC is the boundary, not the verifier.** "It only acts when the policy gate approves" is a
design argument. A ServiceAccount that *cannot* mutate anything is a security boundary — if the
policy engine has a bug, the credentials still cannot do harm. This is the Kubernetes twin of the
Terraform task role.

### Runs on ECS **or** any Kubernetes — EKS, GKE, AKS, k3d

Two deployment paths, both included:

- **Any Kubernetes cluster** (EKS / GKE / AKS / k3d) — the `k8s/` manifests. The runtime is
  cluster-agnostic: it reads the cluster through **in-cluster config** and calls **no cloud API**, so
  on EKS it needs **no IRSA / IAM role** — only the read-only k8s RBAC. The pod is **fully
  `restricted`-PSS compliant** (`seccompProfile: RuntimeDefault`, non-root uid 10001, read-only root
  FS, all capabilities dropped), so it is admitted on clusters that **strictly enforce Pod Security**
  — which is exactly what EKS/GKE/AKS do, and what CI proves by enforcing `restricted` on the
  namespace and admitting the Job while rejecting a privileged pod. The **only** cluster-specific
  change is the image, which the demo hard-codes to `warden:local`. On EKS, push to ECR and set it:
  ```bash
  kubectl apply -k k8s/     # namespace, ServiceAccount, ClusterRole, RoleBinding — portable as-is
  sed 's#warden:local#<acct>.dkr.ecr.<region>.amazonaws.com/warden:0.5.1#' k8s/job.yaml \
    | kubectl create -f -   # one diagnosis, image retargeted to your registry
  ```
- **ECS / Fargate** — the `terraform/` module: a task with a **read-only task role** and **all Linux
  capabilities dropped**, mirroring the k8s Job.

**Scope:** the portability that makes EKS work — strict `restricted` admission and no cloud-API
dependency — is CI-verified on k3d, which enforces the identical Pod Security standard. It has not
been run against a live EKS cluster: the manifests are compliant and cluster-agnostic, not
field-tested on managed EKS.

## Observability that other tools can read

Spans use the **OpenTelemetry GenAI semantic conventions** — `gen_ai.operation.name`,
`gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.usage.input_tokens`,
`gen_ai.usage.output_tokens` — rather than invented attribute names. That is the difference between traces any
tool can read and traces only this project could: **[Langfuse](https://langfuse.com) and
[Arize Phoenix](https://phoenix.arize.com) ingest them over OTLP with no adapter.**

```bash
WARDEN_TRACE_CONSOLE=1 warden run --incident inc-001     # see the spans
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:6006 warden run   # ship to Phoenix
```

The GenAI conventions moved to their own repo in semconv **v1.42.0 (June 2026)** and remain in
*Development* status. Core usage and model attributes are stable enough to build on; expect churn.
Cost has no spec attribute, so it stays under `warden.cost.usd`.

## What the demo shows

Five recorded incidents, each exercising a different route:

| Incident | Evidence | Proposal | Verdict | Why it matters |
|---|---|---|---|---|
| `inc-001` | 5xx spike **after a deploy** | `rollback_deploy` | **approved_for_human** | Clean signal — and a person still presses the button |
| `inc-002` | OOM kills, **no deploy** | `scale_up` | **approved_for_human** | Does not reach for rollback by reflex |
| `inc-003` | Replica saturated, lag 47s | `failover_replica` | **escalated** | Right action, but multi-service blast radius (`P6`) |
| `inc-004` | Two vague log lines | `escalate_to_human` | **auto_safe** | **Declines to invent a fix** |
| `inc-005` | Pool exhausted by idle-in-transaction connections, **no lag** | `terminate_connections` | **approved_for_human** | Tells a stuck-connection incident apart from `inc-003` — a single-service fix, not a failover |

`inc-004` is the one worth running. Given two vague log lines, WARDEN scores low confidence and
proposes escalation — and the verifier lets that through precisely *because* escalation is inert.

## Environments, remediation and ChatOps

The gate does not stop at "approved". WARDEN can **resolve** an incident where it is safe to, and turn
every run into a report a human uses to promote the same fix upward.

**Per-environment policy** lives in [`src/warden/data/environments.yaml`](src/warden/data/environments.yaml)
(override with `WARDEN_ENV_POLICY_PATH`). Each environment declares its allowed/denied actions, its
authorised principals, and whether WARDEN may auto-remediate:

| environment | auto-remediate | example allow | denies |
|---|---|---|---|
| `staging`, `qa-staging` | yes (after approval) | restart, scale, rollback, clear-cache | DB failover |
| `pre-prod`, `qa-prod` | no — human applies | restart, scale-up, rollback | scale-down, cache, failover |
| `prod` | never | restart, scale-up, rollback, failover | scale-down |
| *anything else* | no | *nothing but escalate* | — (**fails closed**) |

**Remediation is gated four ways** — the action must clear the verifier, the environment must permit
auto-remediation, the principal must be authorised there, and an approval must be present. Only then
does it run, and only through a pluggable backend; the shipped `DryRunBackend` changes nothing.

```bash
# Auto-resolve in staging (dry-run), then print the promotion report:
warden run --incident inc-002 --environment staging --principal role:oncall --approve --report

#   -> Remediation: dry_run  "would scale_up 'checkout' in staging"
#   -> Promotion:  pre-prod / qa-prod / prod  (a human applies)

# The same request in prod is refused by policy, not by chance:
warden run --incident inc-002 --principal role:oncall --approve
#   -> Remediation: not_auto_remediable  (prod never auto-applies)

# Arm the REAL Kubernetes backend (restart/scale for real) — still gated, still staging-only here:
kubectl apply -f k8s/remediation-rbac.yaml            # the separate write-RBAC, once
WARDEN_REMEDIATION=live WARDEN_BACKEND=k8s \
  warden run --incident inc-002 --environment staging --principal svc:warden-staging --approve
#   -> Remediation: applied  "scaled deployment/checkout in default from 1 to 2 replica(s)"
```

**Live remediation** (`WARDEN_REMEDIATION=live`) arms a router that sends each approved action to the
backend that can perform it — Kubernetes actions to `KubernetesRemediationBackend`, database actions to
`DatabaseRemediationBackend` — and refuses anything neither can do. On the cluster side it does a real
rollout **restart** or **scale** (up/down, clamped ≥1 and ≤ a ceiling) via `patch deployments`. Its
permission is a separate `warden-remediator` ServiceAccount (`k8s/remediation-rbac.yaml`, not in the
default deploy) that can patch deployments and nothing else — proven both ways by `kubectl auth can-i`
in CI, and the restart/scale proven against a live k3d cluster. The four-way gate is unchanged.

## Databases — PostgreSQL, MySQL, Redis, MongoDB, SQL Server

The same shape as Kubernetes: a **read-only** evidence backend, and a separate, gated write path that
does exactly one safe thing.

**Read (`WARDEN_BACKEND=postgres|mysql|redis|mongo|mssql`, or `db` to take the engine from the DSN).**
`DatabaseBackend` reports connection and transaction health as evidence: active connections against the
maximum, **idle-in-transaction** count, long-running queries, lock waits, replica lag; for Redis,
clients/blocked/evictions/memory; for Mongo, connections and long-running ops. It is **read-only by
construction** — every statement is a SELECT/SHOW/INFO/serverStatus/currentOp, and a test parses the
module's AST and fails if a write verb reaches anything it could execute. Query text is redacted
before it becomes evidence, because a query can carry PII.

**Write — one action: `terminate_connections`.** Connections stuck *idle in transaction* hold pool
slots and row locks; killing them is the standard on-call fix and destroys no data (the transaction
rolls back, the application reconnects). Per engine: `pg_terminate_backend` · `KILL` · `CLIENT KILL` ·
`killOp` · `KILL` (SQL Server). Three clamps, enforced in the SQL **and again in Python** so one broken
`WHERE` cannot widen them:

| clamp | value |
|---|---|
| only connections stuck beyond | `WARDEN_DB_TERMINATE_IDLE_SECS` (default 300s) |
| at most | `WARDEN_DB_TERMINATE_MAX` (default 20) |
| never | its own connection (`pg_backend_pid()` / `CONNECTION_ID()` / `client_id()` / `@@SPID`) |

`WARDEN_DB_DRY_RUN=1` selects the candidates and reports the count **without killing anything** — and
in that mode the backend reports itself as not-live, so the audit records a dry run rather than a
change. Everything else a database incident might want — failover, promotion, schema change, FLUSH,
DROP — is deliberately absent: `failover_replica` escalates to a human by policy, and the rest are not
in the action enum at all.

Its credential is a **separate least-privilege role** (`WARDEN_DB_ADMIN_DSN`), the database twin of the
write-RBAC ServiceAccount. The role that reads health needs none of these, and this role needs nothing
else:

| engine | the only grant it needs |
|---|---|
| PostgreSQL | `GRANT pg_signal_backend` |
| MySQL | `CONNECTION_ADMIN` |
| SQL Server | `ALTER ANY CONNECTION` |
| Redis | an ACL user permitted `CLIENT\|KILL` |
| MongoDB | `killop` |

Every engine is exercised against a real server in CI, not a stub: the `db` job runs all five as
service containers and asserts a stuck connection is selected, terminated and gone.

## Architecture

- [`docs/ai-boundary.md`](docs/ai-boundary.md) — **why the model never decides**, the policy table,
  and the honest limits.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — nodes, state, and where to swap fixtures for real
  backends.
- [`docs/INTERVIEW-NOTES.md`](docs/INTERVIEW-NOTES.md) — the design decisions, defended.
- [`docs/ENGINEERING-NOTES.md`](docs/ENGINEERING-NOTES.md) — defects found while building it, and the
  fix each one forced.

## Tests

```bash
make check     # ruff + unit tests + eval gate
```

`tests/` covers redaction and every policy; `evals/` is the behavioural gate (routing, safety
invariants, cost, budget, audit trail). Live-infrastructure suites are opt-in:

```bash
WARDEN_K8S_INTEGRATION=1 pytest tests/integration/test_live_cluster.py   # needs a cluster
WARDEN_DB_INTEGRATION=1  pytest tests/integration/test_live_database.py  # needs a database
```

## Limits, stated plainly

- Evidence comes from recorded fixtures, a live Kubernetes cluster, or a live database. Wiring to
  Loki/CloudWatch/Datadog is one class each, not done here.
- Remediation is **dry-run by default**. Live backends ship for Kubernetes (restart/scale) and for
  databases (terminate stuck connections), and CI exercises both against real infrastructure — a k3d
  cluster and all five engines as service containers. They stay off unless armed *and* the four-way
  gate passes, and they deliberately do only those things. No rollback, failover, delete, schema
  change or FLUSH: those escalate to a human by policy, or are absent from the action enum entirely.
- **Oracle is not supported** (a licensed, heavy client), and no database *failover* or schema change
  is offered at any tier — by design, not omission.
- The database work runs against **containers**, not managed cloud services (RDS, Cloud SQL, Azure
  SQL). The catalog views and statements are the engines' own, so they transfer — but "tested on RDS"
  is a claim this repo has not earned.
- Redaction is regex-based — a strong control against accidental leakage, not a guarantee against a
  determined adversary.
- The eval suite tests deterministic behaviour, **not** live model quality.
- A timed-out tool thread is **abandoned, not killed** — Python cannot force-stop a thread. The
  caller stops waiting, which is what the deadline is for; a real deployment should also set a
  socket timeout on the backend client.
- The Terraform is **validated in CI, never `apply`-ed** against a live account, and its read policy
  uses `resources = ["*"]` because the services under diagnosis are not known ahead of time.

## Related

[Helios](https://github.com/veerarakesh56/helios) — Rust + Z3 infrastructure failure simulator where
Claude proposes Terraform fixes and an SMT engine re-verifies each one. Same principle, different
domain: **rigorous core, AI shell.**

## License

Apache-2.0.
