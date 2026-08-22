# AEGIS

> AI incident-response orchestrator. **The model proposes. A deterministic verifier decides.
> Nothing here executes against infrastructure.**

**Status:** v0.5.1 — LangGraph pipeline, verified redaction, 9 policies, real tool timeouts,
**a live Kubernetes backend proven against a real k3d cluster in CI** (read-only RBAC verified
both ways, in-cluster Job), **MCP server** exposing the policy gate, OpenTelemetry **GenAI semantic
conventions**, Terraform deploy, **provider-agnostic** (Gemini free tier, Ollama local, Anthropic,
OpenAI-compatible), 4 recorded incidents, **194 tests** (7 against a live cluster) plus a 15-case mutation check,
output-asserting CI.

## The problem

71% of organisations are deploying AI agents. **Only 11% of those use cases reach production**, and
85% lack the process maturity to get there. The gap is not model quality — it is that an agent which
can act on production needs the things operations software has always needed: guardrails, evidence,
proportionality, an audit trail, a cost ceiling, and a human in the loop.

Ask an LLM to remediate an incident and it will always produce something. Given thin evidence it
does not say "I don't know" — it produces a confident, plausible action. In a chat assistant that is
a bug. In an operations tool it is an outage with a good explanation attached.

## What AEGIS does

```
alert → gather evidence → REDACT → analyse → propose → VERIFY → halt | escalate | await approval
                          ^^^^^^                       ^^^^^^
                          nothing unredacted           nothing the model said
                          reaches the model            is trusted
```

- **Evidence first.** Tools run deterministically *before* the model reasons. The model does not
  choose what to look at, because choosing the evidence is choosing the answer.
- **Redaction that is verified, not assumed.** Emails, IPs, UUIDs, ARNs, JWTs, API keys, AWS account
  IDs and tenant identifiers are masked before any token leaves the process — then the output is
  re-scanned and a surviving value raises. Stable placeholders mean the model can still tell that
  two log lines refer to the same host.
- **Typed proposals.** The model returns a `RemediationProposal` from a **closed action enum** or
  the call fails. It cannot invent `delete_database`.
- **A deterministic gate.** Nine policies in plain Python decide what happens. No prompt, no
  probability. Each returns a policy id so a rejection can be explained without re-running anything.
- **A budget that stops things.** Token and USD ceilings raise and halt the run.
- **Real timeouts.** Every context tool runs under a wall-clock deadline. A hung logging backend
  during an incident is the normal case, not the edge case — and a timed-out tool becomes *visible
  partial context* (policy `P8`) rather than a gap that looks like completeness.
- **OpenTelemetry tracing.** One span per node — `aegis.run → tool.* → analyse → propose → verify` —
  carrying confidence, action, blast radius, verdict, policies fired, and **token cost per step**.
  Console exporter by default so it works with no collector; set `OTEL_EXPORTER_OTLP_ENDPOINT` to
  ship to a real backend.
- **A full audit trail.** Every node records what it saw and did.
- **Terraform to deploy it.** ECS Fargate task with a **read-only task role** — AEGIS can inspect
  infrastructure but not change it — and the API key passed by Secrets Manager ARN so it never
  enters Terraform state. See [`terraform/`](terraform/).

## Quickstart

```bash
docker compose up          # no API key needed - runs in mock mode
```

or

```bash
pip install -e ".[dev]"
AEGIS_MOCK=1 aegis demo --verbose
```

### Running against a real model — including free ones

AEGIS is **not tied to a vendor**. That is a design position, not a cost saving: a safety layer that
only works against one model is not a safety layer, and incident logs are the kind of data plenty of
organisations cannot send to any third party at all.

```bash
# Google AI Studio - genuine free tier, no card
pip install -e ".[gemini]"
AEGIS_MOCK=0 AEGIS_PROVIDER=gemini GEMINI_API_KEY=... aegis run --incident inc-001

# Fully local, no key, nothing leaves the machine
pip install -e ".[openai]"
AEGIS_MOCK=0 AEGIS_PROVIDER=ollama AEGIS_MODEL=llama3.1 aegis run --incident inc-001

# Anthropic, Groq or OpenRouter
AEGIS_MOCK=0 AEGIS_PROVIDER=anthropic ANTHROPIC_API_KEY=... aegis run --incident inc-001
AEGIS_MOCK=0 AEGIS_PROVIDER=groq GROQ_API_KEY=... OPENAI_API_KEY=$GROQ_API_KEY aegis run
```

| `AEGIS_PROVIDER` | Key | Notes |
|---|---|---|
| `mock` | none | Deterministic, no network. Default in CI |
| `gemini` | `GEMINI_API_KEY` | **Free tier** |
| `ollama` | none | **Fully local** — nothing leaves the machine |
| `anthropic` | `ANTHROPIC_API_KEY` | |
| `openai` / `groq` / `openrouter` | `OPENAI_API_KEY` | One OpenAI-shaped client covers all three |

⭐ Providers report their own token usage, and a provider that cannot is made to **over-estimate**
rather than return zero — a budget fed zeros never fires.

## MCP — the policy gate as a tool any agent can call

Most MCP servers hand an agent **more capability**. This one hands it a **constraint**.

```bash
pip install -e ".[mcp]"
aegis-mcp                      # stdio transport
```

Any MCP client — Claude Desktop, an IDE agent, another orchestrator — gets four tools:

| Tool | What it does |
|---|---|
| ⭐ **`verify_remediation`** | Runs the deterministic 9-policy gate over a proposed action and returns a binding verdict with the policy ids that fired. **No model involved in the decision.** |
| `redact_text` | Masks identifiers and verifies its own output. Use before putting logs in any prompt |
| `gather_incident_context` | Logs, metrics and deploys under a timeout — already redacted |
| `describe_policy` | The nine policies and the per-environment allow-list |

⭐⭐ **Why this is the interesting one:** an agent written by someone else, with no safety layer of its
own, can ask AEGIS whether the thing it is about to do is allowed in production — and get an
auditable answer with policy ids. **The closed action enum is published in the tool schema**, so a
client cannot even name an action outside the set. Every response carries `may_execute: false`.

Built on the official `mcp` Python SDK **v2** (2026-07-28 spec, stateless core).
⚠ `mcp.server.fastmcp` does not exist in v2 — it was removed in the rework. This uses the low-level
`Server` with explicit callbacks.

## Kubernetes — it has now seen a pod

Until v0.5.0 this project talked about pods constantly — `restart_pods`, `single_pod`, OOM-killed
containers — and had never read one. The vocabulary was Kubernetes; the evidence was JSON fixtures.
That is the same defect shape as every other bug in this README: **a claim the code did not back.**

```bash
pip install -e ".[k8s]"
AEGIS_BACKEND=k8s aegis run --incident inc-002      # reads the cluster your kubeconfig points at
```

**`KubernetesBackend`** satisfies the same three-method contract as the fixture backend — `logs`,
`metrics`, `deploys` — so nothing above it changed. It reads:

| | From | Honest note |
|---|---|---|
| **metrics** | pod status: restart counts, `OOMKilled` terminations, `CrashLoopBackOff`, readiness, memory limits | ⚠ **Not a metrics server.** k3d does not ship one, so these are counts the kubelet already records, not CPU/memory %. They are also what an on-call engineer reads first |
| **logs** | the events stream (`OOMKilling`, `BackOff`, `Unhealthy`…) then container log tails | events first — they are the headline |
| **deploys** | the Deployment's `deployment.kubernetes.io/revision` and last Progressing time | reported only inside a window, so policy P5 is handed real evidence |

⛔ **Read-only by construction.** The module uses only `list_*`, `read_*` and
`read_namespaced_pod_log`; a test greps the source for any write verb. And **RBAC enforces the same
thing from the cluster's side** — see below.

### Deploying it into the cluster it diagnoses

```bash
kubectl apply -k k8s/            # namespace, ServiceAccount, ClusterRole, RoleBinding, Job
```

The ClusterRole has **get / list only** — no `watch`, and no `create`, `update`, `patch`, `delete`.
It is bound with a **namespaced RoleBinding** per diagnosed namespace — never a ClusterRoleBinding. The
Job runs as **uid 10001, read-only root filesystem, all capabilities dropped**, under the
`restricted` Pod Security Standard.

⭐ **RBAC is the boundary, not the verifier.** "It only acts when the policy gate approves" is a
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
  change is the image, which the demo hard-codes to `aegis:local`. On EKS, push to ECR and set it:
  ```bash
  kubectl apply -k k8s/     # namespace, ServiceAccount, ClusterRole, RoleBinding — portable as-is
  sed 's#aegis:local#<acct>.dkr.ecr.<region>.amazonaws.com/aegis:0.5.1#' k8s/job.yaml \
    | kubectl create -f -   # one diagnosis, image retargeted to your registry
  ```
- **ECS / Fargate** — the `terraform/` module: a task with a **read-only task role** and **all Linux
  capabilities dropped**, mirroring the k8s Job.

⚠ **Honestly scoped:** the portability that makes EKS work — strict `restricted` admission, no cloud
API dependency — is **CI-verified on k3d**, which enforces the identical Pod Security standard. It has
**not** been run against a live EKS cluster; the manifests are compliant and cluster-agnostic, not
field-tested on managed EKS.

### Proven against a real cluster, both directions

CI creates a **k3d** cluster on every push and:

1. Validates every manifest with `kubectl apply --dry-run=server` — schema-checked by a real API.
2. Asks the API server **both ways**: `kubectl auth can-i list pods` → must be `yes`;
   `get pods` (only `list` is granted), `delete pods`, `patch deployments`, `get secrets`,
   `list pods -n kube-system`, `get nodes` → must each be **`no`**. A check that only confirmed the
   reads would pass a `*`-verb ClusterRoleBinding.
3. Deploys `k8s/test/oom-workload.yaml` — a pod that **actually OOM-kills itself** (300 MiB into a
   48Mi limit) — and waits for the kubelet to record `lastState.terminated.reason: OOMKilled`.
4. Runs AEGIS against it from outside and asserts the *output*: `"backend": "kubernetes"`,
   `scale_up`, `APPROVED_FOR_HUMAN`, `"tool_errors": []`.
5. Imports the image and runs AEGIS **inside** the cluster as the Job, under the read-only
   ServiceAccount, and asserts the same verdict from its logs — plus that it ran as `user=10001`
   with `readOnlyRootFilesystem`.

### Bugs the cluster found that no fake could

**The OOM workload wasn't OOMing.** The first command was `head -c 300M /dev/zero | tail; echo
unreachable`. busybox's `head` rejects the `M` suffix — `invalid number '300M'` — so nothing was
allocated, the `echo` ran, and the container exited **0**. The Deployment restarted it on a loop:
restart count climbing, status `Completed`, zero OOM kills. **It looked exactly like the OOM test
was working.** Caught by reading the container log instead of the restart counter.

**A 40-line log tail arrived as one line.** With the client's default deserialisation,
`read_namespaced_pod_log` returned the *repr* of bytes as a string — `b'2026-…\n2026-…'` — with
literal backslash-n inside. `_log_text()` now reads the raw response and decodes it, and a test
feeds it every shape the client has been seen to return.

**Redaction left a copy of a UUID behind — and the guard refused the run.** A `CrashLoopBackOff`
event embeds the pod UID twice: bare as `(534e3098-…)` and inside a longer token
`…_default_534e3098-…-24ae0fb955bb_0`. The UUID regex ends in `\b`, and `b` followed by `_` is not a
word boundary, so one copy was masked and one was not. `_assert_clean` saw the survivor and raised
`RedactionLeak` rather than send it to a model. The redactor now runs a **final literal sweep**;
⭐ the failure was loud and safe, which is the guard working as designed.

### Then an adversarial review found nine more

Four independent reviewers each tried to refute one claim about the Kubernetes work; every finding
was attacked by a second reviewer, and the upheld ones were fixed, not noted:

- **RBAC was read-only but not minimal** — 12 of 16 granted verb/resource pairs had no caller. Cut
  to the exact five the code makes; CI now asserts `watch pods` and `get pods` are *denied*.
- **The RBAC unit test passed with `roleRef: cluster-admin`.** Now a structural check, not a grep.
- **The Job could hang forever** (no deadline; a stalled read left a thread joined at exit —
  reproduced live) and **deleted its own evidence** after an hour. Fixed with socket timeouts, a Job
  deadline, and a seven-day TTL.
- **`rollout restart` was reported as a deploy**, so P5 would allow a no-op "rollback".
  `deploys()` now compares ReplicaSet images.
- **Init-container OOMs, dead pods, and other workloads' events** were mis-handled — all fixed.
- **The write-verb tripwire was bypassable** by `getattr`/`call_api`/`subprocess`. Now an AST walk.

## Observability that other tools can read

Spans use the **OpenTelemetry GenAI semantic conventions** — `gen_ai.operation.name`,
`gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.usage.input_tokens`,
`gen_ai.usage.output_tokens` — rather than invented attribute names. That is the difference between
traces a tool can read and traces only we can read: **[Langfuse](https://langfuse.com) and
[Arize Phoenix](https://phoenix.arize.com) ingest them over OTLP with no adapter.**

```bash
AEGIS_TRACE_CONSOLE=1 aegis run --incident inc-001     # see the spans
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:6006 aegis run   # ship to Phoenix
```

⚠ The GenAI conventions moved to their own repo in semconv **v1.42.0 (June 2026)** and remain in
*Development* status. Core usage and model attributes are stable enough to build on; expect churn.
Cost has no spec attribute, so it stays under `aegis.cost.usd`.

## What the demo shows

Four recorded incidents, each exercising a different route:

| Incident | Evidence | Proposal | Verdict | Why it matters |
|---|---|---|---|---|
| `inc-001` | 5xx spike **after a deploy** | `rollback_deploy` | **approved_for_human** | Clean signal — and a person still presses the button |
| `inc-002` | OOM kills, **no deploy** | `scale_up` | **approved_for_human** | Does not reach for rollback by reflex |
| `inc-003` | Replica saturated | `failover_replica` | **escalated** | Right action, but multi-service blast radius (`P6`) |
| `inc-004` | Two vague log lines | `escalate_to_human` | **auto_safe** | ⭐ **Declines to invent a fix** |

⭐ `inc-004` is the one to look at. Most agent demos produce a confident answer there. AEGIS scores
low confidence, proposes escalation, and the verifier lets it through precisely *because* it is
inert.

## What running it against a real model taught us

Every test here runs in mock mode. That is correct for CI — but it means the design was, until it
was actually run, an argument rather than a result. Running all four incidents against a live
**Gemini** model produced three findings the mocks could never have surfaced.

**1. ⚠ The model's self-reported confidence is not calibrated — and that breaks a policy.**
It returned **confidence 0.85 on all four incidents**, including `inc-004`, whose entire evidence is
two vague log lines. Policy `P4` escalates below 0.55, so with this model **P4 would essentially
never fire.** A gate that depends on a number the model has no ability to get right is not a gate.

⭐ **This is why `P9-THIN-EVIDENCE` exists.** It counts what was actually gathered — log lines,
distinct metrics, deploys — and escalates when two independent kinds of evidence are missing.
**Ours to measure, not the model's to claim.** It cannot be talked around by a confident tone.

**2. The live model chose a different action from the mock.** On `inc-003` (saturated replica) the
mock proposes `failover_replica`; the live model proposed `restart_pods` — more conservative, and
arguably wrong for the actual cause. ⛔ **So the eval suite encodes the mock's behaviour, not a
correctness standard.** It is a regression gate for routing and policy, and it was already
documented as such — this is the proof.

**3. Model identifiers expire.** `gemini-2.0-flash` was the hardcoded default; the API replied
*"no longer available … use models/gemini-3.6-flash"*. A pinned model id is a dated assumption,
which is why `AEGIS_MODEL` overrides it without touching code.

⭐ The live run also confirmed the parts that matter: **7 identifiers masked before anything left the
process**, cost tracked per call (~$0.009 per incident), and on the thin-evidence incident the model
proposed `no_action` rather than inventing a fix.

## Bugs worth keeping in the README

Each was found by **running** the thing, not by reading it, and each is now guarded. (The Kubernetes bugs
— the OOM workload that wasn't OOMing, and the log tail that arrived as one line — are in the
Kubernetes section above; both needed a real cluster to surface.)

**0. ⭐ The container produced wrong answers and CI was green.** Fixtures lived at the repo root and
were resolved with `Path(__file__).parents[2] / "fixtures"`. That works from a source checkout and
breaks silently once pip-installed — the path lands outside site-packages. Inside the container
every context tool failed, the evidence came back empty, and **all four incidents returned
`AUTO_SAFE`**: wrong verdicts, exit code 0.

⛔ **The CI docker job never noticed, because it ran `docker run … demo` and checked only the exit
code.** It asked *"did it run?"* when the question was *"was it right?"* Fixtures are now package
data, and **both CI jobs assert on the output** — the exact verdicts and that `P6` fires.

**1. Every incident produced the same hypothesis.** The mock reasoner branched on substrings of the
rendered prompt — which contains field labels like `RECENT DEPLOYS:` and metric keys like
`error_rate`. So the "bad deploy" branch always matched, **and the demo still looked like it
worked.** The instrument was asking whether a *word appeared* when the question was whether a
*deploy existed*. Guarded by `test_hypotheses_are_not_all_the_same`.

**2. The audit trail contradicted the verdict.** `auto_safe` and `approved_for_human` shared a
route, so an inert action carrying `requires_approval=False` still logged that it was waiting on an
operator. Guarded by `test_terminal_node_matches_the_verdict`.

**3. The tool timeout was cosmetic.** `ThreadPoolExecutor` used as a context manager calls
`shutdown(wait=True)` on exit — so the deadline fired at 0.3s and the caller then **blocked for the
full 6 seconds anyway**. The docstring said "each tool has a timeout" while the timeout did nothing.
Guarded by `test_a_hanging_tool_does_not_hang_the_run`, which asserts wall-clock, not just the
exception.

⭐ The pattern in all three: **the code claimed something the code did not do, and everything looked
green.** That is why every guard here is written to be *proven able to fail* before it is trusted.

## Architecture

- [`docs/ai-boundary.md`](docs/ai-boundary.md) — **why the model never decides**, the policy table,
  and the honest limits.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — nodes, state, and where to swap fixtures for real
  backends.

## Tests

```bash
make check     # ruff + unit tests + eval gate
```

`tests/` covers redaction and every policy — each with a case proving the policy can **fire**, not
just pass. `evals/` is the behavioural gate: routing, safety invariants, cost recording, budget
enforcement and the audit trail, asserted on every push.

## Limits, stated plainly

- Tools read recorded fixtures; wiring to Loki/CloudWatch/Datadog is one class each, not done here.
- `await_approval` is terminal. Execution is deliberately absent.
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
