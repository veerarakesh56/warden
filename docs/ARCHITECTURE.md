# Architecture

## Why a state graph and not a loop

A `while` loop with an LLM in it is easy to write and impossible to audit. The graph gives three
things a loop does not:

1. **Named transitions.** "Why did it do that?" is answered by a list of nodes and the state at each
   one, not by scrolling a prompt log.
2. **Typed state at every boundary.** Each node returns a partial state update that is merged, so no
   node can quietly mutate something it does not own.
3. **A place to put the gate.** `verify` is a node with one inbound edge and three outbound ones.
   There is exactly one path from "the model said something" to "something happens", and it goes
   through code that has no model in it.

## The graph

```
START → ingest → gather → redact → analyse → propose → verify ─┬→ halt           → END
                                                               ├→ escalate       → END
                                                               └→ await_approval → END
```

| Node | Model involved? | Responsibility |
|---|---|---|
| `ingest` | no | Record the alert, open the audit trail |
| `gather` | no | Run every context tool; record failures rather than swallowing them |
| `redact` | no | Mask identifiers, **then prove none survived** |
| `analyse` | **yes** | Hypothesis + calibrated confidence (`RootCause`) |
| `propose` | **yes** | One action from a closed enum (`RemediationProposal`) |
| `verify` | no | The binding decision (`Verdict`) |
| `halt` / `escalate` / `await_approval` | no | Terminal outcomes |

Ordering is deliberate: **`gather` precedes `redact` precedes `analyse`.** Evidence is collected
before the model exists in the process at all, so the model cannot influence what evidence is
collected — and nothing unredacted is ever in scope when it is called.

## State

`AegisState` is a `TypedDict`. Every field is optional so partial updates merge cleanly. `audit`
uses an `Annotated[..., _append]` reducer so each node appends rather than overwrites — losing the
trail to a careless return would defeat the purpose of having one.

## Evidence backends

The contract is three methods — `logs`, `metrics`, `deploys` — and `gather()` is the only thing
that calls them. **Nothing above that boundary knows or cares which backend is in use.** That is the
whole reason the boundary exists, and v0.5.0 cashed it in:

| Backend | `AEGIS_BACKEND` | Reads | Proven by |
|---|---|---|---|
| `FixtureBackend` | `fixture` (default) | recorded incidents shipped as package data | the eval gate, every push |
| `KubernetesBackend` | `k8s` | a live cluster — pod status, events, log tails, Deployment revision | the CI `k8s` job: a real k3d cluster, a pod that really OOM-kills, RBAC checked both ways, run from outside *and* inside the cluster |

Adding Loki, CloudWatch or Datadog is the same shape: one class, three methods, passed to
`run(alert, backend=...)`.

### `KubernetesBackend` — what it is honest about

- **Metrics are pod-status counts, not utilisation.** `restart_count`, `oom_killed_count`,
  `crashloop_count`, `pods_ready`, `pods_total`, `memory_limit_mib`. A metrics server would add
  CPU/memory %, and k3d does not ship one. The counts are also what an on-call engineer reads first.
- **Read-only by construction.** Only `list_*`, `read_*`, `read_namespaced_pod_log`. A test greps
  the module for any write verb. The mutation check adds a `delete_namespaced_pod` call and asserts
  the suite goes red.
- **Logs are read raw.** `_preload_content=False`, then `_log_text()` decodes. The client's default
  path returned the repr of bytes as a str against a real k3s cluster — one line, literal `\n`.
- **A missing Deployment is `[]`, not an error.** Bare pods and StatefulSets have none; policy P5
  then refuses any rollback, which is the correct outcome. A 403, by contrast, propagates — it means
  the RBAC is wrong, and hiding it would make a broken deployment look healthy.

### The alert → workload mapping

```
namespace  = alert.labels["namespace"]  or $AEGIS_K8S_NAMESPACE  or "default"
selector   = alert.labels["selector"]   or f"app={alert.service}"
deployment = alert.labels["deployment"] or alert.service
```

### RBAC is the boundary

`k8s/rbac.yaml`: a **ClusterRole** holding the read-only verb set, granted by a **namespaced
RoleBinding** in each namespace AEGIS may diagnose. Never a ClusterRoleBinding. The first draft used
a plain Role in the `aegis` namespace — which cannot see pods in `default`, where workloads live.
A Role only reaches its own namespace; caught before apply.

CI asks the API server directly, both ways: the **exact five** reads the code makes must be `yes`
(list pods, get pods/log, list events, get deployments, list replicasets); writes, unbound
namespaces and cluster-scoped reads must each be `no`. Including `get pods` (only `list` is granted)
and `get secrets` → `no`.

Every tool call is individually caught **and runs under a wall-clock deadline**
(`AEGIS_TOOL_TIMEOUT`, default 5s). A failure or timeout becomes an entry in `context.tool_errors`,
which policy `P8` reads — so a partial picture is *visible to the verifier* rather than looking like
a complete one. This is the difference between degrading and lying.

⛔ **The timeout is implemented with a thread pool shut down using `wait=False`, and that detail is
load-bearing.** Using `ThreadPoolExecutor` as a context manager calls `shutdown(wait=True)` on exit,
which blocks until the hung worker finishes — the deadline fires, then the caller waits the full
duration anyway. It looked implemented and did nothing.
⚠ A timed-out thread is **abandoned, not killed**; Python cannot force-stop one. The caller stops
waiting, which is the point of a deadline. A production backend client should also set its own
socket timeout so the thread actually ends.

## Tracing

`observability.py` wires OpenTelemetry. One span per node —
`aegis.run → tool.* → analyse → propose → verify` — with attributes for confidence, action, blast
radius, verdict, policies fired, and **token/USD cost per step**.

Defaults to no exporter; `AEGIS_TRACE_CONSOLE=1` prints spans, `OTEL_EXPORTER_OTLP_ENDPOINT` ships
them to a collector, `AEGIS_TRACE=0` disables tracing entirely for quiet test runs. If the OTLP
exporter package is absent it falls back to console rather than raising — **telemetry must never take
the system down.**

## Deployment

`terraform/` defines an ECS Fargate task. Two choices are deliberate: the **task role is read-only**
(AEGIS inspects infrastructure, it does not change it — IAM is the boundary, not the verifier), and
the API key is passed as a **Secrets Manager ARN** so it never enters Terraform state.
⚠ Validated in CI, never applied against a live account.

## Cost and budget

`LLMClient` charges every call against a running `CostRecord` and raises `BudgetExceeded` past the
ceiling. The ceiling is enforced in the call path, not reported afterwards — a budget that cannot
stop anything is a number on a dashboard.

⚠ The per-token prices are **configuration, not fact** (`AEGIS_PRICE_IN` / `AEGIS_PRICE_OUT`).
Verify them against current vendor pricing before quoting any figure.

## Structured output

`LLMClient.structured()` returns a validated pydantic object or raises `ModelRefused` after retries.
There is no code path that accepts unvalidated model text. Free text cannot be verified, and
anything that cannot be verified cannot be gated.

## Mock mode

`AEGIS_MOCK=1` replaces both model calls with deterministic factories that read **typed state**.
This is what CI and the eval suite use, so the demo runs with no key and no network.

⛔ The mocks take **no arguments** on purpose. An earlier version passed the rendered prompt and
branched on substrings of it — matching field labels rather than values, so every incident produced
the same hypothesis while appearing to work. Reading typed state through a closure removes the
possibility, and `test_hypotheses_are_not_all_the_same` guards it.

## Testing strategy

- `tests/` — unit. Every policy has a test that proves it can **fire**. A gate nobody has watched
  reject something is not a gate.
- `evals/` — behavioural. Routing per incident, the "nothing is auto-executed" invariant across all
  incidents, redaction effectiveness, cost recording, budget enforcement, audit completeness.

Both run in CI on every push, plus a container build that runs the demo end to end — because a green
local run is not evidence that a stranger can clone it and have it work.
