# AEGIS

> AI incident-response orchestrator. **The model proposes. A deterministic verifier decides.
> Nothing here executes against infrastructure.**

**Status:** v0.3.0 — LangGraph pipeline, verified redaction, 8 policies, real tool timeouts,
**MCP server** exposing the policy gate, OpenTelemetry **GenAI semantic conventions**, Terraform
deploy, **provider-agnostic** (Gemini free tier, Ollama local, Anthropic, OpenAI-compatible),
4 recorded incidents, **69 tests**, eval gate in CI.

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
- **A deterministic gate.** Eight policies in plain Python decide what happens. No prompt, no
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
| ⭐ **`verify_remediation`** | Runs the deterministic 8-policy gate over a proposed action and returns a binding verdict with the policy ids that fired. **No model involved in the decision.** |
| `redact_text` | Masks identifiers and verifies its own output. Use before putting logs in any prompt |
| `gather_incident_context` | Logs, metrics and deploys under a timeout — already redacted |
| `describe_policy` | The eight policies and the per-environment allow-list |

⭐⭐ **Why this is the interesting one:** an agent written by someone else, with no safety layer of its
own, can ask AEGIS whether the thing it is about to do is allowed in production — and get an
auditable answer with policy ids. **The closed action enum is published in the tool schema**, so a
client cannot even name an action outside the set. Every response carries `may_execute: false`.

Built on the official `mcp` Python SDK **v2** (2026-07-28 spec, stateless core).
⚠ `mcp.server.fastmcp` does not exist in v2 — it was removed in the rework. This uses the low-level
`Server` with explicit callbacks.

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

## Three bugs worth keeping in the README

Each was found by **running** the thing, not by reading it, and each is now a regression test.

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
