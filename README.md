# AEGIS

> AI incident-response orchestrator. **The model proposes. A deterministic verifier decides.
> Nothing here executes against infrastructure.**

**Status:** v0.1.0 — LangGraph pipeline, verified redaction, 8 policies, 4 recorded incidents,
33 tests, eval gate in CI.

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
- **A full audit trail.** Every node records what it saw and did.

## Quickstart

```bash
docker compose up          # no API key needed - runs in mock mode
```

or

```bash
pip install -e ".[dev]"
AEGIS_MOCK=1 aegis demo --verbose
```

To run against the live model: `AEGIS_MOCK=0 ANTHROPIC_API_KEY=sk-... aegis run --incident inc-001`

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

## A bug worth keeping in the README

The first version of the mock reasoner branched on substrings of the rendered prompt. That prompt
contains field labels — `RECENT DEPLOYS:` — and metric keys like `error_rate`. **Every incident
matched the "bad deploy" branch and produced an identical hypothesis, and the demo still looked like
it worked.**

The instrument was asking whether a *word appeared*, when the question was whether a *deploy
existed*. It now reads typed state, and `test_hypotheses_are_not_all_the_same` fails the build if
that class of bug ever returns.

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

## Related

[Helios](https://github.com/veerarakesh56/helios) — Rust + Z3 infrastructure failure simulator where
Claude proposes Terraform fixes and an SMT engine re-verifies each one. Same principle, different
domain: **rigorous core, AI shell.**

## License

Apache-2.0.
