# Why the model never decides

The whole of AEGIS is one argument: **a stochastic component may propose, but it must not be the
thing that decides.** Everything else — the graph, the schemas, the policies — is machinery for
holding that line.

## The problem with "the agent fixed it"

An LLM asked to remediate an incident will always produce something. Given thin evidence it does not
say "I don't know"; it produces a confident, well-written, plausible action. That failure mode is
not rare and it is not a prompting mistake — it is what the tool is for. A model is a generator, and
generators generate.

In most domains a wrong answer is an inconvenience you notice and correct. In incident response the
wrong action is executed against production during the exact window when the system is already
degraded and the humans are already stressed. **A hallucination in a chat assistant is a bug. In an
operations tool it is an outage with a plausible explanation attached.**

## Where the line sits

    alert → gather evidence → REDACT → [ model reasons ] → [ model proposes ] → VERIFY → human
                               ^^^^^^                                            ^^^^^^
                               nothing unredacted                                nothing the model
                               reaches the model                                 said is trusted

Two nodes carry the argument.

**`redact` runs before any token reaches the model.** Not because the model is untrustworthy with
data, but because sending customer identifiers to a third party is a decision the system should not
be able to make by accident. The redactor re-scans its own output and raises if any original value
survived — the check can fail, and there is a test that proves it fails.

**`verify` runs after everything the model produced.** It is plain Python over typed data: no
prompt, no probability, no model call. It answers a different question from the model's. The model
answers *"what would fix this?"*. The verifier answers *"is this allowed, proportionate, reversible,
and supported by evidence?"* — and only the second question is safety-critical.

## What the verifier actually catches

The policies are not hypothetical. Each one has a test that proves it can fire:

| Policy | The failure it prevents |
|---|---|
| `P1-ENV-ALLOWLIST` | An action that is fine in dev being run in prod |
| `P2-IRREVERSIBLE-IN-PROD` | Anything with no undo, at any confidence |
| `P3-NO-EVIDENCE` | Acting on a hypothesis formed from nothing |
| `P4-LOW-CONFIDENCE` | Treating a guess as a plan |
| `P5-NO-DEPLOY-TO-ROLL-BACK` | Rolling back a deploy that does not exist — the classic confident hallucination |
| `P6-BLAST-RADIUS` | Unattended actions that cross service boundaries |
| `P7-DISPROPORTIONATE` | Failing over a database because of a `low` alert |
| `P8-PARTIAL-CONTEXT` | Treating a partial picture as a complete one when a tool timed out |
| `P9-THIN-EVIDENCE` | Acting on two log lines because the model *said* it was confident |

⭐⭐ **`P9` is the one that came from evidence rather than reasoning.** Against a live model, all four
bundled incidents came back at **confidence 0.85** — including the one whose entire evidence is two
vague log lines. `P4` escalates below 0.55, so with that model it would never fire.

**A model's self-reported confidence is not a measurement.** It is a token sequence that looks like
one. `P9` counts what was actually gathered — log lines, distinct metrics, deploys — because a
number we compute cannot be influenced by how sure the model sounds.

⭐ **P5 is the one to look at.** The model is not lying when it proposes a rollback — it is
pattern-matching "errors after change" and that is usually right. It is wrong *here* because the
evidence contains no deploy. No amount of prompt engineering reliably prevents this. A four-line
deterministic check does, every time, and can be shown to an auditor.

## The closed action set

`ActionKind` is an enum, not a string. The model cannot propose `delete_database` because there is
no such member and the response fails schema validation before it reaches the verifier.

This costs flexibility and that is the intended trade. Adding a capability should be a pull request
someone reviews, not something the model can reach for at 3am.

## What the evals prove, and what they do not

The eval suite runs in mock mode, so it tests **routing, policy and redaction** — the deterministic
parts that must never drift. It fails the build if a change makes the graph behave differently.

⛔ **It is not a measure of live model quality.** That needs a scored eval against the real model on
a larger corpus, and it belongs in a nightly job, not a pre-merge gate — different instrument,
different question. Claiming these evals measure reasoning quality would be the same category error
this document exists to warn about.

## The honest limits

- The tools read recorded fixtures. Wiring them to Loki, CloudWatch or Datadog is one class each,
  but it has not been done here.
- `await_approval` is a terminal node. Real Slack approval and execution are deliberately absent —
  the moment AEGIS can execute, it needs an entirely different security review.
- Redaction is regex-based. It catches the identifier classes it knows about. It is a strong control
  against accidental leakage, not a guarantee against a determined adversary.
- The mock reasoner is a stand-in with hand-written branches. It exists so the routing can be tested
  deterministically, not to imitate model quality.

## Prior art

The same conviction runs through [Helios](https://github.com/veerarakesh56/helios) — a Rust + Z3
infrastructure simulator where Claude narrates counter-examples and proposes Terraform fixes, and
the SMT engine re-verifies every proposed fix before it counts. Two tools, one principle: **rigorous
core, AI shell.**
