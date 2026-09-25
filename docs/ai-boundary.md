# Why the model never decides

The whole of WARDEN is one argument: **a stochastic component may propose, but it must not be the
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

⛔ **"Reversible" is answered by WARDEN, not asked of the model** — and it was not always so. Until
2026-09-12 `P2` read a `reversible` boolean the *model* wrote, so a proposal could widen its own
permissions by claiming its action could be undone, and two live models gave the identical operation
opposite verdicts (`live-model-run-2026-09-06.md` §3). Reversibility is now a property of the
operation, fixed in `models.py::ACTION_FACTS`, which the model cannot write and an operator cannot
configure. The same field arriving from an MCP client — an untrusted caller — buys nothing either.

## What the verifier actually catches

The policies are not hypothetical. Each one has a test that proves it can fire:

| Policy | The failure it prevents |
|---|---|
| `P1-ENV-ALLOWLIST` | An action that is fine in dev being run in prod |
| `P2-IRREVERSIBLE-IN-PROD` | Anything with no undo, at any confidence — classified by WARDEN's action table, never by the proposal |
| `P3-NO-EVIDENCE` | Acting on a hypothesis formed from nothing |
| `P4-LOW-CONFIDENCE` | Treating a guess as a plan |
| `P5-NO-DEPLOY-TO-ROLL-BACK` | Rolling back a deploy that does not exist — the classic confident hallucination |
| `P6-BLAST-RADIUS` | Unattended actions that cross service boundaries — measured as the wider of WARDEN's per-action floor and the claim, so understating it buys nothing |
| `P7-DISPROPORTIONATE` | Failing over a database because of a `low` alert |
| `P8-PARTIAL-CONTEXT` | Treating a partial picture as a complete one when a tool timed out |
| `P9-THIN-EVIDENCE` | Acting on two log lines because the model *said* it was confident |
| `P10-CLAIM-CONTRADICTS-TABLE` | Discarding a model's warning that something cannot be undone — it does not decide, but it is not ignored either |
| `P11-ACTION-CONTRADICTS-EVIDENCE` | An action that cannot fix what the evidence shows: `scale_up` on OOM kills when every pod is failing, `scale_down` on OOM, `restart_pods` on an unpullable image, `terminate_connections` when the only long sessions are working queries, `failover_replica` with no lag |
| `P12-NO-ACTION-WITH-SYMPTOMS` | "Nothing to do" waved through while the evidence counts broken things (OOM kills, crash loops, unready pods, stuck or blocked sessions, long queries, replica lag) |

⚠ **`P11` and `P12` were written on 2026-09-25 from measured failures** - all three EKS runs the gate
wrongly allowed were `scale_up` against pods OOM-killed before becoming ready. A re-run of the same
scenarios is therefore not an independent test of them. Replaying all 48 recorded EKS/RDS runs through
the new gate changed six verdicts, all on wrong answers, and no correct run's; P11 escalates all
three dangerous EKS runs.

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

- The tools read live systems - CloudWatch and ECS, Kubernetes (measured on managed EKS), and
  databases (PostgreSQL measured on RDS) - or recorded fixtures for the demo. They do NOT read
  CloudWatch for EKS or RDS, Performance Insights, or any CPU/memory/IOPS figure for those; every
  report says what was and was not read.
- `await_approval` is a terminal node of the diagnosis graph. Execution exists separately - live
  remediation behind the four-way gate, dry-run by default - but approving it from Slack does not,
  and would need its own security review.
- Redaction is regex-based. It catches the identifier classes it knows about. It is a strong control
  against accidental leakage, not a guarantee against a determined adversary.
- The mock reasoner is a stand-in with hand-written branches. It exists so the routing can be tested
  deterministically, not to imitate model quality.

## Prior art

The same conviction runs through [Helios](https://github.com/veerarakesh56/helios) — a Rust + Z3
infrastructure simulator where Claude narrates counter-examples and proposes Terraform fixes, and
the SMT engine re-verifies every proposed fix before it counts. Two tools, one principle: **rigorous
core, AI shell.**
