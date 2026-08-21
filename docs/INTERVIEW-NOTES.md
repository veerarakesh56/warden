# Defending this project

⛔ **A flagship you cannot explain out loud is worse than no flagship.** These are the questions this
project invites. If any answer here is not yet yours, read the code before you send the link.

---

## 1. Why a state graph and not a loop?

A `while` loop with a model in it is easy to write and impossible to audit. The graph gives named
transitions, typed state at every boundary, and — the part that matters — **exactly one path from
"the model said something" to "something happens"**, and it goes through `verify`, which contains no
model. When an operator asks "why did it do that?", the answer is a list of nodes and the state at
each, not a scrollback of prompts.

## 2. Why does redaction run before the model rather than after?

Sending customer identifiers to a third party should not be something the system can do by accident.
Redaction after the fact is not a control; it is a cleanup.

## 3. How do you know the redaction worked?

It re-scans its own output and raises `RedactionLeak` if any original value survived. **The guard has
a test proving it can fail** — `test_leak_is_fatal_not_a_warning`. A guard nobody has watched reject
something is not a guard.

⚠ Honest limit: it is regex-based. Strong against accidental leakage, not a guarantee against a
determined adversary.

## 4. Why is the action set an enum instead of a string?

So the model cannot propose `delete_database`. There is no such member, so the response fails schema
validation before it ever reaches the verifier. This costs flexibility deliberately — adding a
capability should be a pull request someone reviews, not something a model can reach for at 3am.

## 5. What does policy P5 actually catch?

A rollback proposed when **no deploy appears in the gathered evidence**. The model is not lying — it
is pattern-matching "errors after change", which is usually right. It is wrong here. No amount of
prompt engineering reliably prevents that; four lines of deterministic code do, every time, and can
be shown to an auditor.

## 6. What do the evals prove — and what do they not?

They prove **routing, policy and redaction do not drift**, and they run in CI on every push.

⛔ They do **not** measure live model quality. That needs a scored eval against the real model on a
larger corpus, in a nightly job — a different instrument answering a different question. Claiming
otherwise would be the same category error the project exists to warn about.

## 7. Name bugs you found in your own code.

Three, all found by running it, all now regression tests:

- **Every incident produced the same hypothesis.** The mock reasoner branched on substrings of the
  rendered prompt, which contains field labels like `RECENT DEPLOYS:`. The instrument asked whether a
  *word appeared* when the question was whether a *deploy existed* — and the demo still looked like
  it worked.
- **The audit trail contradicted the verdict.** `auto_safe` shared a route with
  `approved_for_human`, so an inert action logged that it was awaiting an operator.
- **The tool timeout was cosmetic.** `ThreadPoolExecutor` as a context manager calls
  `shutdown(wait=True)` on exit, so the deadline fired at 0.3s and the caller then blocked the full
  6 seconds anyway. The docstring claimed a timeout the code did not implement.

⭐ This is the strongest answer in the interview. Anyone can show a repo. Almost nobody volunteers
the defect they found in their own instrument.

## 8. Why is the ECS task role read-only?

Because "it only acts when the verifier approves" is a design argument, not a security boundary. IAM
is the boundary. If the credentials cannot mutate infrastructure, a bug in my policy engine cannot
either.

## 9. Did you use AI to build this?

**Yes — say so plainly.** Then describe how it was verified: every guard is proven able to fail
before it is trusted; the eval gate runs in CI; the container is built and run on a clean machine
because a green local run is not evidence; the Terraform is validated on a clean runner.

For an AI-platform role that answer is a strength — it is literally the job. The candidate claiming
they never use AI in 2026 is the one with the credibility problem.

⚠ The commit history carries a `Co-Authored-By: Claude` trailer. Consistent with the above.

## 10. What would you do next?

In order, and be specific — vagueness here undoes everything above:

1. **Wire a real backend.** `FixtureBackend` → CloudWatch/Loki. One class; the boundary exists for it.
2. **A scored nightly eval** against the live model, separate from the deterministic CI gate.
3. **Slack approval + execution**, behind its own security review — the moment AEGIS can act, the
   threat model changes completely.
4. **Narrow the IAM read policy** from `resources = ["*"]` with condition blocks.
5. **Checkpointing.** LangGraph supports it; the graph is written for it but it is not enabled.
