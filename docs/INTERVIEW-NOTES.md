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

## 7b. ⭐ What happened when you ran it against a real model?

**The best question you can be asked, because most portfolio projects were never run for real.**

Three findings, all documented in the README:

1. **Confidence came back at 0.85 on all four incidents** — including the one whose evidence is two
   vague log lines. `P4` escalates below 0.55, so with that model it would never fire. **A model's
   self-reported confidence is a token sequence that looks like a measurement.** That is why `P9`
   exists: it counts gathered evidence, which the model cannot influence by sounding sure.
2. **The live model picked a different action from the mock** on the replica incident. So the eval
   suite is a regression gate for routing and policy — not a correctness standard. Worth saying
   before someone else points it out.
3. **The hardcoded model id had expired.** `gemini-2.0-flash` returned "no longer available". Pinned
   model names are dated assumptions; `AEGIS_MODEL` overrides without a code change.

⭐ If asked "what surprised you?" — this is the answer. It shows the design survived contact with a
real model *and* that you changed the design when the evidence said to.

## 7e. ⭐⭐ You had it adversarially reviewed. What did that find, and what did you do?

**This is the strongest thing to talk about — it shows the work is bigger than the demo.** Four
independent reviewers each tried to *refute* one claim about the Kubernetes work; every finding was
then attacked by a second reviewer; the upheld ones were fixed, not filed.

What it caught, and the fix:
- **RBAC was read-only but not *minimal*** — 12 of 16 granted verb/resource pairs had no caller. I
  cut it to the exact five the code makes, and CI now asserts the unused verbs (`watch pods`,
  `get pods`) are *denied*, not just that writes are.
- **The RBAC test passed with `roleRef: cluster-admin`** — it was a grep for the word "delete". Now
  a structural check: the binding must point at the ClusterRole in the file, verbs ⊆ {get, list}.
- **The Job could hang forever** (no deadline; a stalled read left a thread the interpreter joins at
  exit — I reproduced it live) and **deleted its own diagnosis after an hour**. Both fixed.
- **`kubectl rollout restart` was reported as a deploy**, so the rollback policy would fire on a
  no-op. The backend now compares ReplicaSet images.

⭐ The honest framing: a green test suite proves the tests ran, not that they'd notice a real
regression. The review, and the mutation check (which deliberately breaks the code and asserts the
suite goes red), are how I check the tests themselves. Two mutations "survived" the last run — both
were the mutation *script* pointing at code I'd since rewritten, not test holes; I re-anchored them
and they're caught.

## 7f. Something broke while you were building it against the real cluster. What?

**The redaction leak guard fired — correctly.** A `CrashLoopBackOff` event embeds the pod UID
twice, once inside a longer token where the `\b` regex boundary doesn't match. One copy got masked,
one didn't, and `_assert_clean` refused to send the half-redacted text to the model. I added a final
literal sweep so every found value is replaced everywhere. The point I'd make: **the failure was
loud and safe.** The guard exists precisely so a redaction miss stops the run instead of leaking
quietly — and that's what happened, on real data, before any model saw it.

## 7c. ⭐ Has it actually run against Kubernetes, or does it just talk about pods?

**Both — and the second was true for four releases before the first.** Until v0.5.0 the vocabulary
was Kubernetes (`restart_pods`, OOM-killed containers) and the evidence was JSON fixtures. That is
the exact defect shape the rest of the project exists to catch: a claim the code did not back.

Now: a `KubernetesBackend` reads pod status, events, log tails and Deployment revisions; CI spins up
a **real k3d cluster** on every push, deploys a pod that **really OOM-kills itself**, and asserts
AEGIS reaches `scale_up` / `APPROVED_FOR_HUMAN` — run from **outside** the cluster *and* from
**inside** it as a Job under a read-only ServiceAccount.

⭐ **Two bugs only the real cluster could surface** — say these, they are the proof you ran it:
- The "OOM workload" **wasn't OOMing**. busybox `head -c 300M` rejects the `M` suffix; nothing was
  allocated, the container exited 0, the Deployment restarted it in a loop. Restart count climbing,
  status `Completed`, zero OOM kills — it *looked* like the test worked. Caught by reading the
  container log, not the restart counter.
- The client returned a 40-line log tail as **one line**: the repr of bytes as a str, `b'…\n…'`.
  Invisible with a fake client.

## 7d. Why a ClusterRole with a namespaced RoleBinding, and not a Role?

Because a Role only reaches its own namespace. The first draft put a Role in `aegis`; it could not
see pods in `default`, where the workloads live. A ClusterRole holds the *permission set*; a
RoleBinding grants it in *one namespace at a time*. There is deliberately no ClusterRoleBinding —
that would be cluster-wide. To diagnose another namespace you add one RoleBinding there; you never
widen the role.

And it is tested **both ways** from the API server's own view: reads `yes`, writes `no`, an unbound
namespace `no`, cluster-scoped `no`, `get secrets` `no`. A check that only confirmed the reads
would pass a `*`-verb ClusterRoleBinding.

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
