# Design decisions

Why WARDEN is built the way it is, and what each choice costs. The [README](../README.md) covers what
the tool does; this covers why, including the places where the honest answer is a limit rather than a
feature.

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

## 3. How is the redaction known to work?

Patterns find values; a sweep then masks every copy of a found secret and every standalone copy of a
found identifier (a bare "500" is not taken for the tenant `user_id=500`), across all of an
incident's text at once (`redact_many`: a value found in a later line is masked in the earlier ones).
A plain word after a credential key ("--token not set", "api_key=true") is not taken for its value.
Nothing here can see a secret no pattern matched.

The check that CAN fail is the outbound gate's G5, which re-runs every pattern on what leaves and
blocks the message (`tests/test_gate.py`, `tests/test_cli.py`). An earlier re-scan inside `redact()`
used the sweep's own rule, so it could never fire on a real leak; the second independent review
(2026-09-30) found that, and it was removed.

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

## 7. Bugs this project found in its own code

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

## 8. What changed after running it against a real model

Three findings:

1. **Confidence came back at 0.85 on all four incidents** — including the one whose evidence is two
   vague log lines. (That was an earlier run over the then-four bundled incidents, not recorded as
   an artefact; the recorded run, `docs/live-model-run-2026-09-06.md`, covers five and shows the
   same 0.85 on all.) `P4` escalates below 0.55, so with that model it would never fire. **A model's
   self-reported confidence is a token sequence that looks like a measurement.** That is why `P9`
   exists: it counts gathered evidence, which the model cannot influence by sounding sure.
2. **The live model picked a different action from the mock** on the replica incident. So the eval
   suite is a regression gate for routing and policy — not a correctness standard.
3. **The hardcoded model id had expired.** `gemini-2.0-flash` returned "no longer available". Pinned
   model names are dated assumptions; `WARDEN_MODEL` overrides without a code change.

## 9. What an adversarial review found, and what was done about it

Four independent reviewers each tried to *refute* one claim about the Kubernetes work; every finding
was then attacked by a second reviewer; the upheld ones were fixed rather than filed.

- **RBAC was read-only but not *minimal*** — 12 of 16 granted verb/resource pairs had no caller. Cut
  to the exact five the code makes (six since 2026-09-25, when `list horizontalpodautoscalers` was
  added), and CI now asserts the unused verbs (`watch pods`, `get pods`)
  are *denied*, not just that writes are.
- **The RBAC test passed with `roleRef: cluster-admin`** — it was a grep for the word "delete". Now
  a structural check: the binding must point at the ClusterRole in the file, verbs ⊆ {get, list}.
- **The Job could hang forever** (no deadline; a stalled read left a thread the interpreter joins at
  exit, reproduced live) and **deleted its own diagnosis after an hour**. Both fixed.
- **`kubectl rollout restart` was reported as a deploy**, so the rollback policy would fire on a
  no-op. The backend now compares ReplicaSet images.

A green test suite proves the tests ran, not that they would notice a real regression. The review,
and the mutation check (which deliberately breaks the code and asserts the suite goes red), are how
the tests themselves are checked. Mutations have survived twice, and the two cases are different in
kind. On an earlier run two survived because the mutation *script* was anchored on code since
rewritten, not because of test holes; they were re-anchored and are now caught. On 2026-09-06 one
survived that **was** a genuine hole in a test: the AST tripwire asserting this module is read-only
was collecting zero statements out of `database.py` — every adapter hands its SQL to a helper rather
than to `.execute()` directly — so the test asserted `not []` and had always been green. The checker
now follows that indirection, two tests pin it, and a full re-run then reported 31 caught, 0 survived (the list has since grown to 35, all
caught on a run on 2026-09-25).

## 10. What broke while building against a real cluster

**The redaction leak guard fired — correctly.** A `CrashLoopBackOff` event embeds the pod UID twice,
once inside a longer token where the `\b` regex boundary does not match. One copy got masked, one did
not, and `_assert_clean` refused to send the half-redacted text to the model. A final literal sweep
now replaces every found value everywhere.

The failure was loud and safe. The guard exists precisely so a redaction miss stops the run instead
of leaking quietly — and that is what happened, on real data, before any model saw it.

## 11. Has it run against Kubernetes, or does it only talk about pods?

**Both — and the second was true for four releases before the first.** Until v0.5.0 the vocabulary
was Kubernetes (`restart_pods`, OOM-killed containers) and the evidence was JSON fixtures. That is
the exact defect shape the rest of the project exists to catch: a claim the code did not back.

Now a `KubernetesBackend` reads pod status, events, log tails and Deployment revisions; CI spins up a
**real k3d cluster** on every push, deploys a pod that **really OOM-kills itself**, and asserts
WARDEN proposes `scale_up` and that `P11-ACTION-CONTRADICTS-EVIDENCE` escalates it (`ESCALATED`) —
run from **outside** the cluster *and* from **inside** it as a Job under a read-only
ServiceAccount. Until 2026-09-25, when P11 was added, the asserted verdict was `APPROVED_FOR_HUMAN`.

⭐ **Two bugs only the real cluster could surface:**
- The "OOM workload" **wasn't OOMing**. busybox `head -c 300M` rejects the `M` suffix; nothing was
  allocated, the container exited 0, the Deployment restarted it in a loop. Restart count climbing,
  status `Completed`, zero OOM kills — it *looked* like the test worked. Caught by reading the
  container log, not the restart counter.
- The client returned a 40-line log tail as **one line**: the repr of bytes as a str, `b'…\n…'`.
  Invisible with a fake client.

## 12. Why a ClusterRole with a namespaced RoleBinding, and not a Role?

Because a Role only reaches its own namespace. The first draft put a Role in `warden`; it could not
see pods in `default`, where the workloads live. A ClusterRole holds the *permission set*; a
RoleBinding grants it in *one namespace at a time*. There is deliberately no ClusterRoleBinding —
that would be cluster-wide. To diagnose another namespace you add one RoleBinding there; the role is
never widened.

It is tested **both ways** from the API server's own view: reads `yes`, writes `no`, an unbound
namespace `no`, cluster-scoped `no`, `get secrets` `no`. A check that only confirmed the reads would
pass a `*`-verb ClusterRoleBinding.

## 13. Why is the ECS task role read-only?

Because "it only acts when the verifier approves" is a design argument, not a security boundary. IAM
is the boundary. If the credentials cannot mutate infrastructure, a bug in the policy engine cannot
either.

## 14. Was AI used to build this?

Yes. Every guard is proven able to fail before it is trusted; the eval gate runs in CI; the container
is built and run on a clean machine because a green local run is not evidence; the Terraform is
validated on a clean runner.

⚠ The commit history carries a `Co-Authored-By: Claude` trailer, consistent with the above.

## 15. What is next

1. ~~Wire a real backend.~~ Done: CloudWatch + ECS, Kubernetes and five database engines, measured
   on ECS, managed EKS and RDS PostgreSQL (`docs/bench/`). Still open: CloudWatch for EKS and RDS
   (Container Insights, control-plane logs, RDS log exports, Performance Insights), Loki, Datadog.
2. **A scored nightly eval** against the live model, separate from the deterministic CI gate.
3. **Slack approval.** Execution exists (live remediation behind the four-way gate, dry-run by
   default); approving it from Slack does not, and needs its own security review.
4. **Narrow the IAM read policy** from `resources = ["*"]` with condition blocks.
5. **Checkpointing.** Done by Temporal since Phase 2: IncidentWorkflow and RemediationWorkflow are durable, and a worker restart replays the history (LangGraph, which ran the graph before, was removed).

The full, current plan is [`ROADMAP.md`](ROADMAP.md).

## 16. Decisions of 2026-09-28 (after the full audit and live research)

Each was researched live on that day (`docs/research/2026-09-28/`) and decided on quality, not cost.

- **Architecture principle: Meta's "Agents Rule of Two."** An agent should have at most two of
  three properties: untrusted input, sensitive data, the ability to change state. WARDEN has the first
  two, and changes state only through a signed human approval. "The Attacker Moves Second"
  (arXiv 2510.09023) broke 12 published defences with adaptive attacks, so detectors (Prompt
  Guard, P16) are tripwires, never gates.
- **Temporal Cloud, not self-hosted.**
  - Self-hosted Temporal's default authorizer allows every call.
  - Self-hosting needs real operating effort, upgrades that cannot skip versions, and a stream of
    CVE fixes.
  - Cloud gives a 99.99% HA option and about 2x lower latency.
  - Temporal's own audit logs cover account actions only, so WARDEN keeps its own record of who
    approved and who triggered.
- **Keep the Python verifier; no Rego/Cedar rewrite.**
  - Most policies need evidence that Python computes first.
  - Cedar files evaluated in-process with `cedarpy` are an option later, when a security team wants
    to own the policy.
  - A network policy service would be one more thing that can fail during an outage.
- **No hosted guardrail in the approval path** (Lakera, Prisma AIRS, Cisco AI Defense,
  AlignmentCheck).
  - They detect injection-shaped text, which WARDEN already treats as inert.
  - They are bypassable.
  - They would send production logs to a third party.
- **No Jev.** It was two weeks old, hosted only, with unverified calibration. WARDEN calibrates on
  independent labels instead: Wilson bounds and conformal abstention.
- **KMS Ed25519 for audit signing, S3 Object Lock as the external anchor.** This mirrors
  CloudTrail's own digest design. The key never leaves the HSM.
- **Passkeys (WebAuthn) for approvals, signed over the exact plan hash.** This is stronger than a
  login-based approval (GitHub environments, PagerDuty tasks).
- **Identity is AWS-native; Teleport is an optional adapter.** Teleport's agent features were still a
  preview in 2026-09. Re-checked 2026-10-04: Teleport has since added Beams, a runtime for infrastructure agents, and
  agent behaviour controls to its commercial Identity Security platform (July 2026). WARDEN still needs none of it:
  every control it relies on - a 900-second session per incident, the incident as SourceIdentity, the approvers and
  plan as session tags, a session policy naming the plan's exact resources, and AWS's own record of each session held
  to the audit (actor_use.py) - comes from STS and CloudTrail, free and in the account. A company that runs Teleport
  can add it as an adapter; nothing in WARDEN requires it.
- **Claude Sonnet 5 on the Claude API for the cloud window** (owner, 2026-10-09: the owner's API credits; replaces the
  Gemini choice below). Qualified on the API the same day with the SDK the runtime image ships - 20 of 30 correct,
  none wrong and allowed, every incident answered, $0.48; an earlier run on an older SDK scored 18 (both pass;
  src/warden/data/providers.yaml). Sonnet 5, not the newer Sonnet 5.5, which failed the same bar.
- *(Superseded 2026-10-09)* **Gemini on Google AI Studio's free tier for the first cloud window** (owner, 2026-10-04), while Bedrock access waits
  on AWS Support. Accepted with its costs stated: Google may use free-tier prompts to improve its products (WARDEN sends
  only redacted prompts - typed facts, never raw logs), and the free quota is small (on 2026-10-03 it answered 4 of 30
  incidents in a day), so the qualification (M20) runs in daily batches (`qualify_provider.py --resume`) and the model
  diagnoses in the cloud only once it has passed. Bedrock, or Gemini's paid tier, remains the production choice.
- **Bedrock Claude Sonnet 5 for production** (owner, 2026-10-03), chosen by WARDEN's own replay
  results, never by public leaderboards, which flip between systems. On the 30 recorded incidents
  (src/warden/data/providers.yaml): Fable 5.1 and Fable 5 scored 20 correct, Sonnet 5 19, Sonnet 5.5 16,
  Opus 5 15 and Opus 5.5 10, none with a wrong fix let through. Sonnet 5 passed the bar at a fifth of
  Fable 5.1's price. Opus 5.5, the earlier choice, failed it: it escalated 26 of 30 incidents.
- **Single tenant per company.** No shared namespace, database or bucket across companies.
- **English-only UI and reports**, UTF-8 safe. Non-English log handling (M23) is recorded as open.
- **Region:** the runtime and the Temporal namespace both run in ap-south-2. Bedrock uses the
  India geo profile `in.anthropic.claude-sonnet-5`, so inference stays within India; the global
  profile `global.anthropic.claude-sonnet-5` is the fallback. Both were listed ACTIVE from ap-south-2
  on 2026-10-03, read live. Opus 5.5, the earlier choice, had only a global profile (checked
  2026-09-28). Sonnet 5 retires on Anthropic's platforms no sooner than 2027-06-30; Bedrock sets its
  own date, so check it in W-B. It is billed through AWS Marketplace.
- **Laptop access: IAM Roles Anywhere, not an access key.**
  - The key is created in the TPM and cannot be exported.
  - The CA is discarded after signing.
  - Roles Anywhere has no additional cost and is available in ap-south-2 (checked 2026-09-28).
  - The operator role only reads (`iam/operator/`).
- **One AWS account, hardened, for the lab** (owner decision). Separate accounts per environment are
  the production recommendation, and the IaC supports them.
- **Quarantine keys are filtered word by word, not by an allowlist** (audit A-C-10, 2026-09-30).
  The plan said "allowlist". Measured over every recorded run (4,722 distinct untrusted lines), the
  only application keys were the bench apps' own (`cart_id`, `orders`, `rejected` ...). A fixed list
  would fit only the bench, or would drop every real application's keys. Instead:
  - a key is dropped if any of its words (split on `_ . -` and camelCase) names an instruction:
    `action`, `next`, `step`, `recommended`, `fix`, `plan` ...;
  - every value, including an error code, is length-capped;
  - a value is dropped if it uses a steering word, spaced or run together, or names one of
    WARDEN's own actions.

  None of the 2,667 recorded value facts was dropped. Honest limit: a compound key with no
  separator (`actionplan`) counts as one word.

## 17. Built or adopted, per component (requirements R9 and R57, 2026-10-03)

The rule (R9): use a ready-made production tool wherever one does the job; build only where none does, and say
why. Researched live on 2026-10-03: `docs/research/2026-10-03/build-or-adopt.md` and
`docs/research/2026-10-03/aws-mcp-servers.md`. `tests/test_build_or_adopt_r9.py` requires every module in
`src/warden/` to be named here.

**Adopted** (WARDEN's code is the wiring around them):

- Orchestration: Temporal Cloud and the `temporalio` SDK - `workflows.py`, `runtime.py`, `activities.py` (the
  steps, run as Temporal activities).
- Payload encryption: Temporal's payload-codec interface with `cryptography`'s AES-256-GCM - `codec.py`.
- Passkey approvals: py_webauthn (duo-labs, BSD-3-Clause) verifies every WebAuthn ceremony - `passkeys.py`.
- Signatures: `cryptography`'s Ed25519 for approvals and audit checkpoints (`approvals.py`); AWS KMS for the
  non-exportable signer and S3 Object Lock for the anchors (`audit.py`, register S12).
- Injection tripwire: Meta Llama Prompt Guard 2, pinned by commit, safetensors only - `tripwire.py`.
- Model access: the vendors' own SDKs and the Claude CLI, behind one client - `providers.py`, `llm.py`.
- Typed contracts: Pydantic - `models.py`. Tracing: OpenTelemetry - `observability.py`. MCP: the `mcp` SDK -
  `mcp_server.py`. CommonMark parsing for the outbound gate: `markdown-it-py` - `gate.py`.
- AWS, Kubernetes and database reads: boto3, the Kubernetes client and the database drivers - `aws_backend.py`,
  `aws_stack.py`, `k8s_backend.py`, `database.py`, `tools.py`. What an alarm watches: CloudWatch's own documented
  namespaces and dimensions, one table - `resources.py` (G9-A1; checked against AWS's metric pages 2026-10-10). The state of
  each service's resource: one closed table of read calls and AWS's own structured fields - `aws_describe.py` (G9-A2c). Which more
  resources an investigation may read: only names WARDEN already holds - `investigation.py` (G9-B). From an approved
  diagnosis to its fix plan, from labels and live known-good values only - `resolver.py` (G9-D1). The generic fix
  classes' AWS entries in `platforms/aws.py` (G9-D2b): each a few calls of AWS's own API under the existing
  live-read, exact-session, rollback and positive-health contract - no remediation framework covers that contract.
- AWS knowledge for an error code the model may not know: the AWS Knowledge MCP server (AWS's documentation and
  Knowledge Center, free, no sign-in), called with a closed code and a service word only; its answer is reference,
  never evidence - `aws_docs.py` (G10-C6, owner decision 2026-10-10).
- Configuration and secrets: SSM Parameter Store and Secrets Manager - `settings.py`, `environments.py`.
- Chat delivery: Slack and Microsoft Teams incoming webhooks - `chatops.py`.
- Change records: GitHub's Issues REST API, one issue per applied change - `changes.py`.
- The cloud's front doors: AWS Lambda behind EventBridge (CloudWatch alarm state changes) and API Gateway (the
  Alertmanager webhook, the approval page) - `lambdas.py`, thin adapters over intake, webhooks and the approval page.
- Who used an actor role: AWS CloudTrail (a management-event trail, the only record WARDEN itself does not write)
  delivered by EventBridge, held to WARDEN's audit - `actor_use.py`. Paging goes through a CloudWatch alarm, as for
  WARDEN's other health signals.
- Which change broke it: GitHub's Deployments REST API and AWS CloudTrail's LookupEvents, merged with WARDEN's own
  applied fixes - `timeline.py`. Cursor's Rollouts and Sentry's release tracking answer the same question as paid or
  heavy services (2026-09-27 research); three reads cover WARDEN's stages.
- Per-incident AWS identity: AWS STS AssumeRole - SourceIdentity, session tags and an inline session policy -
  `identity.py`, and boto3 for the AWS writes in `platforms/aws.py`. IAM Roles Anywhere and Teleport's Machine ID
  issue the same STS sessions on AWS (decision D11), so WARDEN calls STS directly.
- Approver labels: signed with the approvers' own Ed25519 keys (`cryptography`), recorded in the audit - `labels.py`.

**Built, and why no ready-made tool fits:**

- The decision rules - `verifier.py`, `grounding.py`, `catalog.py`, `bounds.py`, `freeze.py`, `intake.py`,
  `read_scope.py`, `remediation.py`, `gate.py`'s rules: most policies need evidence that Python computes first
  (section 16 records why not OPA or Cedar).
- The decision component - `decide.py`: a logistic model over a dozen measured features is a dot product and a
  sigmoid; scikit-learn would add a dependency and a pickle for that. Trained by scripts/train_decider.py.
- Number checks in the model's prose - `numbers.py`: a unit library (pint) would convert units, but naming which
  metric a number in free prose refers to is the hard part, and no library does it.
- Telling English logs from others - `language.py`: language-detection libraries (lingua, langdetect) answer
  "which language"; WARDEN needs only "English or not" per line, which script share and function words decide
  without a model download.
- The evidence trust boundary - `evidence.py`, `quarantine.py`: the published defences (dual-LLM, CaMeL, FIDES)
  are patterns or research code, not libraries for log evidence; WARDEN implements the pattern.
- Redaction - `redaction.py`: nothing found is deterministic, reversible with indexed placeholders, covers
  credentials and PII, runs locally and is fast on 20,000 lines; the managed filters are probabilistic and send the
  text out, and LLM Guard was archived on 2026-07-09. Kept under review against the gitleaks, Betterleaks and
  Kingfisher rule sets.
- The audit chain - `audit.py`: Amazon QLDB reached end of support on 2025-07-31 and CloudTrail Lake closed to new
  customers on 2026-05-31; immudb is a BSL-licensed server and Tessera a Go library that needs Aurora on AWS. The
  chain is a SQLite table in CloudTrail's digest pattern, verifiable offline.
- The signature catalogue - `knowledge.py`: k8sgpt, Robusta and the kube-prometheus rules cover Kubernetes only and
  need a live cluster; HolmesGPT and the AWS DevOps Agent are agent loops, not libraries. They serve as checklists
  for the Kubernetes signatures.
- The alert webhook's front door - `webhooks.py`: Prometheus Alertmanager does not sign its webhooks (it can send
  an Authorization header, read 2026-10-03), so the check is a bearer secret in constant time, size caps, and
  Alertmanager's own API confirming each alert is active; no ready-made receiver does that third part.
- The pipeline and its outputs - `graph.py`, `reporting.py`, `runbook.py`, `playbook.py`, `cli.py`, and the
  approval page `approval_page.py` (its ceremonies are py_webauthn's): WARDEN's own product surface.

**Evidence through the AWS MCP servers or the Agent Toolkit (R57): not adopted.** Each lets a model choose its
calls (free-form API calls, Python, SQL or log queries), which WARDEN's design forbids; each returns raw text the
quarantine would still have to handle; the local awslabs servers are being replaced by the managed AWS MCP Server
(GA 2026-05-06, no India region), and the SQL servers carry read-only bypass advisories. The one read they would
add, CloudTrail, is planned as a fixed boto3 `lookup_events` reader with the change timeline (G6). Revisit the
managed server only if it offers fixed, typed operations in an India region.
