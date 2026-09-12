# Changelog

All notable changes to WARDEN are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — pre-1.0, so a minor
bump may carry a breaking change.

## [0.8.0] - 2026-09-12

The gate stops taking the model's word for anything that could loosen it.

### Fixed

- ⛔ **Two of the nine policies read fields the MODEL wrote, in a gate whose entire claim is that
  the model does not decide.** `P2-IRREVERSIBLE-IN-PROD` fired on `proposal.reversible` and
  `P6-BLAST-RADIUS` on `proposal.blast_radius`. A proposal claiming `reversible: true` therefore
  **widened its own permissions**, and the same operation got opposite verdicts from two models: a
  prod-database `terminate_connections` was rejected under Gemini (`reversible: false`, 0.85
  confidence) and merely escalated under Claude (`reversible: true`, 0.45). Recorded as a known
  inconsistency in `docs/live-model-run-2026-09-06.md` §3 since September — *"Neither change is made
  yet"* — and measured, but not fixed, for two releases.
  - `models.py::ACTION_FACTS` is now the gate's own classification of its nine actions:
    `(reversible, blast-radius floor)`. `failover_replica` and `scale_down` are irreversible; a
    rollback is a forward deploy of a previous revision and is not. Deliberately not
    operator-configurable — a config file is only a different author for the same field.
  - **P2 reads the table and nothing else.** P6 takes the wider of the table's per-action floor and
    the claim, so a model may tighten the gate by widening its own blast radius but understating it
    buys nothing.
  - **New `P10-CLAIM-CONTRADICTS-TABLE`**: the proposal warns an action is irreversible while the
    table says otherwise → escalate. Without it, moving to a table-only P2 would have *loosened*
    the gate for a model that warns us. `rejected` and `escalated` both mean nothing runs.
  - **The MCP server was the worst case**: `verify_remediation` builds a proposal from *untrusted
    caller* arguments, so any client skipped P2 by sending `"reversible": true`. It now gets the same
    table, and the response echoes `reversible_by_table` / `blast_radius_enforced` so a caller can
    see it was overruled.
  - **P2 could never fire in mock mode**, which is what CI and the evals use: the mock hardcodes
    `reversible=True` for every action, `failover_replica` included. The mock is deliberately left
    as it is — it makes exactly the wrong claim a real model makes, and the table overruling it is
    the demonstration. `inc-003` in the demo and the eval suite is now REJECTED rather than
    escalated, which is strictly stronger.
- ⛔ **`no_action` skipped every evidence policy, so "nothing is wrong" could not be challenged.**
  On a real AWS account, 14 of 42 runs answered `no_action` about a service with a live fault and the
  gate allowed every one — two at 0.25 confidence while their own `tool_errors` recorded that WARDEN
  could not read the logs. The exemption is now split: `AUTO_SAFE_ACTIONS` still decides who skips
  *approval*, and a new `EVIDENCE_EXEMPT_ACTIONS` — `escalate_to_human` alone — decides who skips
  the *evidence floor*. Handing an incident to a person is the right answer to weak evidence;
  claiming there is no incident is not. P3 keeps the wider set on purpose: "rejected, you may not
  conclude nothing is wrong" is not a verdict an operator can act on, and P9 catches the same
  condition with a verb that makes sense.
  **Replaying the published reports through the new gate: 12 of those 14 are refused, 2 are not, and
  3 runs where `no_action` was correct now escalate.** All three numbers are in the README.

### Added

- `scripts/replay_gate.py` — re-decides published report JSONs with today's policy, by calling the
  real `verify()` rather than a reimplementation. It prints, unavoidably, that **a replay is not a
  measurement**, and refuses to write its JSON inside a run directory where it could be mistaken for
  a score.
- A mutation that flips `failover_replica` to reversible in the table: P2 now reads one tuple, so a
  one-line diff could quietly make the only irreversible action it can reach in prod executable
  again, with every policy still present and every other test green.

### Changed

- `reversible` and `blast_radius` stay **required** in the model-facing schema but are documented as
  advisory, and reports now carry the claim *and* what was enforced side by side. The
  `reversible` flip-rate in `scenarios/score.py` therefore changes meaning: from 0.8.0 it measures
  the model's self-consistency instead of a flaw in the gate. It is kept, because a model that
  cannot describe the same action twice the same way is worth knowing about.
- **The Wave 1 numbers in `docs/bench/` are left exactly as measured under 0.7.0.** Re-scoring them
  against a gate that did not exist when they ran would be inventing a result. The dated records
  that prompted these fixes — `live-model-run-2026-09-06.md` §3, `scenarios/scoring.yaml`'s rubric
  correction, `docs/bench/README.md` — are annotated, never rewritten.

## [0.7.0] - 2026-09-12

The release where WARDEN was measured against a real AWS account instead of described. The
benchmark found bugs in the tool, and two in itself, and everything below is published rather than
summarised: both runs, their rubrics, their hashes and the scorer are in [`docs/bench/`](docs/bench/README.md).

### The measurement

14 fault classes injected into a real ECS Fargate service in `ap-south-2`, 3 runs each, Claude
Sonnet through the `claude` CLI, every run as a 4-action read-only role. Evidence, diagnosis and the
gate scored separately; the rubric committed before the run with its hash in the manifest.

> **20 CORRECT · 5 SAFE-BUT-UNHELPFUL · 14 WRONG · 3 NO-EVIDENCE** — and the number that matters:
> **14 runs proposed `no_action` on a service with a live fault, and the gate allowed every one.**

- **The gate cannot catch "nothing is wrong."** `no_action` and `escalate_to_human` skip every
  policy check by design, so a wrong `no_action` is never refused and never needs approval. Two runs
  closed the incident at 0.25 confidence while their own `tool_errors` recorded that the logs could
  not be read. Published as a design limit, not patched into a better number after the fact.
- **The AWS evidence omits the clearest failure signal there is.** `aws_backend.metrics` derives
  `deployments_failed` from `rolloutState == "FAILED"`, which only ever fires with the ECS
  deployment circuit breaker enabled, and ignores the `failedTasks` count `DescribeServices` already
  returns per deployment. So a service whose new tasks were dying in a loop was reported as
  tasks-at-desired-count, nothing pending, nothing failed. **Open work**, named in the README.
- **A completed rollout hides its own deploy.** Deploy detection compares images against the
  replaced deployment; once a rollout finishes there is nothing to compare, so `ecs-08` scored
  NO-EVIDENCE 3/3 rather than being graded as a model failure.
- **The model is not deterministic.** 8 of 14 scenarios disagreed across three identical repeats,
  including the healthy control, where one run escalated a service with nothing wrong.

### Added

- **`scenarios/` — the fault-injection benchmark.** Real faults (`ops.py`), a wave runner that
  injects, measures, reverts and refuses to continue on a failed revert (`runner.py`), and an
  offline scorer that never imports WARDEN and never reads the hypothesis text (`score.py`). The
  rubric is data (`scoring.yaml`), argued in prose (`SCORING.md`), and a perfect score is stated to
  be a bug report.
- **`terraform/proving-ground/` — a throwaway account to break.** ECS Fargate (Spot optional), a
  4-action reader role, a budget guard, and an operator IAM user with no console access. RDS and EKS
  are opt-in and unused so far.
- **A live AWS backend** (`aws_backend.py`): CloudWatch logs and metrics, ECS service state and
  deploy detection, with every window and cap configurable and bounded.
- **A `claude_cli` provider**, so a run can go through a Claude subscription instead of an API key —
  with the operator's own config deliberately stripped from its environment.
- **`scripts/`**: `publish_bench_run.py` (redact, verify with the repo's own scanner, then copy),
  `teardown_sweep.py` (what Terraform never knew about), `check_iam_actions.py` and
  `validate_policies.py` (AWS's own validator), `prove_boundary.py` and `apply_operator_policy.py`.
- **A permissions boundary, proven live.** `prove_boundary.py` grants the operator, in its own
  policy, the right to edit the boundary and to replace its own boundary — and both stay denied,
  5/5, with a positive control so no denial can be mistaken for propagation delay.

### Changed

- ⛔ **The rubric was corrected after a run, in the open.** It graded `no_action` on a broken
  service SAFE-BUT-UNHELPFUL because "a human gets it". That is false: the verifier exempts
  `no_action` from every policy and the graph records it as `auto_safe`, "approval: not required" —
  nobody is paged. `no_action` is now WRONG unless it is the right answer. Which passives count as
  safe is rubric data, so a rubric predating the key still reproduces its own numbers, and the
  affected run is published under **both** gradings.
- **A wave now waits 18 minutes before every inject** and pins WARDEN's evidence window in its
  environment, because scenarios were reading each other (below). A wave takes ~7 hours.

### Fixed

- **Scenarios read each other's evidence.** WARDEN reads logs 15 minutes around the alert; the
  runner left 0.1–5 minutes between one scenario's revert and the next inject, so **39 of 42 runs**
  in the first full run were graded partly on the previous scenario's fault and recovery. The runner
  now isolates the evidence as well as the state, and the scorer flags any overlapping run. The
  clean re-run has 0 of 42 — and shows the leak changed `ecs-09`'s answer and did *not* change
  `ecs-06`'s, which guessing would have got wrong in both directions.
- **Deploy detection compared revision N with N−1** instead of with the deployment actually being
  replaced, so a rollback was proposed for a service whose rollout had simply not finished.
- **The `claude` CLI was spoken to in the Windows code page**, so any prompt containing an em dash
  or an arrow arrived garbled; every run before the fix was superseded and re-run.
- **A diagnosis could be lost to `print`.** The CLI wrote its report *after* printing it, so a
  console that could not encode a character threw away the result it had already paid for.
- **An exhausted model provider was retried three times and then mistaken for a tool failure.**
  `ProviderExhausted` is now fatal, recognised from the CLI's real wording ("session limit"), and
  the wave stops cleanly and resumes with `--resume` instead of injecting faults it cannot measure.
- **A redacted placeholder blinded the secret scanner to the real secret beside it.**
- **Hashes differed between a CRLF and an LF checkout**, so a rubric that had not changed looked
  tampered with. Content is hashed LF-normalised.
- **`teardown_sweep` died on AWS throttling** after deregistering 38 of 45 revisions, leaving 7
  behind and a traceback where the verdict should have been. Destructive calls now wait a throttle
  out; anything that is not a throttle is still re-raised, so a permission error can never be
  retried into looking like success.
- **Six IAM and Terraform defects** a real apply found: a non-existent action name accepted by no
  console, a global action under a region condition, a duplicate `Sid`, a missing tag permission,
  `timestamp()` in `default_tags` breaking every saved-plan apply, and an example file that switched
  EKS on.

### Testing

- **676 tests and 25 evals.** Every fix above was planted back out and its test watched go red
  before being kept — including the ones that would otherwise pass against a fake.

## [0.6.2] - 2026-09-06

### Fixed

- ⛔ **0.6.1's own fix was wrong, and a real cluster caught it.** Conditioning the scale patch on
  `metadata.resourceVersion` looked correct and passed every unit test against a fake client. It
  fails on a live Deployment: the Deployment controller writes `status` continuously, so
  resourceVersion moves for reasons that have nothing to do with anyone touching `spec`. CI's
  live-cluster job rejected the very first attempt with *"Operation cannot be fulfilled … the object
  has been modified"*.
  The condition is now on the field that actually matters — a JSON Patch `test` op on
  `/spec/replicas` — and a conflict re-reads and recomputes the target, bounded by
  `WARDEN_REMEDIATION_SCALE_RETRIES` (3), raising if it never wins. That is both the idiomatic
  Kubernetes pattern and the semantically right one for a *relative* step: if something else scaled
  to 5 while we were deciding, stepping from 5 is correct and stepping from the stale value is not.
  Nothing is clobbered, because the target is always derived from a fresh read.
  ⭐ The lesson is the project's own: a guard that passes against a fake proves the request was
  made, not that the outcome is right. Only the live job could tell the difference.

### Testing

- **393 tests.** Three tests now cover the scale path: the write is conditional on the count that was
  read, a conflict re-reads and recomputes from the new value, and sustained contention raises
  loudly rather than looping or silently doing nothing.

## [0.6.1] - 2026-09-06

⚠ **Tagged but never released — its scale fix regressed the live-cluster job. Use 0.6.2.**


### Fixed

- **`scale_up` / `scale_down` could silently overwrite a concurrent change.** `_scale` reads the
  Deployment to compute a target from the current replica count, then patches it — a read-then-write
  with no precondition, so anything that changed the Deployment in between (a HorizontalPodAutoscaler,
  another operator, a person with `kubectl`) was clobbered. The patch now carries the observed
  `metadata.resourceVersion`, so the API server rejects the write with 409 Conflict instead and the
  backend surfaces a clear refusal rather than a generic failure. Two tests pin it: one asserts the
  precondition is actually sent, one asserts a conflict is refused and nothing is patched.
  ⚠ The relative `current + SCALE_STEP` step is deliberate and unchanged — "scale up one step" is the
  action an incident responder means — so a duplicate alert still compounds, bounded by
  `WARDEN_REMEDIATION_MAX_REPLICAS`. That is documented, not fixed here.
- Found while writing an answer to "what happens if the same alert arrives twice?", which is a fair
  argument for writing the awkward answers down.

### Testing

- **392 tests** (345 unit + 22 opt-in live, 25 evals, 10 live-cluster, 12 live-database).

## [0.6.0] - 2026-09-06

⛔ **The `0.5.1` tag was 37 commits behind this content.** Everything below already existed on
`main` under the version string `0.5.1`, so anyone cloning the published release got a differently
named package (`src/aegis/`) with 52 files and 14 mutations. This release exists so that the
version number and the code agree. **If you read a description of WARDEN that cites 390-392 tests,
31 mutations or five database engines, this is the release it describes.**

### Changed — BREAKING

- **The project is renamed AEGIS → WARDEN.** The import package moved `src/aegis/` → `src/warden/`,
  the console scripts are `warden` and `warden-mcp`, and every environment variable is
  `WARDEN_*`. There is no compatibility shim: this is a pre-1.0 rename.

### Added

- **A live Kubernetes remediation backend** — a real Deployment restart or scale, clamped (never
  below 1 replica, never above `WARDEN_REMEDIATION_MAX_REPLICAS`), on its own write-scoped RBAC
  separate from the read path. Opt-in behind `WARDEN_REMEDIATION=live`; the default backend still
  changes nothing.
- **Read-only health backends for five database engines** — PostgreSQL, MySQL, Redis, MongoDB and
  SQL Server — plus a gated `terminate_connections` write path that kills only connections stuck
  idle-in-transaction beyond a threshold, count-clamped, never its own connection, on a separate
  least-privilege credential. All five run against real engines in CI as service containers.
- **An environment policy engine** (`environments.yaml`): per-environment allow/deny action lists,
  principal authorisation, and an `auto_remediate` flag. **Fails closed** — an unknown environment
  gets the most restrictive row, not the most permissive.
- **The four-way remediation gate** — an action is applied only when an auto-remediate environment,
  an authorised principal, an explicit approval and an armed backend all hold. `prod` never
  auto-applies.
- **A researched incident-signature knowledge base** (34 signatures) with a deterministic matcher.
  ⚠ Wired to report annotation only; it does not yet influence the hypothesis or the verdict.
- **ChatOps egress** with a redacted report, proven over a real socket.
- **A per-environment `credentials_ref`** so an environment can name its own account pointer.

### Fixed

- **A long redaction-hardening series.** Added masking for private keys, database credentials, AWS
  secret and STS (`ASIA`) keys, bearer tokens, HTTP Basic auth, kubeconfig client keys and
  certificates, session cookies, npm `_authToken`, `github_pat_`, MAC addresses, IBANs, grouped
  credit-card numbers, GCP and Azure secrets, URL-encoded email, and query-parameter, JSON-body and
  webhook credentials. Redaction is recursive over JSON on egress.
- **Three leaks closed on paths the first fix missed** — the MCP server's `recent_deploys`,
  `RunReport.context`, and tool error text before it reaches the audit trail and telemetry spans.
  The same leak on a second code path is the reason the guard re-scans its own *output* rather than
  trusting the substitution.
- **`resolve()` no longer mutates the global environment**, which had been silently leaking an
  endpoint across providers.
- **Permanent provider errors now fail fast** with an honest attempt count.
- **A NaN/inf metric no longer crashes the run.**
- **The read-only database tripwire was green and blind.** Its AST check collected only string
  literals passed *directly* to `.execute()`; every adapter hands its SQL to a helper, so the
  collector returned an empty list and the test asserted `not []`. Found by the mutation check, not
  by review. The checker now follows the indirection, two tests pin it, and a full re-run reports
  **31 caught, 0 survived**.
- **`remediation.py`'s module docstring** claimed the only backend shipped was `DryRunBackend` and
  that "this codebase never mutates a cluster". Both stopped being true when the live backends
  landed.
- Corrected a stale test count (388, measured) and a documentation reference that cited the
  redaction leak-guard test by a name it no longer had.

### Testing

- **390 tests**: 343 unit (+22 opt-in live tests that skip without infrastructure), 25 evals,
  10 against a live k3d cluster, 12 against five live database engines. Across CI nothing is
  skipped — the `k8s` and `db` jobs fail if their tests skip.
- **A 31-case mutation check** (`scripts/mutation_check.py`) that breaks the code deliberately and
  requires the suite to go red for each. Latest run: 31 caught, 0 survived.
- **CI asserts on output, not exit codes** — the container and cluster jobs check the verdicts the
  tool actually prints, because a green exit code once hid a run where every tool had failed.
- **RBAC is asserted both ways from the API server**: the five reads the code makes are allowed;
  writes, secrets, unused read verbs, other namespaces and cluster scope are denied.

## [0.5.1] - 2026-08-22

The last release made under the name **AEGIS**, package `src/aegis/`. Kept for history; prefer
`0.6.0`.
