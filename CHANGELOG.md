# Changelog

All notable changes to WARDEN are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — pre-1.0, so a minor
bump may carry a breaking change.

## [0.10.0] - 2026-09-28

### ⚠ Correction (added 2026-09-28, after release)

This release was announced as "Phase 2 done". **That was false.** On the same day, a full audit found
the following. The tag is kept; fixes ship as 0.10.1 and later, in order of risk:

- **Failure-mode register:** 1 of the 22 rows assigned to Phase 2 was done with a test. The rest are
  open, including false recovery, feedback loops, a mislabelled environment, alarm storms, fighting
  other automation, no degraded mode, a mutex on a free-text name, freeze windows, and no versions
  in the audit.
- **Defects in the RemediationWorkflow shipped here:**
  - a failed rollback ends without an audit record;
  - activities retry forever;
  - the policies P1–P16 are never run;
  - there is no environment on the request;
  - `request_remediation` is not bound to an incident or its verdict;
  - the kill switch is not re-checked before apply;
  - the "at most 2 model calls" cap is not enforced (up to 6);
  - scale is not limited to 50%.
- **Earlier phases:**
  - the quarantine does not fully hold: untrusted text still reaches the model through tool-error
    items, forged log-stream names, the alert text and the environment field;
  - the outbound gate covers Slack only (JSON report, stdout and MCP results are ungated);
  - the in-process live remediation paths trust a typed environment and principal;
  - DB "terminate connections" ignores its target;
  - some tests pass even with their guard removed.
- **Infrastructure design:**
  - per-environment IAM isolation can be broken (`rds-db:connect` has no tag condition key);
  - the deploy role can attach a managed policy to a role it creates;
  - CI apply would fail on two missing permissions.

  Nothing is deployed; no live system was exposed.
- **"Drift means a new plan"** below was wrong: the code ends the workflow as `drifted`. Re-plan
  with a fresh approval is being built.

Every finding, with its fix and test, is in `docs/AUDIT-2026-09-28.md`, and the plan
(`docs/ROADMAP.md`) closes each one. A new CI test fails whenever something is marked done without
the test that proves it.

v2 re-architecture, Phase 1.5 and Phase 2 (partial, see the correction above). Every environment is configured by name, with no key
stored anywhere. A fix is a durable workflow that a person must approve with their own signature.
That workflow applies the fix once and checks the result itself, and every step is recorded
tamper-evidently.

### Added (Phase 2)

- **Temporal workflows** (self-hosted OSS; `workflows.py`, `activities.py`):
  - `IncidentWorkflow` runs the diagnosis nodes as three activities: `prepare`, `diagnose`
    (the one model call, on redacted input only) and `verify` (no model).
  - `RemediationWorkflow` steps: plan against live state → bounds → signed approvals until
    the TTL → live re-check (drift means a new plan) → apply once → its own success check →
    rollback.
  - Completion comes only from the workflow's checklist; there is no input for success.
- **Encrypted workflow history** (`codec.py`): every payload is encrypted with AES-256-GCM, and
  failures are encoded. Without it, the raw alert (a workflow input) was readable in the history.
- **Tamper-evident audit** (`audit.py`):
  - append-only SQLite with a hash chain;
  - Ed25519-signed checkpoints, which catch an edited row even when the chain was recomputed;
  - `warden audit keygen` / `warden audit verify`.
- **Signed approvals** (`approvals.py`):
  - each one binds one plan hash of one workflow, at one tier;
  - it expires and can be used once;
  - T3 plans need a cooling-off period;
  - a two-person rule counts different approvers only.
- **Bounds, kill switch and circuit breaker** (`bounds.py`), with their state in the audit log.
  A reset needs a signed approval of that specific trip.
- **Remediation catalogue** (`catalog.py`): 14 entries.
  - Every target must be a value WARDEN read from live state.
  - Numbers are clamped against live values.
  - Queue purges, IAM writes, Secret applies, deletes, raw SQL and shell are excluded.
- **CLI**: `warden worker`, `incident`, `status`, `approve` (signs only the plan hash you
  reviewed) and `killswitch`.
- **MCP**: `start_incident_diagnosis`, `request_remediation` and `workflow_status`.
  - No tool can approve, sign, reset or execute.
  - No parameter looks like a credential.
  - The tool manifest is pinned by a sha256.

### Added (Phase 1.5)

- **Per-environment everything:**
  - `environments.names(env)` derives every name;
  - IAM templates are rendered per environment, with a boundary meant to deny every other
    environment (it does not yet: see the Correction above, `rds-db:connect` and untagged
    resources);
  - Terraform workspaces are environments;
  - deploy workflows take an `environment` input;
  - settings come from SSM Parameter Store (`settings.py`, with an allowlist).
- **Network**: only the NAT is public. The ALB is internal, and compute runs in private subnets.
- **Tags**: `Project` and `Environment` on everything the stack creates, including EKS nodes and
  disks, the cluster security group, ECS tasks and task definitions.
- **`scripts/account_sweep.py`**:
  - lists everything that can bill, in every region, without trusting tags;
  - audits `Project`/`Environment` tags;
  - reports what it could not see as BLIND.

  It runs as the read-only role `warden-pg-sweep`.
- **Injection tripwire** (P16): Meta Llama Prompt Guard 2 (86M), optional and run locally.
  - 0 false alarms in 4,637 real lines.
  - It catches 6 of the 14 corpus payloads; quarantine and the gate cover the rest.
- `check_publishable` also refuses Slack trigger, Teams and Power Automate webhook URLs, and Hugging
  Face tokens.

### Removed

- LangGraph. `graph.run()` is a plain pipeline over the same nodes. A parity test shows identical
  results to the IncidentWorkflow on every bundled incident.

## [0.9.0] - 2026-09-27

v2 re-architecture, Phases 0 and 1: nothing AI-written runs unapproved, and what the model says is
checked against what it was shown.

⚠ Work between 0.8.0 and this release (P11/P12 on 2026-09-25, the EKS/RDS/full-stack waves, the stack
backend) has no entries of its own here. It is recorded in `docs/`, `docs/bench/` and git history.
0.7.0 and 0.8.0 were never tagged.

### Security (Phase 0)

- The `claude_cli` model process gets an allow-listed environment. AWS keys, DB DSNs and kubeconfig
  no longer reach it.
- Fix commands are printed only for an `approved_for_human` verdict. Escalated commands are listed
  as NOT APPROVED, and rejected ones not at all. Nothing builds an IAM grant or an index from log
  text any more.
- The benchmark harness refuses to execute a non-approved fix, and no longer allows
  `sqs purge-queue`, `iam put-role-policy` or Secret apply.
- Outbound gate v0 (`gate.py`):
  - G3 strips markdown images, links, URLs and HTML outside code blocks.
  - G5 withholds a message that still carries a secret.
  - Slack unfurling is off.
  - A log line can no longer close the evidence code fence.
- MCP `verify_remediation` caps its verdict at `escalated`: the caller claims the evidence counts,
  WARDEN never reads them.

### Added (Phase 1)

- **Evidence ids** (`evidence.py`): L log, E event, M metric, D deploy, C config/state read, T
  failed read, F typed fact.
- **`P13-UNGROUNDED`**: every citation must name a real id and quote it verbatim.
- **`P14-TARGET-NOT-IN-EVIDENCE`**: the target must name a known resource. Seen live on 2026-09-26:
  `lambda:shop-prod-checkout`.
- **Quarantine** (`quarantine.py`): log lines, events, SQL and source reach the model only as typed
  facts of fixed shapes, never as text.
- **G2**: "no customer impact" and "resolved" in model text are marked `[unverified: ...]`. Reports
  show the cited evidence, and say "Not grounded" when P13 fired.
- `scripts/replay_diagnose.py`: re-diagnose a published run's recorded evidence with today's
  pipeline, and score it with the frozen rubric.

### Changed

- **One model call per incident.** `analyse` and `propose` became a single `diagnose` node.
- Measured by replaying 30 recorded incidents on Claude Max, raw lines vs typed facts:
  - 17/30 correct in both arms
  - wrong-and-allowed went 1 → 0
  - input tokens −62% on the ECS wave, −28% on EKS
  - no P13/P14 fire in 60 diagnoses

  A replay, not a live measurement (`docs/ai-boundary.md`).

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

- ⛔ **The ECS evidence could not see tasks dying in a loop.** `metrics()` derived
  `deployments_failed` from `rolloutState == "FAILED"`, which ECS sets only when the deployment
  circuit breaker is enabled — the proving ground does not enable it, so that metric was
  structurally always 0. Meanwhile a revision whose tasks crash on startup is retried indefinitely:
  the old tasks keep serving, so `runningCount == desiredCount`, nothing is pending, and nothing is
  marked failed. On the published wave that evidence made a broken service look healthy and two
  fault classes were answered "no action needed" 3/3 each. `deployment_failed_tasks` now sums
  `failedTasks` across the deployments in the **same `DescribeServices` response** the backend
  already reads — no extra API call, no extra IAM action, so the policy⇄code parity test is
  untouched. ⚠ The published Wave 1 numbers were measured **before** this, and re-measuring means
  rebuilding the proving ground and running the wave again; it has not been done.

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
- **The model is not deterministic.** 8 (7 - recounted from results.json 2026-09-25) of 14 scenarios disagreed across three identical repeats,
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
