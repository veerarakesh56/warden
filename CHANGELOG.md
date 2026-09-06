# Changelog

All notable changes to WARDEN are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — pre-1.0, so a minor
bump may carry a breaking change.

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
