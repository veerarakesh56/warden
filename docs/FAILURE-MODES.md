# Failure-mode register: everything that can go wrong with a fully automated WARDEN

This register was built from:
- a read-only research review on 2026-09-27, covering:
  - OWASP LLM and Agentic Top 10, MITRE ATLAS, NIST AI 600-1, the AWS Agentic AI Lens and Google SRE;
  - published postmortems of automation gone wrong: Knight Capital, Google Diskerase,
    Cloudflare Nov 2025, the Azure Front Door outage of Oct 2025, AWS Oct 2025, and the Anthropic
    Sept 2025 postmortem;
- live research dated 2026-09-28 (`docs/research/2026-09-28/`), covering:
  - OWASP Agentic Top 10 2026 and LLM Top 10 2026;
  - the MITRE ATLAS agent techniques and MAST;
  - published agent incidents;
  - a systematic map from each failure mode to the tools that address it.

**How to read a row.** Every row carries:
- a **Group**: the work group in [`ROADMAP.md`](ROADMAP.md) that closes it;
- a **Status**: `OPEN`, `DONE-local`, `DONE-live` or `DEFERRED`;
- **Evidence**: for a done row, the test (`file::function`) or the live window that proves it.

`tests/test_register.py` fails CI when a row marked done cites no existing test, or when an open row
belongs to a group at or before the current one.

**Honesty note.** On 2026-09-28, v0.10.0 was announced as closing this register's Phase 2 rows. Only
S2 had been closed. The corrected statuses are below.

## Controls already built and tested

| # | Control | Group | Status | Evidence |
|---|---|---|---|---|
| B1 | Grounding: an invented citation id escalates (P13) | G0 | DONE-local | tests/test_grounding.py::test_an_invented_id_escalates |
| B2 | Grounding: a misquote escalates (P13) | G0 | DONE-local | tests/test_grounding.py::test_a_misquote_escalates |
| B3 | A target not in the inventory is rejected (P14) | G0 | DONE-local | tests/test_grounding.py::test_the_fs03_hallucinated_function_is_rejected |
| B4 | Quarantine: the planted injected log line never reaches the model (other spellings: audit A-C-10, open) | G0 | DONE-local | tests/test_quarantine.py::test_an_injected_log_line_never_reaches_the_model_and_does_not_change_the_action |
| B5 | The model CLI gets no credential but its own Claude login token (`CLAUDE_CODE_OAUTH_TOKEN`, since 6504f71): no cloud, database or other model key (environment allowlist) | G0 | DONE-local | tests/test_claude_cli_provider.py::test_no_credential_in_the_parent_environment_reaches_the_model_process |
| B6 | Outbound gate: the planted image or link never reaches Slack (other structure: audit A-C-9, open) | G0 | DONE-local | tests/test_gate.py::test_a_planted_image_or_link_echoed_by_the_model_never_reaches_the_slack_payload |
| B7 | Signed approvals: a forged signature is refused | G0 | DONE-local | tests/test_approvals.py::test_a_forged_signature_is_refused |
| B8 | Tamper-evident audit: a row rewritten with a recomputed chain is caught | G0 | DONE-local | tests/test_audit_log.py::test_rewriting_a_row_and_recomputing_every_later_hash_is_caught_by_the_signature |
| B9 | Kill switch: only a signed approval of that specific trip resets it | G0 | DONE-local | tests/test_bounds.py::test_only_a_signed_approval_of_this_trip_resets_it_and_only_once |
| B10 | MCP cannot approve, sign, reset or execute | G0 | DONE-local | tests/test_mcp_workflows.py::test_no_tool_can_approve_sign_reset_or_execute_and_none_takes_a_credential |
| B11 | The model CLI runs sandboxed: an empty tool list, no MCP servers, no operator settings (`--tools ""`, `--strict-mcp-config`, `--setting-sources ""`) | G0 | DONE-local | tests/test_claude_cli_provider.py::test_no_tool_no_mcp_server_and_no_operator_setting_is_loaded |
| B12 | Breaker: two failed success checks within an hour trip the kill switch | G0 | DONE-local | tests/test_bounds.py::test_two_failed_success_checks_in_an_hour_trip_the_kill_switch |
| B13 | MCP caller claims are never trusted: claimed evidence escalates, never approves | G0 | DONE-local | tests/test_mcp_server.py::test_a_clean_case_on_claimed_evidence_is_escalated_never_approved |
| B14 | CI actions are pinned to full commit SHAs, never tags | G0 | DONE-local | tests/test_ci_lanes.py::test_every_action_is_pinned_to_a_full_commit_sha |

**Known weaknesses of these controls.** The 2026-09-28 audit found gaps in several of them (the
quarantine, the gate's coverage, the tripwire) and some vacuous tests. These are listed in
[`AUDIT-2026-09-28.md`](AUDIT-2026-09-28.md) and fixed in G1. A control above is only as strong as
its audit rows.

## Gaps: critical

| # | What goes wrong | Fix | Group | Status | Evidence |
|---|---|---|---|---|---|
| C13 | **WARDEN fails together with the incident** (region outage), and nobody notices it is down | Heartbeat, plus an external staleness page and a daily synthetic shadow incident; `docs/RUNBOOK-WARDEN-DOWN.md` | G6 | OPEN | |
| C18a | **False recovery.** A dead service stops emitting errors and the workflow's check says "recovered" | Success needs positive signals (request floor plus probe); missing data counts as failure; K=3 consecutive checks; durable re-checks at T+15 and T+60 | G3 | OPEN | |
| C18b | **False recovery at the alarm.** Health alarms use `notBreaching`, so a dead service's alarm goes OK | Health alarms use `treat_missing_data = breaching` | G6 | OPEN | |
| C1 | **Feedback loop.** WARDEN's own restart trips the alarm, which starts a new incident, which restarts again | An alarm on a target inside an open verify window becomes a signal to that workflow, not a new incident | G3 | OPEN | |
| S6 | **Environment mislabelled.** An alert claims dev for a prod resource | The resource's own `Environment` tag and name prefix must match the incident's environment (P18); missing counts as a mismatch | G2 | OPEN | |
| H6 | **Approver impersonation** | WebAuthn passkey signature over the plan hash; Slack `team_id`+`user_id` allowlist; the CLI Ed25519 key only as break-glass | G5 | OPEN | |

## Gaps: high

| # | What goes wrong | Fix | Group | Status | Evidence |
|---|---|---|---|---|---|
| M15 | **Model drift.** The provider changes the model or the CLI | Pin dated model ids; record model id and CLI/API version in the audit | G3 | OPEN | |
| E6 | Model, prompt or CLI changes are not gated | The replay suite (Inspect AI, pass^k, McNemar) gates every change | G7 | OPEN | |
| M10 | The alert name and summary reach the model as text | Rule id plus sanitised labels; the summary becomes quarantined evidence kind A. Accuracy measured on the replay set before keeping it | G3 | OPEN | |
| M11 | Free-text config (Lambda descriptions, env values, tags) reaches the model | Allowlist env keys; quarantine free text | G3 | OPEN | |
| C2 | Alarm storms | Group at intake by fingerprint; signal the open incident; cap open incidents | G3 | OPEN | |
| C20 | Acting on OK or INSUFFICIENT_DATA; a reused workflow id rejects the next real incident | Accept only `state=ALARM`; id = fingerprint plus transition time | G3 | OPEN | |
| C21 | Flapping | N flips in M minutes means an escalate-only incident | G3 | OPEN | |
| C4 | Fighting other automation (autoscaling, Argo/Flux self-heal, the next Terraform apply) | Catalogue `conflicts_with` against the controllers read from live state; GitOps-owned objects escalate | G3 | OPEN | |
| C5 | Acting mid-deploy | A rollout in progress refuses (P21) | G3 | OPEN | |
| C8 | Oscillation (rollback of a rollback) | Never auto-reverse WARDEN's own fix; known-good = healthy ≥ 30 min; cool-down per target | G3 | OPEN | |
| C22 | Generated config (`decider.json`, signatures) ships unchecked | Schema, size and replay validation before load; keep last-known-good | G7 | OPEN | |
| S5 | Forged alerts through the webhook | API Gateway plus HMAC from Secrets Manager; the reader confirms the alarm exists and is in ALARM | G6 | OPEN | |
| S9 | Supply chain: unpinned dependencies, base image by tag | Hash-locked requirements, digest pins, CycloneDX SBOM + ML-BOM, cosign signing, provenance | G3 | OPEN | |
| S15 | The Temporal server is reachable without authentication | Temporal Cloud with one API-key service account per trust zone; the codec fails closed; the workflow re-verifies signatures | G5 | OPEN | |
| S2 | Secrets in Temporal history | Payload codec including failure attributes; the redaction map is never a payload | G2 | DONE-local | tests/test_incident_workflow.py::test_with_encryption_nothing_redacted_is_readable_in_history, tests/test_codec.py::test_failure_messages_and_stack_traces_are_encrypted_too |
| S12 | The audit can be rewritten by whoever holds the key and the database | KMS Ed25519 signer role; checkpoints anchored to S3 Object Lock under another principal; CloudTrail `kms:Sign` as a witness | G3 | OPEN | |
| H1 | Approval fatigue | Approval-latency metric (flag under 10 s); cap on requests per hour; T2+ requires typing the target; status shows policies before prose; catch trials in G7 | G3 | OPEN | |
| H10 | Nobody approves before the TTL | Escalation ladder; "no action taken" recorded and notified | G3 | OPEN | |
| E2 | Calibration trained on its own outcomes | Labels only from independent ground truth | G7 | OPEN | |
| E5 | Shadow thresholds too weak | Gate on the Wilson lower bound (30/30 only certifies ≈ 0.887) plus conformal abstention | G7 | OPEN | |
| M19 | No degraded mode when the model provider is down | A rules-only escalation plus a page; tested | G3 | OPEN | |
| M20 | Unqualified cross-provider fallback | A provider is enabled only after passing the replay set (`data/providers.yaml`) | G3 | OPEN | |
| O5 | Code or catalogue changes under an in-flight approval | `plan_hash` covers the evidence-pack sha, catalogue fingerprint and code version; refuse on mismatch | G2 | OPEN | |

## Gaps: medium and low

| # | What goes wrong | Fix | Group | Status | Evidence |
|---|---|---|---|---|---|
| M2 | Numbers, units and times misread | Numeric grounding after unit normalisation; all times in UTC | G7 | OPEN | |
| M18 | No daily token cap across incidents | A daily token and USD cap counted from the audit | G3 | OPEN | |
| C3 | Remediation mutex keyed on a name, not the resource | Workflow id `rem-<env>-<sha(target_key)>`, keyed on the canonical ARN | G2 | OPEN | |
| C6 | No change freeze or maintenance window | `data/freeze.yaml` (IANA zones) plus P19 | G3 | OPEN | |
| C10 | Restarting everything at once | Use the platform's native progressive settings; refuse aggressive ones | G3 | OPEN | |
| C17 | No canary | One instance first for T2 where the platform allows it | G3 | OPEN | |
| H3 | WARDEN's own Slack noise | Slack bot: one thread per incident, updated in place | G5 | OPEN | |
| H4 | People lose the skill | A quarterly game day without WARDEN | G8 | OPEN | |
| H5 | Unclear accountability | A one-page RACI | G8 | OPEN | |
| S4 | Secret rotation | Rotation table per secret (OPERATIONS) | G6 | OPEN | |
| S11 | Data residency (Bedrock global inference) | Only redacted typed facts are sent; residency recorded per deployment | G6 | OPEN | |
| S17 | Fake "WARDEN" messages | Approvals only through signed passkeys; Slack footer carries the incident id and audit head, verifiable with `warden audit show` | G3 | OPEN | |
| E7 | Audit rows don't pin the versions that decided | A versions row per workflow (git sha, prompt, catalogue and decider hashes, model id, CLI version) | G3 | OPEN | |
| O3 | Temporal history size and retention | Namespace retention set; history-size test | G3 | OPEN | |
| O4 | Backup and DR of WARDEN's state | Aurora backups + PITR; restore drill in W2 | G3 | OPEN | |
| O6 | Clock skew | `workflow.now()`; skew check at worker start | G3 | OPEN | |
| M23 | Non-English logs miss the English vocabulary | Code-shaped facts only; measure. To be DEFERRED only with the owner's agreement | G8 | OPEN | |
| O8 | Reading an already-degraded database adds load | `statement_timeout`, `lock_timeout`, `application_name` on the reader | G1 | DONE-local | every connection WARDEN opens - the reader and the remediation platform share the adapters - bounds its statements and lock waits: PostgreSQL `statement_timeout`, `lock_timeout` and `application_name` set per session, SQL Server's query timeout and `LOCK_TIMEOUT`, MySQL read and write timeouts, MongoDB's socket timeout (`WARDEN_DB_STATEMENT_TIMEOUT`, default 10 s; locks 2 s) (tests/test_database_timeouts.py::test_postgres_bounds_every_statement_and_lock_wait, ::test_sql_server_bounds_every_statement_and_lock_wait; planted: all 6 cases fail without the change) |
| O9 | Applied fixes leave no change record | A GitHub issue per applied change, with the plan hash and audit head | G6 | OPEN | |

## New failure modes (research, 2026-09-28)

| # | What goes wrong | Fix | Group | Status | Evidence |
|---|---|---|---|---|---|
| N1 | **Plausible but false reports:** the report claims checks that never ran | The gate marks such claims; "what was read" comes only from audit rows | G4 | OPEN | |
| N2 | **An empty or errored read taken as healthy** (a throttled tool returns nothing, so "no errors") | P23-EMPTY-READ; unknown health counts as failure | G4 | OPEN | |
| N3 | **Framing:** the alert name or a caller's hypothesis steers the diagnosis | No alert text or hypothesis in the prompt (G3); a paired replay eval (G7) | G3 | OPEN | |
| N4 | **Approver swayed by fluent prose** | Status shows policies and unexplained symptoms before the model's text; the displayed text's sha is stored with the approval | G3 | OPEN | |
| N5 | **Evaluation awareness:** shadow runs overstate quality | Prompts carry no bench or scenario tokens; shadow vs production distributions compared | G4 | OPEN | |
| N6 | **Escalating everything, unmeasured** | Escalation rate and act/abstain accuracy scored; an SLO set from real numbers | G4 | OPEN | |
| N7 | **WARDEN acts on its own components** | P22-SELF-TARGET on the `ops` environment; alerts about WARDEN page only | G4 | OPEN | |
| N8 | **Prompt, policy or catalogue tampered with through a PR** | CODEOWNERS; pinned-hash test; hashes in `plan_hash` and the audit | G4 | OPEN | |
| N9 | **WARDEN's own output fed back into its knowledge base** | A test that nothing in `src/` writes to `data/` | G4 | OPEN | |
| N10 | **Webhook reconnaissance or flooding** | API Gateway throttling, HMAC, intake caps | G6 | OPEN | |
| N11 | **The builder agent games tests or evals** (writes tests that pass without the guard) | `mutation_check.py` plus CI verdict assertions; every new guard plant-checked; `test_register.py` refuses "done" without a test; the mutation anchors are checked in CI (the approval-gate case had silently stopped running, audit A-B-L20) | G0 | DONE-local | tests/test_mutation_anchors.py::test_every_mutation_applies_to_the_file_as_it_is_on_disk (every mutation really runs; the full mutation check is run locally per batch, not in CI, and it does not yet cover the G1 guards - added as G1 guards close) |

## Not applicable to WARDEN, and why

- **Multi-agent failures** (MAST FM-2: inter-agent misalignment, conversation reset, withholding):
  WARDEN makes one model call per incident behind a deterministic gate. There is no second agent
  to misalign with.
- **Long-horizon drift and context rot:** there is no long conversation. Each incident gets a fresh,
  bounded prompt.
- **Agent memory poisoning:** WARDEN has no agent memory. Its knowledge base is human-edited YAML,
  and N9 guards against self-ingest.
- **Code execution by the model:** the model never runs code or commands. Actions come from a closed
  catalogue executed by typed platforms.

## Stated decisions (not gaps)

- **Every fix is human-approved** until Phase 3 shadow evidence (P17) enables a tier. The per-environment
  `auto_remediate` flags are not honoured by the workflow.
- **Architecture principle: Meta's "Agents Rule of Two".** WARDEN processes untrusted input and
  reaches sensitive data, and changes state only through a signed human approval. Detectors (P16)
  are tripwires, never gates.
- **Quality first (owner, 2026-09-28).** Paid services are used when they are the production-correct
  choice, and each is flagged with its cost in `SYSTEM-COMPONENTS.md`.
