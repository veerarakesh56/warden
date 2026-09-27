# Failure-mode register: everything that can go wrong with a fully automated WARDEN

This register comes from a read-only research review on 2026-09-27. It checked OWASP LLM and Agentic
Top 10, MITRE ATLAS, NIST AI 600-1, the AWS Agentic AI Lens, Google SRE, and published postmortems of
automation gone wrong: Knight Capital, the Google Diskerase incident, Cloudflare Nov 2025, the Azure
Front Door outage of Oct 2025, AWS Oct 2025, and the Anthropic Sept 2025 postmortem.

Each item is **built** (in code), **designed** (plan / docs), or a **gap**. Gaps are listed with the
free fix and the phase that closes them. An item leaves this list only when its test exists.

What is already built and tested:
- grounding P13/P14/P15 and inert model text;
- quarantine plus the 14-family injection corpus;
- the closed action set and the deterministic verifier;
- the credential allowlist;
- the outbound gate G2/G3/G5 with Slack unfurling off;
- bounded prompts;
- the approval digest;
- per-environment names and SSM;
- rendered per-environment IAM.

## Gaps: critical

| # | What goes wrong | Free fix | Phase |
|---|---|---|---|
| C13, C14 | **WARDEN fails together with the incident** (region outage), and nobody notices it is down | Core worker writes a heartbeat parameter every 5 min. A scheduled GitHub Actions job pages Slack when it is stale. A daily synthetic shadow incident runs the whole pipeline. A "WARDEN is down" runbook | 4 |
| C18 | **False recovery.** A dead service stops emitting errors and its alarm goes OK (`treat_missing_data = notBreaching`) | Success needs positive signals: request count above a floor, plus a probe. Missing data counts as failure. Re-check at T+15 and T+60. Health alarms use `breaching` | 2 (check), 4 (alarms) |
| C1 | **Feedback loop.** WARDEN's own restart trips the alarm, which starts a new incident, which restarts again | An alarm on a target inside an open remediation's verify window becomes a signal to that workflow, not a new incident | 2 |
| S6 | **Environment mislabelled.** An alert claims dev for a prod resource, and dev auto-remediates | Read the environment from the resource's own `Environment` tag and name prefix. If they disagree with the claim, escalate. The per-environment boundary is the backstop | 2 (+1.5 boundary) |
| H6 | **Approver impersonation.** Any channel member can press a Slack button; a compromised Slack account can approve | Allowlist by immutable `team_id`+`user_id`. Workspace 2FA. T2+ also needs the approver's Ed25519 signature | 2 |

## Gaps: high

| # | What goes wrong | Free fix | Phase |
|---|---|---|---|
| M15, E6 | **Model drift.** The provider updates the model or the CLI and quality changes silently | Pin dated model ids. Record model id and CLI version in the audit. The replay suite gates every model, prompt or CLI change | 1.5 (pin), 3 (gate) |
| M10, M11 | Alert name/summary and free-text config (Lambda descriptions, env values, tags) reach the model as text | Quarantine the alert summary and free-text config fields. Pass the rule id plus sanitised labels | 2 |
| C2, C20, C21 | Alarm storms and flapping; acting on OK/INSUFFICIENT_DATA events; a reused workflow id rejecting the next real incident | Group at intake by resource and window. N flips in M min means escalate. Cap open incidents. Accept `state=ALARM` only. Re-read the live state before acting. id = alarm + transition time | 2, 4 |
| C4, C5 | Fighting other automation (autoscaling, Argo self-heal, the next Terraform apply) or acting mid-deploy | Pre-check for an owning controller or a rollout in progress. Catalogue field `conflicts_with` | 2 |
| C8 | Oscillation (rollback of a rollback) | Never automatically reverse WARDEN's own fix. "Known-good" = healthy for ≥ N min | 2 |
| C22 | WARDEN's generated config (`decider.json`, signatures) ships unchecked | Schema, size and replay validation before load. Keep last-known-good | 3 |
| S5 | Forged alerts through an unauthenticated webhook | API Gateway authorisation with an HMAC/bearer key from SSM. The reader confirms the alarm exists and is in ALARM | 4 |
| S9 | Supply chain: dependencies unpinned, base image by tag | Hash-locked dependencies (`--require-hashes`). Images pinned by digest. SBOM | 2 (before any worker image) |
| S15 | Temporal server reachable without authentication | mTLS (free in open-source Temporal) plus a security group limited to the workers | 4 |
| S2 | Secrets in Temporal history (activity error messages) | Payload codec including failure attributes. The redaction map is never a payload | 2 |
| S12 | The audit can be rewritten by whoever holds the key and the database | Anchor each signed digest externally: a git commit, or S3 under another principal | 2 |
| H1, H10 | Approval fatigue; nobody approves before the TTL | Approval-latency metric (flag under 10 s). Cap requests per hour. T2+ requires typing the target. Escalation ladder when the TTL lapses, then "no action taken" is recorded | 2, 3 |
| E2, E5 | Calibration trained on its own outcomes; shadow thresholds too weak (20/20 correct still leaves a ~14% upper error bound) | Labels only from independent ground truth. Gate on the Wilson lower bound | 3 |
| M19, M20 | No defined degraded mode when the model provider is down; unqualified cross-provider fallback | No model → a rules-only report plus a human page. A provider is enabled only after passing the replay set | 2, 3 |
| O5 | Code or catalogue changes under an in-flight approval | plan_hash includes catalogue and code version. Refuse to apply on mismatch | 2 |

## Gaps: medium and low

| # | What goes wrong | Free fix | Phase |
|---|---|---|---|
| M2 | Numbers, units and times misread (ms/s, MB/MiB, UTC vs local) | Grounding compares numeric claims with metric values after unit normalisation. All times in UTC | 3 |
| M18 | No daily token cap across incidents (an alarm storm × N) | A daily cap across incidents | 2 |
| C3 | Remediation mutex keyed on a name, not the resource | Key it on the canonical ARN | 2 |
| C6 | No change freeze / maintenance window / business hours rule | `data/freeze.yaml` + a P-FREEZE policy | 2 |
| C10, C17 | Restarting everything at once; no canary | Batched restarts respecting min-healthy; apply to one instance first for T2 actions | 2 |
| H3 | WARDEN's own Slack noise | One thread per incident, updated in place | 2 |
| H4, H5 | People lose the skill; unclear accountability | Quarterly game day without WARDEN; a one-page RACI | 5 |
| S4, S11 | Secret rotation; data residency (Bedrock cross-region inference) | Rotation runbook; choose the inference region deliberately | 4 |
| S17 | Anyone with the webhook URL can post fake "WARDEN" messages | Approvals only through the signed app card; incident ids verifiable in the audit | 2 |
| E7 | Audit rows don't pin the versions that decided | Record git sha, prompt/catalogue/decider hashes, model id and CLI version on each row | 2 |
| O3, O4, O6 | Temporal history size and retention; backup/DR of WARDEN's state; clock skew | Blob store + continue-as-new + retention; backups; `workflow.now()` and a skew check | 2, 4 |
| M23 | Non-English logs miss the English vocabulary | Code-shaped facts only; measure | later |
| O8 | Reading an already-degraded database adds load | `statement_timeout`, `lock_timeout`, `application_name` on the reader | 1.5 |
| O9 | Applied fixes leave no change record | A GitHub issue per applied change | 4 |

## Stated decisions (not gaps)

- **Production is human-approved by design.** pre-prod, qa-prod and prod never auto-remediate. P2
  rejects irreversible actions, and T3 is never automatic.
- **Paid items, used only if chosen:**
  - NAT gateway, VPC endpoints and public IPv4 for cloud workers;
  - CloudWatch Logs Insights queries;
  - Bedrock or API tokens.

  Grouping happens in the intake Lambda, not in paid composite alarms.
- **Approval flow, reconciled.**
  - Phase 2 uses a signed approval from the CLI (Ed25519).
  - Phase 4 adds the Slack button through API Gateway. It works for T1. For T2 and above, the Slack
    click is only a front: the approver's signature is still required.
