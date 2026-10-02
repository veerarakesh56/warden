# Roadmap (approved 2026-09-28)

This is the public version of the plan approved on 2026-09-28. The plan followed a full audit
([`AUDIT-2026-09-28.md`](AUDIT-2026-09-28.md)), the owner-requirements trace
([`REQUIREMENTS-TRACE.md`](REQUIREMENTS-TRACE.md)) and twelve live research reports
([`research/2026-09-28/`](research/2026-09-28/README.md)).

**The goal:** a WARDEN that companies can run every day for years. Quality comes first, and cost is
cut only where that costs no quality. Every defect gets a fix proven by a test that fails without
it, and every register row is either done or deferred with the owner's agreement.
[`PRODUCTION-ARCHITECTURE.md`](PRODUCTION-ARCHITECTURE.md) is the target design.

## Rules

- **Nothing is "done" without evidence.** `tests/test_register.py` fails CI if:
  - a row is marked done without a test that exists and is not skipped;
  - an open row belongs to a group that has already finished.
- **Every guard is plant-checked:** remove it and its test must fail.
- **Every commit runs the full checklist** (tests, evals, ruff, bandit, zizmor, publish check,
  Terraform fmt/validate), and CI must be green.
- **Tools and prices are researched live** before they are chosen or relied on.
- **Exploit details stay private until fixed.** A finding that is exploitable on the live account
  is published only after its live fix, because the repository is public.
- **Times are given in UTC and IST (UTC+05:30).**
- **Owner steps are console only**, with complete files, click steps and costs. Each AWS window ends
  with destroy, the all-region sweep and a next-day billing check.

## Order of work

| Step | What | Where | Estimate |
|---|---|---|---|
| W-T | Temporal Cloud namespace (aws-ap-south-2) | owner + Claude | **done 2026-09-28** |
| G0 | Honesty and records: CHANGELOG/README corrections, the audit register, requirements trace, research record, `test_register`, docs honesty test, mutation-check fix, publish-check patterns | local | ~3 days |
| W0-now | Urgent live fixes: the operator policy, IAM Roles Anywhere for the laptop (no password, no key), secrets moved to Secrets Manager and plaintext files deleted, Bedrock access check, trial and Free-plan end dates | owner console | about 25 minutes of clicks in 5 sittings, plus a next-day check (step E5) |
| G1 | Security-critical fixes: quarantine holes, outbound gate on every egress, tripwire, redaction, removal of the in-process live paths, MCP read scoping, codec fail-closed, IAM isolation and CI hardening, vacuous tests rewritten | local | ~2 weeks → **v0.10.1** |
| G2 | Workflow correctness: bounded retries, every path audited, the ≤ 2 model-call cap, remediation bound to incident/verdict/environment/target, full `plan_hash`, re-plan on drift, trust-zone queues, worker versioning | local | ~1.5 weeks |
| G3 | The remaining Phase-2 register rows: intake, alert-text quarantine (measured first), real success checks, conflicts, freeze windows, model pinning and qualification, degraded mode, caps, Postgres audit, supply chain, zero hardcoding, backend and harness fixes | local | ~3 weeks → **v0.11.0** |
| W0 | GitHub: branch protection with required checks, CODEOWNERS, every environment deploys only from `main`, the OIDC sub-claim customisation | owner (GitHub web UI) | after G3, $0 |
| G4 | The new failure modes plus the research adoptions: compromised-model tests, ControlArena, blind diagnosis, admission policy and chaos in CI, sandbox-runtime, Scorecard/Checkov, model-weight verification | local + CI | ~3 weeks → **v0.12.0** |
| G5a | Integrations: Prometheus evidence, GitOps detection, PagerDuty, Slack bot, passkey approval page, KMS signer, Bedrock provider | local | ~2.5 weeks |
| W-B | Live Bedrock: Sonnet 5 through the India geo profile, re-qualified on Bedrock (register M20), Petri audit, Gemini test | owner + Claude | 1 window |
| G5b | Qualification results published | — | → **v0.13.0** |
| G6 | Production runtime (Temporal Cloud, ECS on EC2, Aurora, S3 Object Lock, KMS, Secrets Manager, intake, approval, observability), change timeline, operations docs, threat model; windows W1 (identity), W2 (laptop-off rehearsal), W3 (the 28-fault run) | local + windows | ~8–10 weeks → **v0.14.0** |
| G7 | Calibration and shadow mode: independent labels, Platt + conformal, UQLM, Wilson bounds, Inspect AI gate, catch trials | local | ~2 weeks → **v0.15.0** |
| G8 | Helios gate on every Terraform change, game day and RACI, public benchmarks | local | ~1.5 weeks → **v1.0** |

**Total:** about 24–28 weeks of work.

**Recorded deviation (2026-09-28).**
- The order puts W0-now before G1. W0-now waits on owner console steps, so G1 code work started while it was pending.
- An independent review then refuted most of the G1 rows first marked done. They are reopened, each with its reason (AUDIT-2026-09-28).
- The `ops` environment moved from G0 to G1, with the IAM work.

## Calendar (estimates, not commitments)

All dates are in UTC, with IST = UTC+05:30. They assume continuous work and owner windows being
available when due. They will be re-checked against two dates that are not yet known: the end of the
AWS Free plan (6 months from account creation) and the end of the Temporal Cloud trial. Both are read
in W0-now, and the owner is told before any window they affect.

| Milestone | Target (UTC / IST) |
|---|---|
| G0 complete | 2026-10-01 / 2026-10-01 (records corrected after the 2026-09-28 independent review; SYSTEM-COMPONENTS cost table delivered in 40f5f0e) |
| W0-now window | A-E2 done 2026-10-02 (E1 at 14:11 UTC / 19:41 IST); E5 2026-10-03; E3 and E4 from 2026-10-04 14:11 UTC / 19:41 IST |
| v0.10.1 (G1) | 2026-10-16 / 2026-10-16 |
| v0.11.0 (G2 + G3) | 2026-11-13 / 2026-11-13 |
| v0.12.0 (G4) | 2026-12-04 / 2026-12-04 |
| v0.13.0 (G5 + W-B) | 2026-12-23 / 2026-12-23 |
| v0.14.0 (G6 + W1–W3) | 2027-02-26 / 2027-02-26 |
| v0.15.0 (G7) | 2027-03-12 / 2027-03-12 |
| v1.0 (G8) | 2027-03-24 / 2027-03-24 |

⚠ **Known date that affects the plan:** the Temporal Cloud trial ($150 of credits for 90 days from
2026-09-28) ends around **2026-12-27**, before the G6 windows (W1-W3, 2027-02). After that, Temporal
Cloud is paid (about $50 per million Actions; SYSTEM-COMPONENTS section 11). The exact date is read in
W0-now step F. The owner decides before W1 whether to pay, and the decision is recorded here.

**Read in W0-now (2026-10-02):** the AWS Free plan ends **2027-03-09 09:50 UTC / 15:20 IST**, with USD 171.78
of credits left. The AWS windows (W-B, W1-W3, the last ending 2027-02-26) fit before it, with 11 days to spare;
G7 and G8 come after it. The cost estimates published before W2 and W3 are checked against the credits left
then, and the owner decides before W1 what happens to the account at plan end.

The dates are whole days, so UTC and IST fall on the same date. Window start and end times are
always given in both.

## Owner decisions this roadmap rests on (2026-09-28)

1. **Quality first.** Paid services are allowed when they are the production-correct choice, each
   flagged with its cost.
2. **Orchestration:** Temporal Cloud.
3. **Account:** one AWS account, hardened; the IaC also supports multi-account.
4. **Runtime:** test windows only, until there is a real system to watch.
5. **Secrets and config:** Secrets Manager for every secret, SSM for plain configuration.
6. **ECS:** on an EC2 capacity provider.
7. **Drift:** re-plan, and ask for approval again.
8. **Slack:** a bot with threads.
9. **Releases:** keep the v0.10.0 tag and correct its notes.
10. **GitOps:** detect it and escalate now; a PR path comes later.
11. **Identity:** AWS-native; Teleport as an optional adapter.
12. **Production model:** Bedrock Claude Sonnet 5 (owner, 2026-10-03; Opus 5.5 failed WARDEN's replay qualification).
13. **Paging:** PagerDuty.
14. **Approvals:** passkeys on the owner's Cloudflare domain.
15. **Audit signing:** KMS Ed25519, with an S3 Object Lock anchor.
16. **Write path:** only the Temporal workflow can change anything.
