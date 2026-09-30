# Owner requirements trace

Everything the owner has asked for across every session, from the requirements trace of
2026-09-28, with the work group that delivers it (see [`ROADMAP.md`](ROADMAP.md)) and its status.

`tests/test_register.py` enforces the statuses: a DONE-local row must cite a test that exists and
carries nothing that may skip or expect it to fail - any decorator but `parametrize`, `asyncio`,
`timeout` or `filterwarnings`; a module `pytestmark`, one line or many; `importorskip`, `skip(` or
`xfail(` in the test or at module level (two files are allowed a module-level skip CI never hits, each
with its reason and, for the provider extras, a test that CI still installs them). A citation the cell
calls not covering the row does not count, and `::test_x` means the file cited last. A DONE-live row
must start with the window and a past date; a DEFERRED row must start with `owner-agreed` and a real
past date; an open row cannot belong to a group that has already been finished. A skip decided at run
time any other way - an `if` around `pytest.skip` in a helper - is not detected.

## Requirements

| # | Requirement (owner's words, shortened) | Group | Status | Evidence |
|---|---|---|---|---|
| R1 | "Honesty, not polish… don't flatter me" — the docs must never overclaim | G8 | OPEN | a standing rule, not a task: it cannot be DONE, and saying so was itself an overclaim (second independent review, 2026-09-30). Enforced for every KNOWN false claim by tests/test_docs_honesty.py::test_no_known_false_claim_is_back; review 2 found more (README approval-gate line, ROADMAP cost table, FAILURE-MODES B5, the redaction 'raises' claims, owner-step flag and tfvars), corrected and pinned. Re-checked by an independent docs review before v1.0 (G8) |
| R2 | Don't pitch WARDEN as novel or as something a company should adopt as-is | G0 | DONE-local | tests/test_docs_honesty.py::test_the_readme_does_not_pitch_adoption |
| R3 | No email or account ID anywhere in the repo | G0 | DONE-local | tests/test_check_publishable.py::test_the_repository_as_it_stands_is_publishable |
| R4 | Every time given in UTC and IST (docs, reports, Slack, approval page) | G3 | OPEN | |
| R5 | "Do it yourself; if you need a permission, add it to the policy" — owner steps only where unavoidable | G1 | OPEN | |
| R6 | Complete, paste-ready files and console-only click steps | G1 | OPEN | |
| R7 | Check IAM against official AWS docs and validators | G1 | OPEN | |
| R8 | Research live, up to today, before choosing or claiming anything | G8 | OPEN | a standing working rule, not a window: 'W-research' was invented to mark it DONE-live (second independent review, 2026-09-30). Each decision's research is dated in docs/research/2026-09-28/ and in the commit that uses it; re-checked before v1.0 (G8) |
| R9 | Prefer ready-made production tools over building from scratch | G4 | OPEN | |
| R10 | Quality first; cost only to trim waste; flag every paid item with its cost | G3 | OPEN | |
| R11 | Cost safety: nothing left running and billing | G0 | DONE-local | tests/test_account_sweep.py::test_untagged_billable_resources_are_found_and_free_defaults_are_not (the sweep tool). Running it, plus the next-day billing and Access Analyzer check, after every window is an owner procedure: written as step E5 of W0-now in OWNER-CONSOLE-STEPS (added 2026-09-30 - the earlier claim that it was 'recorded per window' was untrue, third review). Last sweep: 2026-09-28 19:49 UTC / 2026-09-29 01:19 IST, clean |
| R12 | Soak before faults; watch 30 min before destroy | G6 | OPEN | review 2026-09-28: regrouped from G0. The runner refuses a fault before a soak, but `--min-minutes` overrides the minimum and nothing enforces the 30-minute watch before destroy; enforcing both belongs to the W2/W3 runtime work |
| R13 | Separate pipelines for infra, apps and the tool itself | G6 | OPEN | |
| R14 | Claude Max CLI for development and benchmarks | G0 | DONE-local | tests/test_claude_cli_provider.py::test_it_is_registered_under_both_spellings (the claude_cli provider exists and resolves; which backend a run uses is configuration) |
| R15 | Gemini API test with an AI Studio key | G5 | OPEN | |
| R16 | Bedrock provider and test | G5 | OPEN | |
| R17 | AWS region Hyderabad (ap-south-2), never hardcoded | G3 | OPEN | |
| R18 | Separate identities for the tool, the operator and the harness | G1 | OPEN | |
| R19 | Real AWS services for tests, not local Docker/k3d | G6 | OPEN | |
| R20 | ECS on EC2 (capacity provider), not Fargate | G6 | OPEN | |
| R21 | The full stack up at once, broken in every way; find, report, fix (28 faults) | G6 | OPEN | |
| R22 | Performance Insights, CloudWatch logs and Logs Insights used as evidence | G3 | OPEN | |
| R23 | Allow for logs arriving minutes late | G3 | OPEN | |
| R24 | Kubernetes access for finding problems, never editing | G1 | OPEN | review 2026-09-28: regrouped from G0. The reader RBAC is read-only, but the remediator grants `patch deployments`, which rewrites the pod template (audit A-I-11, G1) |
| R25 | Mask pids, ids and secrets before anything reaches the model | G1 | OPEN | |
| R26 | Real RCA with real names; risks stated before the steps | G6 | OPEN | |
| R27 | Slack proof of real alerts | G6 | OPEN | |
| R28 | Approve and deny from Slack | G5 | OPEN | |
| R29 | Screenshots, JSON reports and proofs of every live run | G6 | OPEN | |
| R30 | A full, current architecture diagram in the README | G6 | OPEN | |
| R31 | CI failures fixed, and CI never red | G3 | OPEN | review 2026-09-28: regrouped from G0. CI on main was red for SEVEN commits: ab900cd (pushed after green; failed on the k3d-only job) and 54180fb (pushed onto the red main), fixed in 0fcbfbb; bdb8a13 (pushed after green; failed because CI has no torch) and 5a753da (pushed onto the red main), fixed in e8278f2; ea65387 (2026-09-30, a ruff error shown as a 'hidden fix' and not run to zero before the push), fixed in 7d175af; 584e89a (2026-09-30 10:34 UTC / 16:04 IST, a race in the MCP stdio test: stdin closed before the answer), fixed in 4a2caa9; 14e32e1 (2026-09-30 14:18 UTC / 19:48 IST, parallel test workers raced to download Temporal's test server), fixed in a1b73ce. No test can prove 'never red'. The control is branch protection with required checks, an owner step in window W0 (after G3) |
| R32 | Zero hardcoding; secrets only in AWS (Secrets Manager for secrets, SSM for config) | G3 | OPEN | |
| R33 | No long-lived access keys anywhere | W0-now | OPEN | |
| R34 | Per-environment everything: dev, staging, qa-staging, pre-prod, qa-prod, prod | G6 | OPEN | |
| R35 | GitHub secrets and variables per environment | G6 | OPEN | |
| R36 | A real production runtime: event-driven, running with the laptop off | G6 | OPEN | |
| R37 | Auth tooling like Teleport, decided on evidence (AWS-native default, Teleport adapter optional) | G6 | OPEN | |
| R38 | A change timeline across all stages, like Cursor Rollouts ("which change broke it") | G6 | OPEN | |
| R39 | Unknown, new issue types still handled (escalate) | G4 | OPEN | |
| R40 | Agents never have direct access: AI decides what, orchestration controls how | G1 | OPEN | |
| R41 | Agents cannot destroy things; prompt injection defended | G1 | OPEN | |
| R42 | An output gate like ZeroDrift Anchor (PASS/REWRITE/BLOCK/ESCALATE on every egress) | G1 | OPEN | |
| R43 | Just-in-time, short-lived agent identity with full audit (Teleport Agent Trust ideas) | G6 | OPEN | |
| R44 | A calibrated decision component instead of Jev | G7 | OPEN | |
| R45 | Every AI failure mode researched, even minute ones, and each covered | G4 | OPEN | |
| R46 | Anti-faking, anti-hallucination, anti-sycophancy, no blind trust in stale data | G7 | OPEN | |
| R47 | Meta Prompt Guard as the injection detector, required in higher environments | G1 | OPEN | |
| R48 | Temporal instead of LangGraph (production orchestration) | G0 | DONE-local | tests/test_incident_workflow.py::test_every_bundled_incident_gets_the_same_verdict_as_the_graph |
| R49 | Temporal Cloud (owner's trial) | G0 | DONE-live | W-T 2026-09-28: namespace active in aws-ap-south-2; the Temporal SAMPLE Workflow completed and recovered from an injected failure. WARDEN itself on Temporal Cloud is not yet proven - that is window W2 (G6) |
| R50 | A single approver, stated honestly | G5 | OPEN | |
| R51 | WARDEN never creates database indexes | G1 | OPEN | |
| R52 | Public and private subnets done properly | G1 | OPEN | proven for terraform/fullstack only (tests/test_fullstack_infra.py::test_only_the_nat_lives_in_a_public_subnet_and_nothing_is_open_to_the_internet); second independent review 2026-09-30: the proving ground runs ECS tasks with public IPs and EKS nodes and RDS in public subnets (deliberate for the Wave 1-3 lab, documented, but not 'done properly') - G1-I |
| R53 | Every resource tagged, including Environment | G1 | OPEN | proven for terraform/fullstack only (tests/test_fullstack_infra.py::test_everything_the_stack_creates_carries_project_and_environment_tags); second independent review 2026-09-30: the proving ground's EKS node group has no launch template (its instances and volumes are untagged) and the ECS service does not propagate tags; the harness guards now follow the tags Terraform applies (tests/test_proving_ground_tags.py) - G1-I |
| R54 | Sweeps never trust tags | G0 | DONE-local | tests/test_account_sweep.py::test_a_resource_without_both_tags_or_with_an_unknown_environment_is_reported |
| R55 | Subnets, tags and isolation proven on a live stack | G6 | OPEN | |
| R56 | Helios checks every Terraform change | G8 | OPEN | |
| R57 | Evaluate the AWS Agent Toolkit / AWS MCP servers | G4 | OPEN | |
| R58 | Passkey approvals on the owner's Cloudflare domain | G5 | OPEN | |

## Working rules (how Claude works, not features)

These are followed in every session, and recorded in Claude's project memory:
- Double-check everything; no misses, no mistakes. Verify that something runs before believing it,
  and check running jobs every few minutes.
- No popping-up terminal windows. Plan mode while planning. Never go blindly.
- Never paste keys. Run `check_publishable` before and after every push. Keep CI green.
- Stop WSL and Docker when the machine is overloaded.
- Run `pytest.exe tests` exactly as CI does. Tests and evals both run before every commit.

## Stated contradictions, resolved

- **Manual trigger vs event-driven.** The benchmark harness is triggered by hand, with Claude Max.
  Production is event-driven, and both enter through `intake`. Recorded in
  `PRODUCTION-ARCHITECTURE.md`.
- **Secrets Manager vs SSM.** Decided on 2026-09-28: every secret goes to Secrets Manager, plain
  configuration goes to SSM.
