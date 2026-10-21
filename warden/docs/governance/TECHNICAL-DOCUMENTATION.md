# Technical documentation and instructions for use (register CW5)

An index in the order of the EU AI Act's Annex IV (technical documentation, Article 11), pointing to where each
part is kept, and the instructions for use a deployer needs (Article 13). Not legal advice; see
`warden/docs/COMPLIANCE-CROSSWALK.md` for whether these obligations apply at all.

## Annex IV, part by part

| Annex IV | Where |
|---|---|
| 1. General description: purpose, provider, versions, how it interacts with other systems, forms of release, hardware, instructions for use | `README.md`; `CHANGELOG.md`; `docs/PRODUCTION-ARCHITECTURE.md`; the instructions below |
| 2. Detailed description: design choices, architecture, data, human oversight measures, pre-determined changes, validation and testing | `docs/DESIGN-DECISIONS.md`; `docs/ARCHITECTURE.md`; `warden/docs/governance/AI-POLICY.md`; `warden/docs/FAILURE-MODES.md`; the test suite and plant checks |
| 3. Monitoring, functioning and control: capabilities and limits, accuracy expected, foreseeable unintended outcomes | `warden/docs/BENCHMARKS.md`; `warden/src/warden/data/providers.yaml` (measured qualification and escalation SLO); `warden/docs/governance/IMPACT-ASSESSMENT.md` |
| 4. Appropriateness of the performance metrics | `fault-lab/scenarios/SCORING.md`; `warden/docs/BENCHMARKS.md`; `warden/src/warden/data/decider.json` (held-out measurement) |
| 5. Risk management system | `warden/docs/FAILURE-MODES.md` and `warden/tests/test_register.py`, which fails if a row is marked done without a test |
| 6. Relevant changes over the lifecycle | `CHANGELOG.md`; git history; the change records (O9) |
| 7. Standards applied | `warden/docs/COMPLIANCE-CROSSWALK.md` |
| 8. EU declaration of conformity | not drawn up: not required for a system that is not high-risk; to be written by a deployer for whom it is |
| 9. Post-market monitoring | escalation SLO (N6), observe-mode measurement of new policies, concerns (`CONCERNS.md`), signed approver labels (`warden label`) |

## Instructions for use (for whoever deploys WARDEN)

**Intended purpose.** Decision support for on-call engineers: a diagnosis with cited evidence and at most one
proposed remediation from a closed catalogue, applied only after a person approves the exact plan.

**Not intended for.** Changing systems without a person; acting on its own components; environments it is not
configured for; any use where a wrong remediation could endanger health or safety without a separate safety system.

**Accuracy to expect.** On WARDEN's 30-incident replay set the production model (Claude Sonnet 5.5) chose the
correct action in 17, let no wrong fix through, and handed 24 of 30 to a person (2026-10-15, `providers.yaml`). On
172 held-out cases it was correct in 160 and let no harmful proposal through (`warden/docs/BENCHMARKS.md`). Expect it to
escalate often; that is the safe failure.

**Human oversight.** Approvers sign the exact plan; T2 and T3 need the target typed; the kill switch stops every
change; the gate's policies are shown before the model's prose.

**Inputs and data.** Logs, metrics, deploy records and configuration, redacted before any model sees them.
Untrusted text reaches the model only as typed facts. The default deployment calls the Anthropic API, and Anthropic
decides where inference runs; where a diagnosis was processed is recorded with it (`processed_in` in the audit's
provenance). A deployer who needs inference in one region can choose a provider that offers it, after qualifying it.

**Operating and maintenance.** `warden/docs/OPERATIONS.md` (rotation), `warden/docs/RUNBOOK-WARDEN-INCIDENT.md` (when WARDEN is
the incident), `warden/docs/governance/GAME-DAY.md` (keeping the skill), a yearly review of each incident signature.

**Logs.** Every proposal, approval, change and model call is in the tamper-evident audit; `warden audit verify`
checks it.
