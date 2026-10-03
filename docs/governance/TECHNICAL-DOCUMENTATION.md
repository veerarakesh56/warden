# Technical documentation and instructions for use (audit CW5)

An index in the order of the EU AI Act's Annex IV (technical documentation, Article 11), pointing to where each
part is kept, and the instructions for use a deployer needs (Article 13). Not legal advice; see
`docs/COMPLIANCE-CROSSWALK.md` for whether these obligations apply at all.

## Annex IV, part by part

| Annex IV | Where |
|---|---|
| 1. General description: purpose, provider, versions, how it interacts with other systems, forms of release, hardware, instructions for use | `README.md`; `CHANGELOG.md`; `docs/PRODUCTION-ARCHITECTURE.md`; the instructions below |
| 2. Detailed description: design choices, architecture, data, human oversight measures, pre-determined changes, validation and testing | `docs/DESIGN-DECISIONS.md`; `docs/ARCHITECTURE.md`; `docs/governance/AI-POLICY.md`; `docs/FAILURE-MODES.md`; the test suite and plant checks |
| 3. Monitoring, functioning and control: capabilities and limits, accuracy expected, foreseeable unintended outcomes | `src/warden/data/providers.yaml` (measured qualification and escalation SLO); `docs/governance/IMPACT-ASSESSMENT.md` |
| 4. Appropriateness of the performance metrics | `scenarios/SCORING.md`; `src/warden/data/decider.json` (held-out measurement) |
| 5. Risk management system | `docs/FAILURE-MODES.md`, `docs/AUDIT-2026-09-28.md`, `docs/REQUIREMENTS-TRACE.md` and `tests/test_register.py` |
| 6. Relevant changes over the lifecycle | `CHANGELOG.md`; git history; the change records (O9) |
| 7. Standards applied | `docs/COMPLIANCE-CROSSWALK.md` |
| 8. EU declaration of conformity | not drawn up: not required for a system that is not high-risk; to be written by a deployer for whom it is |
| 9. Post-market monitoring | escalation SLO (N6), observe-mode measurement (A-P-8), concerns (`CONCERNS.md`), labels (A-P-2) |

## Instructions for use (for whoever deploys WARDEN)

**Intended purpose.** Decision support for on-call engineers: a diagnosis with cited evidence and at most one
proposed remediation from a closed catalogue, applied only after a person approves the exact plan.

**Not intended for.** Changing systems without a person; acting on its own components; environments it is not
configured for; any use where a wrong remediation could endanger health or safety without a separate safety system.

**Accuracy to expect.** On WARDEN's 30-incident replay set the production model (Claude Sonnet 5) chose the
correct action in 19, let no wrong fix through, and handed 25 of 30 to a person (`providers.yaml`). Expect it to
escalate often; that is the safe failure.

**Human oversight.** Approvers sign the exact plan; T2 and T3 need the target typed; the kill switch stops every
change; the gate's policies are shown before the model's prose.

**Inputs and data.** Logs, metrics, deploy records and configuration, redacted before any model sees them.
Untrusted text reaches the model only as typed facts. Where the model processed them is recorded with every
diagnosis (`processed_in` in the audit's provenance); the production deployment uses Bedrock's India geography
profile, so inference stays in India (D12).

**Operating and maintenance.** `docs/OPERATIONS.md` (rotation), `docs/RUNBOOK-WARDEN-INCIDENT.md` (when WARDEN is
the incident), `docs/governance/GAME-DAY.md` (keeping the skill), yearly signature review (R46).

**Logs.** Every proposal, approval, change and model call is in the tamper-evident audit; `warden audit verify`
checks it.
