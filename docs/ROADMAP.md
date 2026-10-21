# Roadmap

What is built, what has been measured, and what comes next. Dates are estimates, not commitments. The
detailed record of each change is in [`CHANGELOG.md`](../CHANGELOG.md); what is still open is in
[`FAILURE-MODES.md`](FAILURE-MODES.md), where every row is either closed by a test or marked open.

## Built

- **Diagnosis.** Evidence from AWS (CloudWatch, ECS, Lambda and many more services), Kubernetes, five
  database engines, Datadog, Grafana and X-Ray; redaction; untrusted text reduced to typed facts; one
  model diagnosis with cited evidence, a second opinion before any fix reaches a person.
- **Decision.** The deterministic verifier and outbound gate; observe mode for new policies.
- **Remediation.** Temporal workflows; a closed catalogue of writes; signed approvals of the exact plan
  hash (passkeys on an approval page, or an Ed25519 break-glass key); re-planning on drift; the workflow's
  own success check and rollback; bounds, a breaker and a kill switch.
- **Record.** A hash-chained, signed audit; records pages; a GitHub issue per applied change.
- **Cloud runtime.** The Terraform module for running WARDEN in AWS (`terraform/modules/warden-runtime`),
  deployed and run in a development account.
- **Measurement.** A replay qualification that every model must pass, and held-out benchmark sets with
  their answer keys ([`BENCHMARKS.md`](BENCHMARKS.md)).

## Next

| What | Why |
|---|---|
| Calibration and shadow mode | Prod: no fix is applied without a person's passkey, and Eldane, the AI critic, runs there in shadow - it reviews and is scored, never approves. Dev: autonomous through Eldane from the first plan, with no shadow period; demoted at the first failure until a person re-enables it (autonomy.py). The calibrated decider exists but does not yet beat the base rate, so nothing decides on it. |
| Lower escalation | The production model hands most incidents to a person. Fewer escalations of right fixes, with no more wrong ones, is the main quality goal. |
| A production environment | Today it has run against a development environment only. A separate production environment, deployed only from its own branch with a required reviewer, is next. |
| Game days | A quarterly exercise without WARDEN, so people keep the skill to diagnose ([`governance/GAME-DAY.md`](governance/GAME-DAY.md)). |
| Backup and restore drill | A measured restore of WARDEN's own record. |
| Temporal codec server | So the Temporal web UI can show decrypted payloads to people allowed to see them. |

## Rules the work follows

- **Nothing is "done" without evidence.** `tests/test_register.py` fails CI if a register row is marked
  done without a test that exists and is not skipped.
- **Every guard is plant-checked:** remove it, and its test must fail.
- **Every commit runs the full checks** (tests, evals, ruff, bandit, zizmor, the publish check, Terraform
  format and validate), and CI must be green.
- **Tools and prices are checked live** before they are chosen or relied on.
- **Times are given in UTC and IST (UTC+05:30).**
