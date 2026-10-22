# Security review pack

The page a client's security team asks for: where each answer is. Every line points to the document or code that
holds it; this page adds no claim of its own. Checked against `main` at `28eabc5` (#115 and #119 merged) on
2026-10-22. Where a part is still an open pull request, it says **pending PR #n**:
under review, not merged, not running.

## What WARDEN is

An AI on-call engineer for AWS: an alarm, read-only evidence, a model's proposal from a closed catalogue, deterministic
checks, a signed approval (in prod always a person's; in dev Eldane, the AI critic, under the conditions in
[OPERATIONS.md](OPERATIONS.md#dev-autonomy-eldane-demotions-and-a-persons-re-enable-owner-2026-10-17)), one change,
verification, undo, and a signed record of each step.
[README](../README.md) · [ARCHITECTURE.md](ARCHITECTURE.md) · [How it runs in AWS](PRODUCTION-ARCHITECTURE.md) ·
[Why the model never decides](ai-boundary.md)

## Threat model

- STRIDE over the trust boundaries: [THREAT-MODEL.md](THREAT-MODEL.md).
- The trust zones ([ARCHITECTURE.md, trust zones](ARCHITECTURE.md#trust-zones)), the safety layers
  ([ARCHITECTURE.md, the safety layers](ARCHITECTURE.md#the-safety-layers)), and the register of failure modes with
  the test that holds each ([FAILURE-MODES.md](FAILURE-MODES.md)).

## Data: what leaves, what is kept

- What leaves the network, to where, how it is masked and checked, and what the model provider does with a prompt
  (training, retention, region, each linked to Anthropic's page), the egress ledger, the sealed vault and the
  approvers' reveal: [DATA-EGRESS.md](DATA-EGRESS.md).
- What WARDEN stores, where, and for how long; how to delete it: [DATA-RETENTION.md](DATA-RETENTION.md).

## Permissions

- Which identity has which access, per zone, and why no long-lived key exists:
  [How each part gets access](PRODUCTION-ARCHITECTURE.md#how-each-part-gets-access-no-keys-anywhere).
- The IAM policies themselves, per environment: [`iam/templates/`](../iam/templates/) (rendered into
  [`iam/dev/`](../iam/dev/), [`iam/prod/`](../iam/prod/), [`iam/ops/`](../iam/ops/)).
- The operator identity and its guardrails: [AWS-SETUP.md](AWS-SETUP.md).
- The runtime's roles, keys and network: [`terraform/modules/warden-runtime/`](../terraform/modules/warden-runtime/).

## Human approval

Tiers, passkeys, Sign in with Slack and break-glass: [Human approval](PRODUCTION-ARCHITECTURE.md#human-approval) ·
[People and records](ARCHITECTURE.md#people-and-records) · dev autonomy through Eldane and when it stops:
[OPERATIONS.md](OPERATIONS.md#dev-autonomy-eldane-demotions-and-a-persons-re-enable-owner-2026-10-17).

## Audit

- The signed hash chain, its KMS signer and S3 Object Lock anchor, and `warden audit verify`:
  [ARCHITECTURE.md, the safety layers](ARCHITECTURE.md#the-safety-layers) · [`audit.py`](../src/warden/audit.py).
- Reading the records: [OPERATIONS.md, WARDEN's records](OPERATIONS.md#wardens-records-registers-g10-46-g10-47).
- Retention of the audit and logs: [DATA-RETENTION.md](DATA-RETENTION.md).

## Kill switches

- WARDEN's own switch, the breaker that trips it, and the signed reset:
  [ARCHITECTURE.md, the safety layers](ARCHITECTURE.md#the-safety-layers) ·
  [`bounds.py`](../src/warden/bounds.py).
- Stopping every change in the first minute, including without WARDEN (the act service to zero):
  [RUNBOOK-WARDEN-INCIDENT.md](RUNBOOK-WARDEN-INCIDENT.md#0-first-minute-whatever-happened-stop-all-changes).
- The IAM deny on the actor role, outside WARDEN's code:
  [`scripts/iam_kill_switch.py`](../scripts/iam_kill_switch.py) ·
  [`iam/templates/kill-switch.json`](../iam/templates/kill-switch.json).

## When WARDEN itself is the incident

[RUNBOOK-WARDEN-INCIDENT.md](RUNBOOK-WARDEN-INCIDENT.md) · secret and key rotation:
[OPERATIONS.md](OPERATIONS.md#secret-and-key-rotation-register-s4) · frameworks mapped to the register:
[COMPLIANCE-CROSSWALK.md](COMPLIANCE-CROSSWALK.md).

## Reporting a vulnerability

[SECURITY.md](../SECURITY.md) (GitHub private vulnerability reporting).
