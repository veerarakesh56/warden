# Impact assessment (audit CW2)

Who WARDEN affects, how it could harm them, how likely and how bad, what holds it, and what is left. Not legal
advice. Reviewed with the AI policy (`AI-POLICY.md`).

## Who is affected

- **On-call engineers**: WARDEN shapes what they see first at 3 am, and asks them to approve changes.
- **The people and businesses using the services WARDEN watches**: a wrong fix, or a slow one, is their outage.
- **People whose data is in the logs**: logs carry identifiers, credentials and sometimes personal data.
- **The operator of the install**: carries the cost, the accountability and the regulatory position.

## Benefits

Faster first diagnosis with the evidence cited; a fix proposed only from a closed, reviewed catalogue; a complete,
tamper-evident record of what was proposed, approved and done.

## Harms, and what holds each

| Harm | Likelihood | Severity | What holds it | Left over |
|---|---|---|---|---|
| A wrong fix makes an outage worse | medium | high | signed approval of the exact plan (R50, H6); the gate (P0-P24); bounds and the breaker (B12); rollback and its own success check | a hasty approver (H1 records hasty approvals) |
| A correct fix is escalated, so the outage lasts longer | high (Sonnet 5 escalates 25 of 30, N6) | medium | escalation is measured against an SLO (N6); calibration is G7's work | escalation stays high until calibration earns a role (R44) |
| Personal data or secrets leave in a prompt or a message | low | high | redaction before the model, the outbound gate (B6), payload encryption (S2) | patterns are open-ended (R7-O2, deferred) |
| An attacker steers WARDEN through log text | medium | high | quarantine to typed facts (B4), the tripwire (P16), the closed catalogue, approval | adaptive attacks beat detectors; only the architecture holds |
| Engineers lose the skill to diagnose without WARDEN | medium | medium | the quarterly game day (H4) | - |
| WARDEN fails during the incident it should help with | low | medium | rules-only mode without a model (M19); the WARDEN-incident runbook (A-P-6) | the heartbeat and staleness page come with the runtime (C13) |
| A person trusts a fluent report over the evidence | medium | medium | policies shown before prose (N4); claims of unrun checks marked (N1) | - |
| Environmental cost of model use | certain | low | one call per incident, measured (`warden usage`, CW3) | emissions are read at account level only |

## Regulatory position

See `docs/COMPLIANCE-CROSSWALK.md`: for a typical company WARDEN is very likely not a high-risk system under the EU AI
Act; at an operator of critical digital infrastructure it could be argued in, and a written Article 6(3) assessment
should then be kept with this document.
