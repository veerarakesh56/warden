# Environmental impact (register CW3)

WARDEN's environmental cost is mostly the model calls it makes and the cloud resources it runs on. No model provider
publishes energy per token, so WARDEN measures what it controls and reads the rest at account level.

## What WARDEN measures itself

Every model call is recorded with its tokens and cost (`incident.llm_spend` rows in the audit). Per day:

```
warden usage --days 30
```

prints the incidents, calls, input and output tokens and USD for each day. Model use is capped by design: each
incident has a ceiling of model calls and of US dollars (6 calls and US$0.25 in the cloud runtime), there is a daily
cap on tokens and USD across incidents (M18), and no call is made at all when the provider is down (rules-only
escalation, M19).

## What the account reports

AWS's Customer Carbon Footprint Tool reports the account's emissions - Scope 1, 2 and 3 since its October 2025 update,
with history from January 2022 - in the Billing console (Carbon footprint). Read it monthly while WARDEN runs in the
cloud, and record it below. It is account-level: WARDEN's share is estimated from its services' share of the bill.

| Month | Account emissions (MTCO2e) | WARDEN's share of the bill | Tokens (from `warden usage`) |
|---|---|---|---|
| 2026-10 | not read yet | - | - |

Source: https://aws.amazon.com/about-aws/whats-new/2025/10/aws-customer-carbon-footprint-tool-scope-3-emissions-data
(read 2026-10-03).
