# Owner steps, AWS console only

Things only you can do. The operator (`warden-operator`) is blocked from all of them by design.
Everything is done in the AWS web console, with no CLI. Each policy is a **complete file**: open it on
GitHub, press **Raw**, **Ctrl+A**, **Ctrl+C**, and paste it over everything in the console's JSON box.

**Sign in as your admin identity** (the one you used to create `warden-operator`), not as the operator.
Avoid the root user.

---

## ▶ NOW: nothing to do

**Laptop sign-in: dropped (owner decision, 2026-09-27).** No console password, no password manager.
Local work keeps using this machine's current credentials. The real-world test runs entirely in the
cloud, where every part uses a machine identity (GitHub OIDC for deploys, a task role for each WARDEN
worker) and no person's key is involved (`docs/PRODUCTION-ARCHITECTURE.md`).

The next steps here arrive when an environment is first brought up:
- its permissions boundary, deploy role and parameters, from the committed files in `iam/<env>/`;
- one small update to the operator boundary, so the operator can hand work to that role.

---

## Done 2026-09-27

1. `WardenFullstackOperator` updated: the operator may delete detached network interfaces (used the
   same day to clean up the old stack).
2. `WardenOperatorGuardrails` (deny-only) created from
   [`operator-guardrails.json`](https://github.com/veerarakesh56/warden/blob/main/terraform/proving-ground/operator-guardrails.json)
   and attached to `warden-operator`.
3. IAM Access Analyzer `warden-external-access` created in ap-south-2, **external access** type only.
   The other types are paid. Its "Service access" setting (AWS Organizations) is left alone.
   - Check **Access analyzer → Resource analysis → Active** after every live AWS window.
   - No findings is the goal. Any finding means something is reachable from outside the account; tell
     Claude which resource it names.

**Undo, if ever needed:**
- For 1: the policy's **Policy versions** tab → previous version → **Set as default**.
- For 2: user → **Permissions** → remove `WardenOperatorGuardrails`.
- For 3: **Analyzer settings** → tick the analyzer → **Delete**.
