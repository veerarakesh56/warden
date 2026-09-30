# Owner steps, AWS console only

Things only you can do. The operator (`warden-operator`) is blocked from all of them by design.
Everything is done in the AWS web console, with no CLI. Each policy is a **complete file**: open it on
GitHub, press **Raw**, **Ctrl+A**, **Ctrl+C**, and paste it over everything in the console's JSON box.

**Sign in as your admin identity** (the one you used to create `warden-operator`), not as the operator.
Avoid the root user.

---

## ▶ NOW: W0-now - no more long-lived key (about 25 minutes of clicks, in 5 short sittings)

> ⏸ **Wait for Claude's go-ahead before starting.** An independent review (2026-09-28) found gaps
> in the first version of these steps: the chained sweep role was missing `sts:SetSourceIdentity`,
> no step sent the profile ARN, the old key could have been used by mistake, and some plan items
> were missing. This version fixes them. It will be re-verified before you are asked to start.

What this gives:
- The laptop stops using an access key. It signs in to AWS with a certificate whose private key
  lives inside the laptop's TPM chip, so the key cannot be copied off the machine.
- The old IAM user and its key are retired.
- The new operator identity can only read and check: no builds, no database logins, no IAM
  changes (`iam/operator/policy.json`, enforced by `tests/test_operator_role.py`).
- The Slack webhook moves from a plaintext file into Secrets Manager, and the leftover plaintext
  files are deleted.
- Claude reads and records three facts: the AWS Free-plan end date and credits, whether this
  account may use Claude models on Bedrock, and (from you) the Temporal Cloud trial end.

**Honest limit.** The TPM key has no PIN. Malware running as you, while the laptop is on, could use
it to get 1-hour credentials. It can never copy the key. If the laptop is lost or you suspect that,
use step G at once.

**Already done on this computer by Claude (2026-09-28):**
- The TPM key and certificate were created. The CA that signed the certificate was thrown away, so
  no CA key exists anywhere.
- AWS's `aws_signing_helper` 1.8.5 was downloaded, and its checksum and Amazon code signature were
  verified. It signs with the TPM key offline. It finds the certificate with the selector
  `Key=x509Subject,Value=CN=warden-operator-laptop,O=warden`.

**Cost:**
- IAM Roles Anywhere: no additional cost. The source is AWS's announcements (the 2022 launch and
  the 2023 region additions); no current pricing page says otherwise (searched 2026-09-30). WARDEN
  uses its own certificate authority, so no AWS Private CA charge applies.
- Whether a **Free-plan** account may use it is NOT confirmed. AWS says a Free-plan account gets
  "access to select AWS services" and lists none as blocked. On 2026-09-30 a read-only API call from
  this account got an ordinary IAM refusal (the old operator lacks the permission), not a plan block.
  That is evidence, not proof. Step B1 is the real test.
- IAM: free.
- Secrets Manager: USD 0.40 per secret per month plus USD 0.05 per 10,000 calls, so about USD 0.40
  a month, covered by the Free-plan credits.

**Before you start:** sign in as your admin identity, and set the region (top right) to
**Asia Pacific (Hyderabad) ap-south-2** wherever a step says so.

**A. One click, first.**
1. IAM → **Users** → `warden-operator` → **Permissions** tab.
2. Tell Claude the names of every policy listed there.
3. Tick `WardenProvingGroundOperator` → **Remove**. This policy let the operator log in to any
   database as its master user and edit its own permissions (audit A-I-4). Nothing uses it now.
4. If `WardenProvingGroundOperatorRdsEks` is listed, remove it too.
5. Leave the rest for now.

Side effect: until step B works, Claude cannot run `scripts/validate_policies.py`. Only that
removed policy granted Access Analyzer.

**B1. The trust anchor** (region Hyderabad).

⚠ If the console refuses because of the account plan (a message about the Free plan, upgrading, or a
subscription), stop there and tell Claude. Step A stays done (it is a fix on its own), the laptop
keeps its access key, and the alternative is decided with you. Upgrading to the paid plan would end
the Free plan's no-charge guarantee; the credits would still apply.

1. Open **IAM Roles Anywhere** → **Create a trust anchor**.
2. Name: `warden-operator`.
3. CA source: **External certificate bundle**. Paste the whole content of
   `%USERPROFILE%\.warden\roles-anywhere\ca.pem`: open it in Notepad, **Ctrl+A**, **Ctrl+C**.
4. Leave the notification settings at their defaults (they warn 45 days before the certificate
   expires).
5. Tags: `Project` = `warden`, `Environment` = `ops`.
6. **Create a trust anchor**.
7. Open it, copy its **ARN**, and send it to Claude. The ARN contains the account number; that is
   fine in chat, and it never goes into the repository.

Claude then writes the role's trust policy to `C:\work\warden\iam\operator\trust.local.json`. It
pins that exact anchor and the laptop certificate's name (CN and O). The file is never committed.

**B2. The permissions policy.**
1. IAM → **Policies** → **Create policy** → **JSON**.
2. Paste
   [`iam/operator/policy.json`](https://github.com/veerarakesh56/warden/blob/main/iam/operator/policy.json)
   (Raw → Ctrl+A → Ctrl+C).
3. **Next** → name `WardenOpsOperator` → tags `Project` = `warden`, `Environment` = `ops` →
   **Create policy**.

**B3. The role.**
1. IAM → **Roles** → **Create role** → **Custom trust policy**.
2. Paste the local file `C:\work\warden\iam\operator\trust.local.json` (open it in Notepad) →
   **Next**.
3. Tick `WardenOpsOperator` → **Next**.
4. Name `warden-ops-operator`. Maximum session duration stays at **1 hour**.
5. Tags `Project` = `warden`, `Environment` = `ops` → **Create role**.

There is no permissions boundary on this role. Its only non-read permission is assuming the
read-only sweep role, so a boundary would limit nothing. The test keeps it that way.

**B4. The profile** (region Hyderabad).
1. IAM Roles Anywhere → **Create a profile**.
2. Name `warden-ops-operator`, role `warden-ops-operator`.
3. No session policies. Session duration stays at the default (1 hour).
4. Tags `Project` = `warden`, `Environment` = `ops` → **Create a profile**.
5. Open it, copy its **ARN**, and send it to Claude. The signing helper needs the profile ARN as
   well as the anchor ARN.

Claude then:
1. Adds a named profile `warden` to `%USERPROFILE%\.aws\config` that signs in with the
   certificate. It does not use `default`, because `default` still reads the old key from the
   credentials file, which would silently win.
2. Proves the new identity: `aws sts get-caller-identity --profile warden` must show
   `assumed-role/warden-ops-operator/...`.
3. Reads, with the new identity only (read-only, no model is called):
   - the Free-plan end date and credits left;
   - whether Claude Opus 5.5, Fable 5.1 and Sonnet 5 are available to this account through the
     global profile. This is the check for whether the Free plan allows these Marketplace-billed
     models. If it does not, decision D12 goes back to you.
   - whether Anthropic's one-time use-case form has been submitted. Submitting it is your decision
     in window W-B, not now.
   - the Bedrock quotas for the Opus 5.5 global profile.
4. Records all of this under "W0-now results" below and checks the roadmap calendar against both
   end dates.

**C. The sweep role's trust** (only after Claude confirms B works).
1. IAM → **Roles** → `warden-pg-sweep` → **Trust relationships** → **Edit trust policy**.
2. Paste the local file `C:\work\warden\terraform\proving-ground\sweep-role-trust.local.json`.
   It trusts the new role instead of the old user, and allows `sts:SetSourceIdentity`: a Roles
   Anywhere session always carries one, and without that permission the chained AssumeRole fails.
3. **Update policy**. Claude then runs the all-region sweep through the new role.

**D. The Slack webhook into Secrets Manager** (region Hyderabad).
1. Secrets Manager → **Store a new secret** → **Other type of secret** → **Plaintext** tab.
2. Delete the `{}` and paste the one line from `%USERPROFILE%\.warden\slack-webhook` (Notepad).
3. Encryption key `aws/secretsmanager` → **Next**.
4. Name `warden/ops/slack-webhook`. Tags `Project` = `warden`, `Environment` = `ops` → **Next**.
5. Leave rotation **off**. A webhook cannot rotate itself, and the Slack bot token replaces it
   later (G5).
6. **Next** → **Store**.

Claude compares the stored value with the file by hash, never printing either.

**E. Retire the old key.**
1. When Claude says steps B-D all work through the role: IAM → **Users** → `warden-operator` →
   **Security credentials** → the access key → **Actions** → **Deactivate**.
2. Claude then:
   - proves the old key is refused;
   - moves `%USERPROFILE%\.aws\credentials` aside, so nothing can fall back to it;
   - makes the certificate profile the default;
   - runs the checks again.
3. Two days later, if nothing broke:
   1. Delete that access key.
   2. Delete the user `warden-operator`.
   3. Delete the policies `WardenProvingGroundOperator`, `WardenProvingGroundOperatorRdsEks` (if it
      exists) and `WardenFullstackOperator`, each only if its **Entities attached** tab is empty.
   4. Keep `WardenOperatorGuardrails` and `WardenProvingGroundBoundary` until Claude says otherwise.
4. Claude then deletes the plaintext files:
   - the moved credentials file;
   - `%USERPROFILE%\.warden\slack-webhook`;
   - `%USERPROFILE%\.warden\fs-secrets.tfvars` (it holds no secret, only comments);
   - `terraform\fullstack\terraform.tfvars` (your IP and budget email; that stack reads them from
     Parameter Store now);
   - `%APPDATA%\temporalio\temporal.toml` and `temporal.toml.bak-before-cloud-setup` next to it.
     They hold the Temporal trial API key, which expired on 2026-09-29. Claude deletes the files
     without opening them. WARDEN's own Temporal key comes later, from Secrets Manager.

   `terraform\proving-ground\terraform.tfvars` STAYS: the proving ground still reads your IP and
   budget email from it, and deleting it would break its next plan. It holds no secret and git
   ignores it.

**F. One date to read.** In the Temporal Cloud web UI (cloud.temporal.io), under Settings /
Billing or Plan, read when the trial ends and the credits left, and tell Claude.

**G. If the laptop is lost or compromised (keep for later).** IAM Roles Anywhere → trust anchor
`warden-operator` → **Disable**. No new credentials can be issued from then on; any issued earlier
expire within an hour. No certificate revocation list exists, because the CA key was thrown away,
so disabling the anchor is the switch.

**Renewal (calendar).** The laptop certificate expires **2027-09-28 13:54 UTC / 19:24 IST**.
AWS's notification warns 45 days before. To renew:
1. Claude runs `python scripts/roles_anywhere_cert.py issue`.
2. You replace the trust anchor's certificate bundle with the new `ca.pem`. It is the same anchor
   and the same ARN, so there are no trust policy changes.
3. Claude removes the old certificate. Until then the helper picks the newer one, because the
   profile's `credential_process` passes `--use-latest-expiring-certificate`. Claude writes it that
   way in step E2; the flag was checked in `aws_signing_helper credential-process --help` 1.8.5.

**Undo, if ever needed:**
- A: user → **Add permissions** → attach `WardenProvingGroundOperator` again.
- B: delete the profile, the role, the policy and the trust anchor.
- C: paste the previous trust (it named `user/warden-operator`).
- E1: reactivate the key, and Claude restores the credentials file. There is no undo after E3
  step 1, which is why E waits two days.

**W0-now results** (Claude fills this in; nothing is recorded yet):

| Fact | Value | Read on (UTC / IST) |
|---|---|---|
| AWS Free plan ends | - | - |
| AWS credits left | - | - |
| Opus 5.5 / Fable 5.1 / Sonnet 5 available to this account | - | - |
| Anthropic use-case form submitted | - | - |
| Opus 5.5 global-profile quotas | - | - |
| Temporal Cloud trial ends / credits left | - | - |

---

## LATER (cloud test window): bring up one environment - `dev` shown

What this gives: GitHub Actions can deploy the `dev` stack with short-lived credentials through
OIDC (no key stored anywhere). The boundary (`iam/dev/boundary.json`) is meant to keep it away from
every other environment's resources. **⚠ Not yet (audit 2026-09-28):** tag-based isolation has gaps
(e.g. `rds-db:connect` carries no tag condition). **Do not do this section until release 0.10.1**,
which fixes the templates and replaces these steps. Repeat for another environment by replacing
`dev` everywhere.

Costs: IAM, OIDC, Parameter Store (Standard tier) and GitHub Environments are free. The S3 state
bucket holds kilobytes, so it is effectively free.

**1. GitHub's identity provider (once per account, skip if it already exists).**
1. IAM, left menu: **Identity providers**. If `token.actions.githubusercontent.com` is listed, open
   it and check that the audience `sts.amazonaws.com` is there. Then skip to step 2.
2. Otherwise: **Add provider**. Choose **OpenID Connect**. Provider URL
   `https://token.actions.githubusercontent.com`. Audience `sts.amazonaws.com`. **Add provider**.

**2. The environment's boundary and deploy policy.** Create each from its complete file, the same way
you created the guardrails:
IAM → **Policies** → **Create policy** → **JSON** → **Ctrl+A**, **Delete**, paste → **Next** →
name → **Create policy**.

| Name | File (complete) |
|---|---|
| `WardenEnvBoundary-dev` | [`iam/dev/boundary.json`](https://github.com/veerarakesh56/warden/blob/main/iam/dev/boundary.json) |
| `WardenEnvDeploy-dev` | [`iam/dev/deploy.json`](https://github.com/veerarakesh56/warden/blob/main/iam/dev/deploy.json) |

**3. The deploy role.**
1. IAM → **Roles** → **Create role** → **Custom trust policy**.
2. Paste the complete trust file. Take it from **this computer, not GitHub**: open
   `C:\work\warden\iam\dev\trust.local.json` in your editor. It already contains your account
   number; that file is never committed. (Claude re-creates it with
   `python scripts/render_env_iam.py --account`.) It trusts exactly one thing: this repository's
   GitHub environment `dev`. **Next**.
3. Tick `WardenEnvDeploy-dev` and `WardenOperatorGuardrails`.
4. Expand **Set permissions boundary**. Choose **Use a permissions boundary to control the maximum
   role permissions**, then select `WardenEnvBoundary-dev`. **Next**.
5. Role name `warden-dev-deploy`. Add tags `Project` = `warden` and `Environment` = `dev`.
   **Create role**.
6. Open the role and check that *Permissions boundary* shows `WardenEnvBoundary-dev`. Copy its
   **ARN** for step 6.

**4. The environment's parameters.** Systems Manager → **Parameter Store** → **Create parameter**,
three times.
- Every time: Tier **Standard**. ⚠ **Not Advanced, which is paid.**
- For SecureString: KMS key source **My current account**, with key `alias/aws/ssm`.
- Tags every time: `Project` = `warden`, `Environment` = `dev`.

| Name | Type | Value |
|---|---|---|
| `/warden/dev/tf/my_ip_cidr` | String | your public IP followed by `/32` (open https://checkip.amazonaws.com) |
| `/warden/dev/tf/budget_email` | SecureString | where budget alarms go |
| `/warden/dev/env/WARDEN_SLACK_WEBHOOK` | SecureString | the Slack webhook URL |

**5. The state bucket.** S3 → **Create bucket**:
- General purpose, name `warden-dev-tfstate-` followed by 6 random lowercase letters and digits,
  region Asia Pacific (Hyderabad).
- ACLs disabled; **Block all public access** ticked (the default).
- **Bucket Versioning: Enable**. Default encryption SSE-S3.
- Tags `Project` = `warden`, `Environment` = `dev`.
- **Create bucket**. Copy its name for step 6.

**6. GitHub.** In the repository → **Settings** → **Environments** → **New environment** → name
`dev` → **Configure environment**.
- Under **Environment variables**, add:
  - `AWS_ROLE_ARN` = the ARN from step 3
  - `TF_STATE_BUCKET` = the bucket name from step 5
- For `pre-prod`, `qa-prod` and `prod` only:
  - tick **Required reviewers** and add yourself;
  - leave "Prevent self-review" unticked;
  - **Deployment branches**: **Selected branches**, rule `main`.

**7. Tell Claude "dev is up".** Claude runs the Terraform **plan** for `dev` from GitHub Actions.
A negative check (another environment's role must be refused) is planned for window W1. It does
not exist yet (audit 2026-09-28).

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

## Done 2026-09-28

4. The read-only sweep role `warden-pg-sweep`:
   - `WardenFullstackOperator` was updated so the operator may assume it.
   - The role has one policy, `WardenSweepReadOnly`, from
     [`sweep-role-policy.json`](https://github.com/veerarakesh56/warden/blob/main/terraform/proving-ground/sweep-role-policy.json).
   - Its trust policy is the local file (it contains the account number).
   - Verified the same day: it sees all 18 regions. Creating a bucket or a security group, reading a
     parameter's value and listing IAM users are all denied.
   - Claude uses it through `python scripts/account_sweep.py`.

**Undo, if ever needed:**
- For 1: the policy's **Policy versions** tab → previous version → **Set as default**.
- For 2: user → **Permissions** → remove `WardenOperatorGuardrails`.
- For 3: **Analyzer settings** → tick the analyzer → **Delete**.
- For 4: delete the role `warden-pg-sweep`, then the policy `WardenSweepReadOnly`, then set the
  previous version of `WardenFullstackOperator` as default.
