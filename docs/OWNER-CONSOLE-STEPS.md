# Owner steps, AWS console only

Things only you can do. The operator (`warden-operator`) is blocked from all of them by design.
Everything is done in the AWS web console, with no CLI. Each policy is a **complete file**: open it on
GitHub, press **Raw**, **Ctrl+A**, **Ctrl+C**, and paste it over everything in the console's JSON box.

**Sign in as your admin identity** (the one you used to create `warden-operator`), not as the operator.
Avoid the root user.

---

## ▶ NOW: a read-only sweep role (about 5 minutes, free)

Why: the operator can list only some services, and only in ap-south-2. So "nothing is running" could
not be proven for every service in every region, nor could every resource's tags be checked. This
role can **only list** what exists in every region and read tags. It cannot change anything, read a
secret's value or open a file. Only `warden-operator` may use it. Claude runs
`python scripts/account_sweep.py` with it.

**1. Update `WardenFullstackOperator`** (lets the operator use the new role; nothing else changes).
IAM → **Policies** → `WardenFullstackOperator` → **Edit** → **JSON** → **Ctrl+A**, **Delete**, paste
[`terraform/fullstack/operator-policy-fullstack.json`](https://github.com/veerarakesh56/warden/blob/main/terraform/fullstack/operator-policy-fullstack.json)
→ **Next** → **Save changes**.

**2. Create the policy `WardenSweepReadOnly`.** IAM → **Policies** → **Create policy** → **JSON** →
**Ctrl+A**, **Delete**, paste
[`terraform/proving-ground/sweep-role-policy.json`](https://github.com/veerarakesh56/warden/blob/main/terraform/proving-ground/sweep-role-policy.json)
→ **Next** → name `WardenSweepReadOnly` → **Create policy**.

**3. Create the role `warden-pg-sweep`.**
1. IAM → **Roles** → **Create role** → **Custom trust policy**.
2. **Ctrl+A**, **Delete**, and paste the complete file from **this computer, not GitHub**: open
   `C:\work\warden\terraform\proving-ground\sweep-role-trust.local.json` in your editor. It contains
   your account number, so it is never committed. It trusts `warden-operator` only. **Next**.
3. Tick `WardenSweepReadOnly` (only this one). **Next**.
4. Role name `warden-pg-sweep`. Add the tag `Project` = `warden`. There is no `Environment` tag:
   the role serves the whole account, not one environment. **Create role**.

**4. Tell Claude "sweep role done".** Claude runs the sweep over every region and reports anything
that exists, anything with missing or wrong `Project` / `Environment` tags, and anything it still
could not see.

Undo: delete the role, then the policy, then set the previous version of `WardenFullstackOperator`
as default (**Policy versions** tab).

---

## Then nothing until the cloud test

Local work uses this machine's current credentials. The next console work is the section below,
**only when the real-world cloud test starts** - not before.

---

## LATER (cloud test window): bring up one environment - `dev` shown

What this gives: GitHub Actions can deploy **only** the `dev` stack. It gets short-lived credentials
through OIDC (no key stored anywhere), and it can never touch another environment's resources
(`iam/dev/boundary.json`). Repeat for another environment by replacing `dev` everywhere.

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
It also runs a negative check: another environment's role must be refused.

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
