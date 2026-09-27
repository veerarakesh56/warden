# Owner steps, AWS console only

Things only you can do. The operator (`warden-operator`) is blocked from all of them by design.
Everything is done in the AWS web console, with no CLI. Each policy is a **complete file**: open it on
GitHub, press **Raw**, **Ctrl+A**, **Ctrl+C**, and paste it over everything in the console's JSON box.

**Sign in as your admin identity** (the one you used to create `warden-operator`), not as the operator.
Avoid the root user.

---

## ▶ NOW: laptop sign-in without a stored key (Phase 1.5, step 2)

**Why.** This laptop holds a long-lived access key for `warden-operator`, the top risk the audit found.
It is replaced by **`aws login`**: you sign in through the browser (password + MFA), and the command
line gets short-lived credentials that renew every 15 minutes for up to 12 hours. Then the key is
switched off and deleted.

It costs nothing and you stay on the Free plan. (IAM Identity Center, the company-grade option, needs
AWS Organizations, which would move the account to the paid plan. See
[`PRODUCTION-ARCHITECTURE.md`](PRODUCTION-ARCHITECTURE.md).)

**1. Update the boundary.** File (complete):
[`terraform/proving-ground/operator-policy-boundary.json`](https://github.com/veerarakesh56/warden/blob/main/terraform/proving-ground/operator-policy-boundary.json)
- It adds the two browser sign-in actions and shortens some statement names.
- It is 5,985 of 6,144 characters, and AWS's own validator reports no errors.
- Steps:
  1. IAM → **Policies** → search `WardenProvingGroundBoundary` → click it → **Edit** → **JSON**.
  2. **Ctrl+A**, **Delete**, paste the whole file → **Next** → **Save changes**.
  3. If it says there are already 5 versions: open the **Policy versions** tab, tick the *oldest*
     version not marked *Default*, **Delete**, then repeat 1 and 2.

**2. Allow browser sign-in for the command line.**
1. IAM → **Users** → `warden-operator` → **Permissions** tab → **Add permissions** → **Add permissions**.
2. **Attach policies directly** → search `SignInLocalDevelopmentAccess` (type: *AWS managed*) → tick it → **Next** → **Add permissions**.

**3. Give the operator a console password.**
1. Same user → **Security credentials** tab → *Console sign-in* → **Enable console access**.
2. Choose **Custom password**, and make a strong one in a password manager.
3. ⚠ **Untick "Users must create a new password at next sign-in".** The boundary does not allow the
   operator to change its own password, so a forced change would lock it out.
4. **Apply**, and note the **console sign-in URL** shown.

**4. Add MFA to that sign-in.**
1. Same tab → *Multi-factor authentication (MFA)* → **Assign MFA device**.
2. Choose **Passkey or security key** (best) or **Authenticator app**, and follow the prompts.

**5. Tell Claude "sign-in steps done".** Claude then:
- writes the CLI profile in `~/.aws/config` (no secret goes in it);
- asks you to type `! aws login --profile warden` in the chat. Your browser opens; sign in as
  `warden-operator` with the password and MFA;
- checks that the CLI, Python and Terraform all work through the sign-in, and that the permissions
  boundary still holds.

**6. After Claude confirms the checks (not before):**
1. IAM → **Users** → `warden-operator` → **Security credentials** → *Access keys* → the key starting
   `AKIA` → **Actions** → **Deactivate**.
2. **Two days later**, if nothing broke: same place → **Actions** → **Delete** (type the key id to
   confirm). Claude then deletes the local `~/.aws/credentials` file.

**Undo:** re-activate the key in the same place. Its inactive state is kept until you delete it.

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
