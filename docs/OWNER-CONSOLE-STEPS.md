# Owner steps, AWS console only (2026-09-27)

Three changes only you can make. The operator (`warden-operator`) is blocked from all of them by
design. Everything is done in the AWS web console, with no CLI. Each policy is a **complete file**:
copy all of it and paste it over everything in the console's JSON box.

**Sign in as your admin identity**: the admin IAM user or SSO role you used to create the operator,
not `warden-operator`. Avoid the root user.

| Step | What it does | Cost |
|---|---|---|
| 1 | Lets WARDEN's operator delete the two leftover network interfaces, so the rest of the old stack can be destroyed | free |
| 2 | Deny-only guardrails: stops a hijacked agent from opening the account up | free |
| 3 | IAM Access Analyzer, external access: finds anything reachable from outside the account | free (**only** this analyzer type, see step 3) |

Getting a file's full text: open it on GitHub (links below), press **Raw**, then **Ctrl+A** and
**Ctrl+C**. Or open it from your local checkout in any editor.

---

## Step 1: update `WardenFullstackOperator`

File (complete): [`terraform/fullstack/operator-policy-fullstack.json`](https://github.com/veerarakesh56/warden/blob/main/terraform/fullstack/operator-policy-fullstack.json)

The only change from the version already in AWS is one action, `ec2:DeleteNetworkInterface`, in the
first EC2 statement. That statement is locked to region ap-south-2. AWS refuses to delete a network
interface that is still attached, so only detached leftovers can go. The file is 6,026 of IAM's
6,144 characters, and AWS's own policy validator reports 0 errors and 0 warnings.

1. Console search bar: type **IAM** and open it.
2. Left menu: **Policies**. Search box: `WardenFullstackOperator`. Click its name.
3. **Edit** (top right). Choose the **JSON** tab.
4. Click inside the editor, **Ctrl+A**, **Delete**. Paste the whole file (**Ctrl+V**).
5. The editor should show no red errors. **Next**. **Save changes**.
   - If it says the policy already has 5 versions: open the **Policy versions** tab, tick the
     *oldest* version that is **not** marked *Default*, **Delete**, then repeat 3 to 5.
6. Check: the **Policy versions** tab shows a new version marked **Default**.

## Step 2: create and attach `WardenOperatorGuardrails`

File (complete): [`terraform/proving-ground/operator-guardrails.json`](https://github.com/veerarakesh56/warden/blob/main/terraform/proving-ground/operator-guardrails.json)

Every statement in it is a **Deny**; it grants nothing. It stops the operator from:

- rewriting who may assume a role;
- turning off the account's S3 public-access block, or changing bucket or object ACLs;
- creating a Lambda URL with no authentication, or letting everyone invoke a Lambda;
- sharing snapshots, AMIs, secrets, ECR repositories or log data outside the account;
- stopping CloudTrail or IAM Access Analyzer.

The operator's boundary forbids it from detaching a user policy, so it cannot remove this one.
AWS's validator reports 0 errors. Its one warning is expected: the Lambda rule matches the literal
principal `*`.

**2a. Create the policy**

1. IAM, left menu: **Policies**, then **Create policy**.
2. **JSON** tab. **Ctrl+A**, **Delete**, paste the whole file. **Next**.
3. Policy name: `WardenOperatorGuardrails`.
   Description: `Deny-only guardrails for warden-operator (docs/OWNER-CONSOLE-STEPS.md)`.
4. **Create policy**.

**2b. Attach it to the operator**

1. IAM, left menu: **Users**. Click `warden-operator`.
2. **Permissions** tab, **Add permissions**, then **Add permissions** again.
3. Choose **Attach policies directly**. Search `WardenOperatorGuardrails`. Tick it. **Next**.
4. **Add permissions**.
5. Check: the Permissions tab lists `WardenOperatorGuardrails`, with type *Customer managed*.

## Step 3: IAM Access Analyzer, external access (free)

This finds what no deny can prevent. Example: a new role that trusts another AWS account. IAM cannot
inspect a trust policy when a role is created, so this can only be found after the fact.

⚠ **Choose only "External access".** The other analyzer types are **PAID**: *unused access* is charged
per IAM user or role per month, and *internal access* per resource monitored. External access
analysis has no charge.

1. **Top-right region selector: choose Asia Pacific (Hyderabad), ap-south-2.** Analyzers are
   per region, and every WARDEN resource is in this one.
2. IAM, left menu: **Access analyzer** (under *Access reports*). Then **Analyzer settings**, then
   **Create analyzer**.
3. **Analysis**: choose **Resource analysis - External access**.
4. Name: `warden-external-access`. **Zone of trust**: *Current account*.
5. **Create analyzer**.
   - **"Service access" (AWS Organizations trusted access): leave it alone.** It only matters for
     watching several accounts through AWS Organizations; this is one account.
   - AWS may create a role named `AWSServiceRoleForAccessAnalyzer` on its own. That is expected and
     free; let it.
6. After a few minutes: **Access analyzer**, then **Resource analysis**, **Active** findings.
   - **No findings** is the goal.
   - Any finding means something is reachable from outside this account. Do not archive it;
     tell Claude which resource it names.
   - Look again after every live AWS test window.

## Step 4: tell Claude "done"

Claude then, as `warden-operator`:
1. Deletes the two detached network interfaces left by Lambda (`eni-0c3fb858ed9546af5`,
   `eni-089d8ceacae288168`).
2. Re-runs `terraform destroy` for the old full stack. That removes the VPC, 2 subnets and 1
   security group, all $0 today but still listed.
3. Runs the no-billing sweep, and checks that the Access Analyzer shows no active findings.

## Undo (if ever needed)

- Step 1: in the policy's **Policy versions** tab, tick the previous version and **Set as default**.
- Step 2: `warden-operator`, **Permissions**, tick `WardenOperatorGuardrails`, **Remove**. Then
  delete the policy.
- Step 3: **Analyzer settings**, tick the analyzer, **Delete**.
