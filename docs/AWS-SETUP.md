# AWS setup — which identity, which permissions

Read this before running anything in `terraform/proving-ground/`. It answers one question: **what do
I create in AWS, and with what permissions?**

---

## There are TWO identities, and you only create one of them

| | Who creates it | What it can do | Why it exists |
|---|---|---|---|
| **The operator** | **You**, by hand, once | Create and destroy the proving ground; inject faults into it | Terraform and the fault injector run as this |
| **The reader** (`warden-pg-*-reader`) | **Terraform**, every apply | **Four read actions and nothing else** | ⭐ WARDEN runs as this, so "read-only" is enforced by IAM during a run rather than asserted about the source code |

⛔ **Do not create the reader role by hand.** `terraform/proving-ground/iam.tf` creates it, and
`tests/test_aws_backend.py` asserts its four actions are exactly the four API calls
`src/warden/aws_backend.py` makes — in *both* directions, so it cannot drift from the code. A
hand-made copy would drift on the first change and nothing would notice.

---

## The recommendation, in order of preference

### 1. Best: a separate AWS account used for nothing else

If you can, create a **new AWS account** (free; AWS Organizations makes a second account a few
clicks) and do this work there. Then the blast radius of any mistake — mine, yours, or the fault
injector's — is an account containing nothing you care about, and the permissions question stops
being difficult.

In that account, `AdministratorAccess` on a non-root user is a *reasonable* choice, and I would
rather tell you that than pretend a hand-crafted policy is meaningfully safer in an empty account.

### 2. Acceptable: your existing account, with the scoped policy in this directory

If it is your only account, use the policy files here. They are genuinely scoped — region-limited,
IAM limited to roles named `warden-pg-*`, `PassRole` limited by target service, and explicit `Deny`
statements over identity and data-store destruction.

⚠ **Be honest about what that does and does not buy you.** Most AWS `Create*` calls (`ec2:CreateVpc`,
`eks:CreateCluster`) do not support resource-level ARNs, so those statements are `"Resource": "*"`
with a region condition. This identity can still create networking and compute in that region. It
cannot touch your IAM users, your access keys, your buckets' contents, or your existing databases.

### 3. Never: the root user

Root should have MFA, a long password you do not use anywhere else, and no access keys at all. If
your root user has access keys, delete them — that is worth doing today regardless of this project.

---

## Do this

### Step 1 — the operator identity

**Preferred: IAM Identity Center (SSO), not an IAM user with access keys.** It issues *temporary*
credentials, so there is no long-lived secret on your laptop to leak. The AWS Agent Toolkit's
`aws login` uses this browser flow.

If you use an IAM user instead: **enable MFA on it**, and treat its access key as a real secret —
`scripts/check_publishable.py` will fail the build if one is ever committed, but the better answer is
for it never to exist.

### Step 2 — attach the policy

```bash
# Wave 1 (ECS + CloudWatch only). This is all you need to start.
aws iam create-policy \
  --policy-name WardenProvingGroundOperator \
  --policy-document file://terraform/proving-ground/operator-policy.json

# Later, only when you get to Wave 2 (EKS) or Wave 3 (RDS):
aws iam create-policy \
  --policy-name WardenProvingGroundOperatorRdsEks \
  --policy-document file://terraform/proving-ground/operator-policy-rds-eks.json
```

Then attach whichever you created to your user, your group, or your Identity Center permission set.

⚠ **Two things to change if you edit the defaults:**

- The policies hard-code **`ap-south-2`** (Hyderabad) in every `aws:RequestedRegion` condition. If you set a
  different `region` in `terraform.tfvars`, change it in the policy files too or every call is denied.
- IAM statements are scoped to `role/warden-pg-*`, which matches the default `var.name = "warden-pg"`
  plus Terraform's random suffix. If you change `var.name`, change the policy.

### Step 2b — the ECS service-linked role, once per account

⛔ **An AWS account that has never used ECS has no `AWSServiceRoleForECS`, and Terraform will not
create it for you.** The apply fails on `PutClusterCapacityProviders` with:

```
InvalidParameterException: Unable to assume the service linked role.
Please verify that the ECS service linked role exists.
```

which does not mention IAM at all. Granting `iam:CreateServiceLinkedRole` is necessary and *not*
sufficient — the permission allows the call, but something still has to make it:

```bash
aws iam create-service-linked-role --aws-service-name ecs.amazonaws.com
```

Already exists? It returns `InvalidInput ... has been taken`, which is success.

⭐ **This is deliberately not a Terraform resource.** `AWSServiceRoleForECS` is account-wide, and
anything else in the account using ECS depends on it — a `terraform destroy` of this proving ground
must not be able to delete it. One-time account bootstrap, not managed infrastructure.

### Step 3 — an account-level budget, not just the Terraform one

The Terraform creates a `$5` budget, but it only exists **while the proving ground exists**. Create a
standing one in the console (**Billing → Budgets**) for the whole account, alarming on **forecast**
as well as actual. Forecast matters: by the time actual spend crosses a threshold, a forgotten EKS
control plane has already been running for two days.

### Step 4 — verify before you apply

```bash
aws sts get-caller-identity     # must print YOUR account. This is the one that gets billed.
```

Then:

```bash
cd terraform/proving-ground
cp terraform.tfvars.example terraform.tfvars
# set: region, your public IP as a /32 (curl -s https://checkip.amazonaws.com), budget email
terraform init
terraform plan                  # read it. It should create ~15 resources and no RDS, no EKS.
```

⛔ `terraform.tfvars` and `terraform.tfstate` are gitignored, and `check_publishable.py` fails the
build if either is ever tracked. **tfstate holds every `sensitive` value in plaintext** — marking a
variable `sensitive` hides it from CLI output, not from state.

---

## What a real `terraform apply` turned out to need

The Wave 1 block **has** now been run against a real account. It failed twice, and both were
permissions the policy did not grant. Recorded here rather than quietly patched, because "derived by
reading the `.tf` files" was never the same thing as "tested", and this is what the difference cost:

| Missing | Symptom |
|---|---|
| `budgets:TagResource` | `AccessDeniedException ... not authorized to perform: budgets:TagResource`. The budget resource carries tags, and tagging is a separate action from `ModifyBudget` |
| `iam:CreateServiceLinkedRole` for `ecs.amazonaws.com` | `InvalidParameterException: Unable to assume the service linked role`. ⭐ **An account that has never used ECS has no `AWSServiceRoleForECS`.** Nothing in the Terraform mentions it — AWS creates it on your behalf, and only if you may |

⭐ The second one is the interesting failure: a permission an experienced reader would not think to
grant, because the resource needing it does not appear anywhere in the configuration. It is scoped
with an `iam:AWSServiceName` condition so it can create that one service-linked role and no other.

⚠ **The RDS and EKS blocks are still untested** and were derived the same way. **The EKS block is
the least certain part** — managed node groups are the one place where AWS does the most work on
your behalf, and the required caller permissions are easy to under-specify. Expect it to need at
least one round of exactly the above.

⭐ Before pasting any policy, run `python scripts/check_iam_actions.py`. It checks every action
against AWS's own published list — it would have caught `budgets:DescribeBudget`, which was in this
file and does not exist. It cannot tell you an action is *missing*; only an apply does that.

If an apply fails with `AccessDenied`:

1. The error names the exact action. **Add that action to the policy.**
2. ⛔ **Do not fall back to `AdministratorAccess` to make it work**, and if you do as a one-off to
   get unblocked, take it off again afterwards and record which action was missing.
3. Send me the error and I will correct the policy file — a policy that needed widening is a bug in
   this document, and it should be fixed here rather than worked around on your machine.

## What the reader role can do, for comparison

The whole point of the second identity:

```
cloudwatch:GetMetricData   ecs:DescribeServices   ecs:DescribeTaskDefinition   logs:FilterLogEvents
```

Four actions. No writes of any kind. WARDEN runs under this and nothing else, so a bug in its code
cannot mutate anything — which is a different and much stronger claim than "the policy engine would
have stopped it."
