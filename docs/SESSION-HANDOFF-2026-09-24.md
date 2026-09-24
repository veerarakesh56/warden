# Handoff — 2026-09-24

## Where things stand

| | |
|---|---|
| **Cost right now** | **nothing is billing.** 28 resources destroyed and `terraform state list` is empty. Checked directly, not inferred: EKS clusters 0, RDS instances 0, EC2 instances 0, NAT gateways 0, Elastic IPs 0, volumes 0, ENIs 0, non-default VPCs 0, log groups 0. The tagging index still lists 6 rows for a while: the subnet returns `InvalidSubnetID.NotFound`, and the task definitions are `INACTIVE` (free; AWS never fully deletes them). ⚠ The `$` budget alarm was destroyed with everything else and comes back on the next apply. |
| Wave 1 (ECS) | measured and published, unchanged. |
| Wave 2 (EKS) | **blocked** — see below. The cluster came up and was torn down again; the node group never created. |
| Wave 3 (RDS) | **built, dry-run green, not yet run live.** 6 scenarios, 7 ops (5 injectors, 2 reverts), 32 tests, every guard plant-verified. All three waves dry-run and score end to end, and a partial `--resume` of Wave 3 was tested. |

## ✅ Resolved 2026-09-24 — and the first fix was not enough on its own

The boundary edit below was applied from the console. It **still** failed: IAM's access
troubleshooter showed the request was evaluated against `role/AWSServiceRoleForAmazonEKSNodegroup`
- the ARN **without** its `aws-service-role/eks-nodegroup.amazonaws.com/` path, because the role
did not exist yet. `role/aws-service-role/*` cannot match that. Creating the service-linked role
first (`iam:CreateServiceLinkedRole`, already allowed by both policies, and something EKS does on
its own anyway) gave it a real, pathed ARN, and the same `GetRole` then succeeded. A role outside
the proving ground is still refused. The step is now a comment above the node group in `eks.tf`.

## ⛔ What was asked of your admin identity

Creating an EKS **managed node group** calls `iam:GetRole` on
`AWSServiceRoleForAmazonEKSNodegroup` to check whether that service-linked role exists. AWS's own
error is unambiguous:

```
InvalidRequestException: Failed to validate if SLR: AWSServiceRoleForAmazonEKSNodegroup
already exists due to missing permissions for 'iam:GetRole'
```

and, called directly:

```
not authorized to perform: iam:GetRole ... because no permissions boundary allows the action
```

The permissions boundary caps `iam:GetRole` to `warden-pg-*` roles. The boundary is the ceiling, so
raising it is not something the operator can do — `DenyTouchingThisBoundary` denies
`warden-operator` every write to the boundary, **which is the boundary working, not a bug**. The
whole point of a boundary is that the identity underneath it cannot widen it.

`terraform/proving-ground/operator-policy-boundary.json` already carries the fix in this repo
(`CeilingReadServiceLinkedRoles`: `iam:GetRole` on `arn:aws:iam::*:role/aws-service-role/*` — a
read of a role AWS itself owns, which grants nothing else). It needs to be pushed **with the admin
credentials that created the boundary**, not the operator's:

```bash
python scripts/apply_operator_policy.py \
    terraform/proving-ground/operator-policy-boundary.json WardenProvingGroundBoundary
```

Run as `warden-operator` it fails with AccessDenied and changes nothing, which is the correct
outcome. This machine has no admin profile (`aws configure list-profiles` shows only `default`,
which IS the operator), so the console is the easy route:

> IAM → Policies → `WardenProvingGroundBoundary` → Edit → JSON → add this statement → Save
> (if it says 5 versions exist, let it delete the oldest non-default one)
>
> ```json
> { "Sid": "CeilingReadServiceLinkedRoles", "Effect": "Allow",
>   "Action": "iam:GetRole", "Resource": "arn:aws:iam::*:role/aws-service-role/*" }
> ```

After that, `terraform apply` with `enable_eks=true` builds everything: ~7 minutes for the cluster,
~3 for the node.

### Why there is no way round this from inside the boundary - every route was checked

| Route to a worker node | Blocked by |
|---|---|
| Managed node group (what `eks.tf` uses) | `CreateNodegroup` calls `iam:GetRole` on the node-group service-linked role with the CALLER's credentials; the ceiling caps `GetRole` to `warden-pg-*` |
| Self-managed EC2 node | the ceiling denies `ec2:RunInstances` outright (`DenyTheComputeThatWouldMakeAStolenKeyWorthStealing`) - so a leaked operator key cannot launch compute. EKS launching nodes on the operator's behalf is the design's intended way round that, which is why it is a managed node group |
| Fargate profile | needs the `eks-fargate` service-linked role, which the ceiling's `CreateServiceLinkedRole` list does not include; and Fargate on EKS needs private subnets, i.e. a NAT gateway this proving ground deliberately does not pay for |

Widening the ceiling from inside it would make it not a ceiling - and "WARDEN's operator runs under
a boundary it cannot edit" is a claim this repo makes in public.

### Fixed while checking: the node would never have joined anyway

`eks.tf` had `endpoint_private_access = false` with `public_access_cidrs` locked to your IP. A node
reaches the API server from its OWN public IP, which the allow-list refuses, so the node group
would have failed with "instances failed to join the kubernetes cluster" after ~20 billed minutes.
Private access is now on (the VPC already has DNS hostnames enabled, which it needs); `terraform
plan` accepts it.

## What was done without you

- **Operator policy v9** (self-edit, no admin needed — the boundary already allowed all of it):
  - merged the two duplicate service-linked-role statements into one, and added the EKS node-group
    service name;
  - added `RdsForWave3` (create/delete/modify the instance and subnet group, scoped to
    `warden-pg-*`) and `RdsReadsThatTakeNoResource` (`rds:Describe*`, which Terraform's plan needs
    and which takes no resource ARN).
  - ⚠ **The policy is now 6065 of the 6144-character limit.** 79 characters left. A fourth wave
    needs a second managed policy, and attaching one is an admin action.
- **Wave 3 built end to end**: `scenarios/ops_db.py`, `scenarios/catalog/wave3-db.yaml`,
  runner wiring (`--target db`), `scripts/setup_proving_ground_db.py`, and three test files.
- **`teardown_sweep.py` now reports what EKS leaves behind** - ENIs, unattached Elastic IPs,
  available volumes, NAT gateways, security groups - none of which the ECS-shaped sweep looked at.
  It reports and never removes. The three that BILL (EIPs, NAT gateways, volumes) fail the sweep;
  the two that are free only get listed, or every account with a security group would be red forever.
- **README counts corrected**: 779 tests (was 690), 33 mutations caught (was 32).
- **Two Terraform bugs on the never-applied RDS path, found by running `terraform plan` (plan only,
  nothing created):**
  - ⛔ The database security-group rule's description said `operator's`. EC2 rejects apostrophes
    there, `terraform validate` does not notice, and **Wave 3's first apply would have failed on
    it.** Fixed, and `tests/test_terraform_descriptions.py` now checks every security-group
    description against EC2's own character set - watched fail with the apostrophe put back.
  - `variables.tf` and the precondition's error message both said the password is "generated per
    run by the harness and passed with -var". No code does that. Both now say what is true.
- **Also confirmed against the live account** before anyone spends money: Postgres 16 resolves to
  16.13, db.t4g.micro is orderable for it in ap-south-2, and the subnet group spans two AZs. The
  password precondition fails on a blank password and passes on a generated one.

## Before Wave 3 runs live

```bash
# Generated, never typed: it lands in no shell history and no file. You never need to know it -
# the db_dsn output carries it.
export TF_VAR_db_password="$(python -c 'import secrets; print(secrets.token_urlsafe(24))')"
terraform -chdir=terraform/proving-ground apply -var enable_rds=true
export WARDEN_BENCH_DB_DSN="$(terraform -chdir=terraform/proving-ground output -raw db_dsn)"
export WARDEN_BENCH_DB_SG="$(terraform -chdir=terraform/proving-ground output -raw db_security_group_id)"
python scripts/setup_proving_ground_db.py --apply     # ⛔ REQUIRED ONCE - see below
python -m scenarios.runner --wave 3 --only db-01-healthy-control --repeat 1
```

⛔ **The setup step is not optional and is not folded into the harness on purpose.** The injectors
refuse to touch a database unless it contains a `warden_proving_ground` table. That table is the
only thing standing between "open ~58 sessions and take an ACCESS EXCLUSIVE lock" and someone's real
Postgres. If the harness created the mark when it was missing, the guard would bless whatever
database it was handed - which is exactly the one you did not mean to point it at. So a human runs
`setup_proving_ground_db.py --apply` against a DSN they chose, and it refuses twice: once on the
DSN's text, once on the server's own `current_database()`.

⚠ The password lives in `TF_VAR_db_password` and in Terraform state (`terraform.tfstate`,
gitignored - checked). Never `-var db_password=...`: that puts it in shell history. The DSN reaches
the tool under test through the environment and nothing else: not the manifest, not the ground
truth, not an argv. There is a test for each of those three, and each one was watched fail when the
guard it covers was broken on purpose.

## Known, deliberate, and not fixed

- **A killed `mutation_check.py` leaves source mutated.** It restores on exit; it cannot restore if
  you kill it. If the suite is suddenly red for no reason, `git status src/` first.
- Wave 3 asks nothing about CPU, memory or IOPS. The database backend reads none of them and
  Performance Insights is disabled — a scenario about an undersized instance would be scoring the
  model for the tool's blindness.
- `deploys()` returns `[]` for every database engine, so `rollback_deploy` cannot be correct in
  Wave 3 and `deploys_nonempty` cannot hold. That absence is a published result, not a gap to hide.
