# The proving ground

A **throwaway** AWS environment that exists for one reason: to run WARDEN against real ECS, real
RDS and real EKS instead of recorded fixtures, and to leave an evidence bundle behind.

This is **not** the deployment module. That is `terraform/`, one directory up — a task definition
with a read-only role, meant for an account that already has a cluster and a VPC. This directory
*creates* the things under investigation, on purpose, so there is something real to investigate.

---

## ⛔ Cost — read this before you run anything

**RDS and EKS are OFF by default, and that is the single most effective cost control here** — more
than any instance-size choice. The dominant risk is not the hourly rate, it is **forgetting**: an
idle EKS control plane is billed at $0.10/hour whether or not anything runs on it, which is about
**$73 a month** for nothing. Wave 1 of the benchmark touches neither service.

| Configuration | What runs | Per hour | A 2-hour session |
|---|---|---|---|
| **Default** (`enable_rds=false`, `enable_eks=false`) | ECS/Fargate Spot, CloudWatch, VPC, IAM | **~$0.009** | **~$0.02** |
| `+ enable_rds` | adds `db.t4g.micro`, 20 GB | ~$0.030 | ~$0.06 |
| `+ enable_eks` | adds the control plane + 1 spot node | ~$0.119 | ~$0.24 |
| Everything on | | ~$0.140 | ~$0.28 |

Line by line, so the numbers can be checked rather than believed:

| Resource | Rate | Note |
|---|---|---|
| Fargate **Spot**, 2 tasks × (0.25 vCPU + 0.5 GB) | ~$0.0086/hr | Spot is ~70% off on-demand. Two tasks, so "1 of 2 running" is visible when one is killed |
| CloudWatch Logs | ~$0 | 1-day retention, a few MB |
| VPC, subnets, IGW, route table, security groups, IAM | **$0** | None of these are billed |
| **NAT Gateway** | **$0.045/hr + $0.045/GB** | ⭐ **Deliberately not created.** It would cost more than everything else here combined |
| RDS `db.t4g.micro` + 20 GB gp2 | ~$0.021/hr | **$0 on an account under 12 months old** — the free tier covers 750 hrs/month |
| EKS control plane | **$0.10/hr** | Charged whether or not anything runs on it. The expensive one |
| EKS node, 1 × `t3.small` **spot** + 20 GB | ~$0.010/hr | |

> The one deliberate deviation from how you would really run this: everything sits in **public
> subnets with public IPs**. That is not laziness — a private-subnet design needs a NAT Gateway, and
> a NAT Gateway is both the largest cost here and the most common source of a surprise AWS bill.
> Access is restricted to your own IP (`var.my_ip_cidr`) rather than left open, and the production
> module one directory up uses private subnets.

`terraform output estimated_hourly_usd` computes the figure from the switches you actually set, so
it cannot drift from this table.

### Four guards against the forgotten-environment bill

1. **RDS and EKS default to off.** Turn one on for the wave that needs it, and only then.
2. `terraform destroy` runs from an **EXIT trap** in `scripts/aws_proof.sh`, so it happens even if
   the run fails and even on Ctrl-C.
3. An **AWS Budget** at `var.budget_usd` (default $5) emails you at 60% / 90% of *forecast* and
   100% of actual. Forecast matters: by the time actual spend crosses $5, a forgotten cluster has
   already been up for two days. Budgets are free.
4. Every resource is tagged `Project = warden-proving-ground`, so anything a failed destroy left
   behind can be found:

   ```bash
   aws resourcegroupstaggingapi get-resources \
     --tag-filters Key=Project,Values=warden-proving-ground \
     --query 'ResourceTagMappingList[].ResourceARN'
   ```

   The harness runs exactly this after every destroy and writes the count to
   `teardown-remaining.txt`. **It should read `0`** — the destroy's own exit code is not trusted,
   because a destroy can report success and leave a node group behind.

---

## What it creates

| | Why the benchmark needs it |
|---|---|
| **VPC**, 2 public subnets in 2 AZs, IGW, route table | Two AZs because RDS subnet groups and EKS both require it |
| **ECS cluster + a service named `checkout`** on Fargate Spot | `WARDEN_BACKEND=aws` — `ecs:DescribeServices`, `ecs:DescribeTaskDefinition`, `cloudwatch:GetMetricData` |
| A **CloudWatch log group** | `logs:FilterLogEvents` |
| **Three** task definition revisions: healthy, an identical re-registration, and a deliberately OOM-ing one | So a real bad deploy — and a real *non*-deploy — can be staged rather than simulated. See the comment at the top of `ecs.tf`; the middle revision is not redundant |
| ⭐ A **reader role with exactly four permissions** | The harness **assumes** it before running WARDEN, so "read-only" is enforced by IAM during the benchmark instead of asserted about the source. See `iam.tf` |
| **RDS PostgreSQL** *(opt-in)* | `WARDEN_BACKEND=postgres` — RDS speaks the ordinary wire protocol |
| **EKS** cluster + 1 spot node *(opt-in)* | `WARDEN_BACKEND=k8s` — EKS *is* Kubernetes, so this proves the existing backend on managed EKS rather than k3d |
| An **AWS Budget** | See above |

## Prerequisites

```bash
aws --version                  # AWS CLI v2
terraform -version             # >= 1.5
kubectl version --client       # only if enable_eks
aws sts get-caller-identity    # must print YOUR account - this is the one that gets billed
```

## Run it

```bash
cd terraform/proving-ground
cp terraform.tfvars.example terraform.tfvars   # then edit: your IP, your email, your region
terraform init
terraform apply                                 # ~3 minutes with the default switches
```

Or let the harness do the whole thing, including teardown:

```bash
bash scripts/aws_proof.sh
```

Turning on what a later wave needs:

```bash
terraform apply -var enable_rds=true -var db_password="$(openssl rand -base64 24)"
terraform apply -var enable_eks=true    # ⛔ $0.10/hour from this moment, idle or not
```

## Tear it down

```bash
terraform destroy
```

Then **check it actually went**, because a destroy can partially fail — the query is in
`terraform output teardown_check`. An empty list is the only acceptable answer.

## ⛔ What must never be committed

`terraform.tfvars` holds your home IP and your email. `terraform.tfstate` holds **every `sensitive`
value in plaintext**, including the RDS master password — marking a variable `sensitive` hides it
from CLI output, not from state. Both are in `.gitignore`, and
`python scripts/check_publishable.py` fails the build if either is ever tracked.
