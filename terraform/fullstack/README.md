# Wave 4 - the full stack (infrastructure)

The AWS side of `docs/WAVE4-FULLSTACK.md` section 2: VPC (+ one NAT gateway), ElastiCache Redis,
DynamoDB, SQS/SNS, six Lambdas, API Gateway, ALB + ECS Fargate, EKS, Secrets Manager, EventBridge
and the CloudWatch alarms that are the alert source - and, through `aurora_express.py` in this
directory, Aurora PostgreSQL Serverless v2. Everything is named `warden-pg-fs-*` and tagged
`Project=warden-fullstack`.

⛔ **The account is on the AWS Free plan (2026-09-26, docs/WAVE4-FULLSTACK.md section 9).** It
creates Aurora only in EXPRESS configuration, which the Terraform provider cannot do, so
`aurora_express.py create` makes the cluster after `terraform apply` and `aurora_express.py destroy`
removes it before `terraform destroy`. Express configuration has no VPC (the Aurora internet access
gateway, 5432) and IAM database authentication only: **there is no database password anywhere**.
The Free plan also admits only Free Tier eligible instance types: the EKS node is m7i-flex.large.

**Three independent pipelines.** This directory is INFRA only. It never builds or deploys
application code:

| pipeline | what | how | reads |
|---|---|---|---|
| infra | this directory | `terraform apply` locally, or `.github/workflows/infra.yml` (dispatch) | - |
| apps | Lambdas, container image, `k8s/fullstack` | `scripts/deploy_fullstack_apps.py`, or `.github/workflows/apps.yml` (dispatch) | `stack.json` |
| WARDEN CI | the tool | `.github/workflows/ci.yml` | - |

Lambdas are created from a placeholder zip, ECS from a placeholder container that answers 200 on
every path; every code field is in `ignore_changes`, so a re-apply never rolls the apps back.
Kubernetes objects are not in terraform at all.

## ⛔ Cost - about USD 0.50/hour, USD 12/day

Estimates for ap-south-2 using published ap-south-1 / us-east-1 list prices (Hyderabad prices differ
slightly), no free tier, idle load from the traffic Lambda. The budget alarm is the real guard.

| resource | per hour | note |
|---|---|---|
| Aurora Serverless v2, 2 instances at the 0.5 ACU floor | ~0.13 | does not scale to zero |
| EKS control plane | 0.10 | standard support pinned; extended support would be 0.60 |
| EKS node, 1 x m7i-flex.large on-demand + 20 GB | ~0.05-0.1 | Free Tier eligible (the Free plan's condition), not free for these hours |
| NAT gateway (one, public[0]) + data processed | ~0.06 | the in-VPC Lambdas' way to Aurora's internet gateway |
| Public IPv4 addresses (2 ECS tasks, 1 node, 2 ALB, 1 NAT) | ~0.03 | 0.005 each |
| ElastiCache, 2 x cache.t4g.micro | ~0.035 | |
| ALB + minimal LCU | ~0.03 | |
| Fargate, 2 x (0.25 vCPU, 0.5 GB) on-demand | ~0.025 | not Spot, on purpose |
| Interface endpoints (Secrets Manager, SQS), one subnet each | ~0.022 | |
| Container Insights (enhanced, one node) | ~0.01-0.03 | per observation |
| DynamoDB 5 RCU / 5 WCU, 20 alarms, 1 secret, Lambda/SQS/SNS/API calls | ~0.015 | |
| **total** | **~0.50** | |

**Budget:** this stack carries its own alarm, `warden-pg-fs-guard` (USD 50 a month by default,
`budget_usd`), emailing `budget_email` from your gitignored terraform.tfvars on forecast 60%/90% and
actual 50%/100%. The proving ground's budget was destroyed with it.
USD 50 is about four days of this stack left running. Destroy it when a run ends.

## Before the first apply (owner, admin credentials)

1. **Raise the ceiling.** Push the updated boundary (the operator cannot, by design):

       python scripts/apply_operator_policy.py \
           terraform/proving-ground/operator-policy-boundary.json WardenProvingGroundBoundary

   It adds scoped allows for DynamoDB, SNS, Secrets Manager, ElastiCache and API Gateway on
   `warden-pg-fs-*`, KMS only through Secrets Manager and RDS, the ElastiCache service-linked role,
   `rds-db:connect` (2026-09-26: without it in the ceiling no IAM database login works, because
   every `warden-pg-fs-*` role carries this boundary), and narrows the
   DeleteSecret/PutSecretValue/DeleteTable/DeleteDBCluster deny so it excludes `warden-pg-fs-*`
   (and still denies everything else).
2. **Grant the operator.** Create (or, after a change, add a version of) the managed policy
   `WardenFullstackOperator` from `operator-policy-fullstack.json` (6.0k of the 6,144-char limit)
   and attach it to the operator user (and to the CI role, below). The operator cannot do this
   itself: the boundary denies `iam:CreatePolicy` and `iam:AttachUserPolicy`, and allows it to edit
   only its own `WardenProvingGroundOperator`. 2026-09-26 added the NAT gateway and Elastic IP
   actions and passing roles to `pods.eks.amazonaws.com` (EKS Pod Identity).
3. **The operator's own policy** (the operator applies it itself):

       python scripts/apply_operator_policy.py \
           terraform/proving-ground/operator-policy.json WardenProvingGroundOperator

   2026-09-26 added `AuroraIamLoginAsPostgres` (`rds-db:connect` on `dbuser:*/postgres`): the
   master-user login `bootstrap-db` and the harness's admin connection sign with the operator's own
   credentials. 6,136 of 6,144 characters.
4. **Service-linked roles** on a fresh account (the Wave 2 lesson: the calls that need them check
   a path-less ARN the boundary does not match):

       aws iam create-service-linked-role --aws-service-name eks-nodegroup.amazonaws.com
       aws iam create-service-linked-role --aws-service-name elasticache.amazonaws.com

5. **CI only:** the OIDC role `warden-pg-fs-ci`, the state bucket `warden-pg-fs-tfstate-*` and the
   repository variables - the list is at the top of `.github/workflows/infra.yml`. No AWS keys are
   stored anywhere.

## Apply (the operator)

    cp terraform.tfvars.example terraform.tfvars    # set my_ip_cidr
    terraform init && terraform apply
    mkdir -p ~/warden-fullstack-build
    terraform output -json | python -c "import json,sys; print(json.dumps({k: v for k, v in json.load(sys.stdin).items() if not v['sensitive']}, indent=1))" > ~/warden-fullstack-build/stack.json
    python aurora_express.py create     # Aurora (express): cluster, 0.5-2 ACU, reader; merges its keys into stack.json

`aurora_express.py create` takes several minutes (the reader instance), writes the endpoints into
the metadata secret `warden-pg-fs-db-app`, and adds `aurora_cluster`, `aurora_writer_endpoint`,
`aurora_reader_endpoint`, `aurora_instance_endpoints`, `aurora_writer_instance` (express names the
writer itself), `db_name` and `db_master_username` to stack.json. Run it again after any later
`terraform output` rewrite of stack.json: on an existing cluster it only refreshes those records.
`python aurora_express.py status` shows what exists.

`stack.json` carries no sensitive output and no password (none exists). It does carry ARNs with the
account id: it lives outside the repo and is never published.

Then the apps pipeline:

    python scripts/deploy_fullstack_apps.py build
    python scripts/deploy_fullstack_apps.py bootstrap-db     # as postgres, IAM token from YOUR credentials
    python scripts/deploy_fullstack_apps.py deploy all

`deploy ecs` writes the revision it registered into stack.json as `ecs_baseline_task_definition`
(the revision the harness reverts ECS faults to). A later `terraform output` rewrite drops that key:
run `deploy ecs` again after re-generating stack.json.

`deploy k8s` also applies the ClusterRole `warden-readonly` from `k8s/rbac.yaml` (the six reads);
`k8s/fullstack/warden-rbac.yaml` binds it in `shop` only.

## Destroy

    python aurora_express.py destroy    # FIRST: terraform does not know the cluster exists
    terraform destroy
    aws resourcegroupstaggingapi get-resources --region ap-south-2 \
      --tag-filters Key=Project,Values=warden-fullstack --query 'ResourceTagMappingList[].ResourceARN'

The second command must print `[]`. Expect the security-group deletes to wait up to ~20 minutes
while Lambda releases the in-VPC functions' network interfaces; that is AWS, not a hang.

## Things that are deliberate

- **One NAT gateway, in one AZ** (2026-09-26): Aurora (express) is outside the VPC, so the in-VPC
  Lambdas need a way out; AWS APIs are still reached through the endpoints. ⚠ If `public[0]`'s AZ
  fails, the in-VPC Lambdas lose the database - accepted for a benchmark, a production stack runs
  one NAT per AZ. Aurora itself has no security group: its internet access gateway cannot be
  disabled, and IAM authentication (`rds-db:connect`, one database user per identity) is the control.
- **The ALB listens on 0.0.0.0/0:80.** The traffic Lambda runs outside the VPC (a VPC Lambda has
  no internet without NAT), so its source address is not fixed. The API serves synthetic orders.
- **EKS API endpoint locked to `my_ip_cidr`**, private endpoint on (nodes join through it).
- **No autoscaling on DynamoDB, no ECS circuit breaker, catalog-api rolls with maxSurge 0, cart-worker
  uses Recreate:** each would mask a fault before anything read it.
- **Rules a fault revokes are separate resources** (Redis ingress per app SG, the ECS execution
  role's secret grant, orders-api's task-role `rds-db:connect`, checkout's `WriteCarts` statement),
  so the harness can remove and restore exactly one.
- **Alarm descriptions name the symptom, never the cause** (tested).
- **The ContainerInsights alarms** (`catalog-api-not-ready`, `cart-worker-not-running`) use metric
  names documented for Container Insights with enhanced observability and not yet seen on this
  cluster. Verify with `aws cloudwatch list-metrics --namespace ContainerInsights` after the first
  apply.
