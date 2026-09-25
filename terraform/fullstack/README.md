# Wave 4 - the full stack (infrastructure)

The AWS side of `docs/WAVE4-FULLSTACK.md` section 2: VPC, Aurora PostgreSQL Serverless v2,
ElastiCache Redis, DynamoDB, SQS/SNS, six Lambdas, API Gateway, ALB + ECS Fargate, EKS, Secrets
Manager, EventBridge and the CloudWatch alarms that are the alert source. Everything is named
`warden-pg-fs-*` and tagged `Project=warden-fullstack`.

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

## ⛔ Cost - about USD 0.45/hour, USD 11/day

Estimates for ap-south-2 using published ap-south-1 / us-east-1 list prices (Hyderabad prices differ
slightly), no free tier, idle load from the traffic Lambda. The budget alarm is the real guard.

| resource | per hour | note |
|---|---|---|
| Aurora Serverless v2, 2 instances at the 0.5 ACU floor | ~0.13 | does not scale to zero |
| EKS control plane | 0.10 | standard support pinned; extended support would be 0.60 |
| EKS node, 1 x t3.medium on-demand + 20 GB | ~0.05 | |
| Public IPv4 addresses (2 ECS tasks, 1 node, 2 ALB, 2 Aurora) | ~0.035 | 0.005 each |
| ElastiCache, 2 x cache.t4g.micro | ~0.035 | |
| ALB + minimal LCU | ~0.03 | |
| Fargate, 2 x (0.25 vCPU, 0.5 GB) on-demand | ~0.025 | not Spot, on purpose |
| Interface endpoints (Secrets Manager, SQS), one subnet each | ~0.022 | |
| Container Insights (enhanced, one node) | ~0.01-0.03 | per observation |
| DynamoDB 5 RCU / 5 WCU, 20 alarms, 2 secrets, Lambda/SQS/SNS/API calls | ~0.015 | |
| **total** | **~0.45** | |

**Budget:** the account budget lives in `terraform/proving-ground` (one budget, not two). The owner
raises it to USD 50 there: `terraform -chdir=terraform/proving-ground apply -var budget_usd=50`.
USD 50 is about four and a half days of this stack left running. Destroy it when a run ends.

## Before the first apply (owner, admin credentials)

1. **Raise the ceiling.** Push the updated boundary (the operator cannot, by design):

       python scripts/apply_operator_policy.py \
           terraform/proving-ground/operator-policy-boundary.json WardenProvingGroundBoundary

   It adds scoped allows for DynamoDB, SNS, Secrets Manager, ElastiCache and API Gateway on
   `warden-pg-fs-*`, KMS only through Secrets Manager and RDS, the ElastiCache service-linked role,
   and narrows the DeleteSecret/PutSecretValue/DeleteTable/DeleteDBCluster deny so it excludes
   `warden-pg-fs-*` (and still denies everything else).
2. **Grant the operator.** Create a managed policy `WardenFullstackOperator` from
   `operator-policy-fullstack.json` (5.6k of the 6,144-char limit) and attach it to the operator
   user (and to the CI role, below). The operator cannot do this itself: the boundary denies
   `iam:CreatePolicy` and `iam:AttachUserPolicy`.

   ⛔ **Open blocker:** `terraform/proving-ground/operator-policy.json` (statement
   `NeverTouchExistingDataOrKeys`) still denies `secretsmanager:PutSecretValue`/`DeleteSecret`,
   `dynamodb:DeleteTable` and `rds:DeleteDBCluster` on `*`. An explicit deny in any attached policy
   wins, so until that statement gets the same `NotResource` scoping as the boundary, the operator
   can neither write the secret values nor destroy this stack. The operator can push that change
   itself with `scripts/apply_operator_policy.py`.
3. **Service-linked roles** on a fresh account (the Wave 2 lesson: the calls that need them check
   a path-less ARN the boundary does not match):

       aws iam create-service-linked-role --aws-service-name eks-nodegroup.amazonaws.com
       aws iam create-service-linked-role --aws-service-name elasticache.amazonaws.com

4. **CI only:** the OIDC role `warden-pg-fs-ci`, the state bucket `warden-pg-fs-tfstate-*` and the
   repository variables - the list is at the top of `.github/workflows/infra.yml`. No AWS keys are
   stored anywhere.

## Apply (the operator)

    export TF_VAR_db_master_password="$(python -c 'import secrets; print(secrets.token_urlsafe(24))')"
    cp terraform.tfvars.example terraform.tfvars    # set my_ip_cidr
    terraform init && terraform apply
    mkdir -p ~/warden-fullstack-build
    terraform output -json | python -c "import json,sys; print(json.dumps({k: v for k, v in json.load(sys.stdin).items() if not v['sensitive']}, indent=1))" > ~/warden-fullstack-build/stack.json

`stack.json` carries no sensitive output (the tools fetch passwords from Secrets Manager when they
need them). It does carry ARNs with the account id: it lives outside the repo and is never published.

Then the apps pipeline:

    python scripts/deploy_fullstack_apps.py build
    python scripts/deploy_fullstack_apps.py bootstrap-db     # WARDEN_FS_DB_MASTER_PASSWORD or TF_VAR_db_master_password
    python scripts/deploy_fullstack_apps.py deploy all

`deploy ecs` writes the revision it registered into stack.json as `ecs_baseline_task_definition`
(the revision the harness reverts ECS faults to). A later `terraform output` rewrite drops that key:
run `deploy ecs` again after re-generating stack.json.

`deploy k8s` also applies the ClusterRole `warden-readonly` from `k8s/rbac.yaml` (the six reads);
`k8s/fullstack/warden-rbac.yaml` binds it in `shop` only.

## Destroy

    terraform destroy
    aws resourcegroupstaggingapi get-resources --region ap-south-2 \
      --tag-filters Key=Project,Values=warden-fullstack --query 'ResourceTagMappingList[].ResourceARN'

The second command must print `[]`. Expect the security-group deletes to wait up to ~20 minutes
while Lambda releases the in-VPC functions' network interfaces; that is AWS, not a hang.

## Things that are deliberate

- **Public subnets, no NAT gateway** (as the proving ground): the private subnets reach AWS through
  endpoints only. Aurora is publicly accessible but its SG admits the operator IP and the app SGs.
- **The ALB listens on 0.0.0.0/0:80.** The traffic Lambda runs outside the VPC (a VPC Lambda has
  no internet without NAT), so its source address is not fixed. The API serves synthetic orders.
- **EKS API endpoint locked to `my_ip_cidr`**, private endpoint on (nodes join through it).
- **No autoscaling on DynamoDB, no ECS circuit breaker, catalog-api rolls with maxSurge 0, cart-worker
  uses Recreate:** each would mask a fault before anything read it.
- **Rules a fault revokes are separate resources** (Redis/Aurora ingress per app SG, the ECS
  execution role's secret grant, checkout's `WriteCarts` statement), so the harness can remove
  and restore exactly one.
- **Alarm descriptions name the symptom, never the cause** (tested).
- **The ContainerInsights alarms** (`catalog-api-not-ready`, `cart-worker-not-running`) use metric
  names documented for Container Insights with enhanced observability and not yet seen on this
  cluster. Verify with `aws cloudwatch list-metrics --namespace ContainerInsights` after the first
  apply.
