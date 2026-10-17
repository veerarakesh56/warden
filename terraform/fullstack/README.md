# The full-stack lab (infrastructure)

The AWS side of the full-stack lab ([`docs/FULLSTACK-LAB.md`](../../docs/FULLSTACK-LAB.md)): VPC (+ one NAT gateway), ElastiCache Redis,
DynamoDB, SQS/SNS, six Lambdas, API Gateway, ALB + ECS Fargate, EKS, Secrets Manager, EventBridge
and the CloudWatch alarms that are the alert source - and, through `aurora_express.py` in this
directory, Aurora PostgreSQL Serverless v2. Everything is named `warden-<env>-*` (the Terraform
workspace is the environment; `dev` in the examples) and tagged `Project=warden` +
`Environment=<env>`.

⛔ **Built for an account on the AWS Free plan (docs/FULLSTACK-LAB.md section 1).** That plan
creates Aurora only in EXPRESS configuration, which the Terraform provider cannot do, so
`aurora_express.py create` makes the cluster after `terraform apply` and `aurora_express.py destroy`
removes it before `terraform destroy`. Express configuration has no VPC (the Aurora internet access
gateway, 5432) and IAM database authentication only: **there is no database password anywhere**.
The Free plan also admits only Free Tier eligible instance types: the EKS node is m7i-flex.large.

**Three independent pipelines.** This directory is INFRA only. It never builds or deploys
application code:

| pipeline | what | how | reads |
|---|---|---|---|
| infra | this directory | `terraform apply` locally, or `.github/workflows/deploy-<env>.yml` (by hand, from the branch `<env>`; part: infra), or a plan on a push to the branch `<env>` (`on-merge-<env>.yml`) | - |
| apps | Lambdas, container image, the shop (`manifests/shop`, synced by Argo CD; `k8s/shop-pipeline`) | `scripts/deploy_fullstack_apps.py`, or `.github/workflows/deploy-<env>.yml` (by hand, from the branch `<env>`; part: apps), or a push to the branch `<env>` (`on-merge-<env>.yml`) | `stack.json` |
| WARDEN CI | the tool | `.github/workflows/ci-tool.yml` | - |

Branches (owner, 2026-10-16): an environment deploys only from the branch of its own name, and `main` deploys
nothing (CI only). The `dev` branch deploys dev; it is `main` fast-forwarded. The `prod` branch deploys prod, every
job behind a person's approval; it is `dev` merged by pull request. A commit that did not come that way is refused
before the job holds a credential.

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
| Public IPv4 address (the NAT gateway's Elastic IP only; ECS, EKS and the internal ALB are private) | ~0.005 | |
| ElastiCache, 2 x cache.t4g.micro | ~0.035 | |
| ALB + minimal LCU | ~0.03 | |
| Fargate, 2 x (0.25 vCPU, 0.5 GB) on-demand | ~0.025 | not Spot, on purpose |
| Interface endpoints (Secrets Manager, SQS), one subnet each | ~0.022 | |
| Container Insights (enhanced, one node) | ~0.01-0.03 | per observation |
| DynamoDB 5 RCU / 5 WCU, 20 alarms, 1 secret, Lambda/SQS/SNS/API calls | ~0.015 | |
| **total** | **~0.50** | |

**Budget:** this stack carries its own alarm, `warden-<env>-guard` (USD 50 a month by default,
`budget_usd`), emailing the address in SSM `/warden/<env>/tf/budget_email` (SecureString) on
forecast 60%/90% and actual 50%/100%. The proving ground's budget was destroyed with it.
USD 50 is about four days of this stack left running. Destroy it when a run ends.

## Before the first apply

The identities that build this stack are the environment's rendered IAM (`iam/<env>/`, from `iam/templates/` by
`scripts/render_env_iam.py`) and the operator role (`iam/operator/`). Create the environment's deploy role,
permissions boundary, state bucket, Parameter Store values and GitHub environment as
[`docs/SETUP.md`](../../docs/SETUP.md) section 3 describes. On a fresh account, also create two service-linked
roles once (the calls that need them check a path-less ARN the boundary does not match):

    aws iam create-service-linked-role --aws-service-name eks-nodegroup.amazonaws.com
    aws iam create-service-linked-role --aws-service-name elasticache.amazonaws.com

No AWS keys are stored anywhere: CI reaches AWS through the OIDC role `warden-<env>-deploy`.

## Apply (the environment's deploy role)

The stack belongs to an **environment** (dev or prod - the keys of
`src/warden/data/environments.yaml`), and the environment is the **Terraform workspace**. Names are
`warden-<env>-*`, every resource is tagged `Project=warden` + `Environment=<env>`, and every role
carries `WardenEnvBoundary-<env>` (`iam/<env>/boundary.json`). The two per-environment values are
read from SSM Parameter Store, never from a file: `/warden/<env>/tf/my_ip_cidr` (String) and
`/warden/<env>/tf/budget_email` (SecureString). A workspace that is not an environment - including
`default` - is refused before anything is built.

    terraform init
    terraform workspace select -or-create dev
    WARDEN_ENV=dev terraform apply
    mkdir -p ~/warden-fullstack-build
    terraform output -json | python -c "import json,sys; print(json.dumps({k: v for k, v in json.load(sys.stdin).items() if not v['sensitive']}, indent=1))" > ~/warden-fullstack-build/stack.json
    WARDEN_ENV=dev python aurora_express.py create   # Aurora (express): cluster, 0.5-2 ACU, reader; merges its keys into stack.json

`aurora_express.py create` takes several minutes (the reader instance), writes the endpoints into
the metadata secret `warden-<env>-db-app`, and adds `aurora_cluster`, `aurora_writer_endpoint`,
`aurora_reader_endpoint`, `aurora_instance_endpoints`, `aurora_writer_instance` (express names the
writer itself), `db_name` and `db_master_username` to stack.json. Run it again after any later
`terraform output` rewrite of stack.json: on an existing cluster it only refreshes those records.
`WARDEN_ENV=dev python aurora_express.py status` shows what exists. The script acts only on the environment
WARDEN_ENV names, refuses without one, and refuses a stack.json of another environment.

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
`manifests/shop/base/warden-rbac.yaml` binds it in `shop` only.

## Destroy

    WARDEN_ENV=dev python aurora_express.py destroy  # FIRST: terraform does not know the cluster exists
    terraform destroy
    python scripts/account_sweep.py     # every region, every service, never trusts tags

The sweep must end `clean` (exit 0). A tag-filtered listing is not enough: an untagged resource bills
the same, and it would be invisible to a tag filter. Expect the security-group deletes to wait up to ~20 minutes
while Lambda releases the in-VPC functions' network interfaces; that is AWS, not a hang.

## Network: what is public and what is not (2026-09-27 review)

| Where | What | Reachable from |
|---|---|---|
| Public subnets | the NAT gateway (its Elastic IP) only; `map_public_ip_on_launch = false` | nothing inbound |
| Private subnets | ECS tasks (no public IP), EKS nodes and control-plane interfaces, in-VPC Lambdas, Redis, the ALB (**internal**), interface endpoints | inside the VPC only; the ALB only from the Lambda security group |
| AWS-managed, public by design | API Gateway (the shop's public API), the EKS API endpoint | API Gateway: throttled; `POST /checkout` needs a bearer token, which the checkout Lambda checks in constant time against a Secrets Manager secret written write-only (in no plan or state, `api_auth.tf`); `GET /health` is open and touches nothing; JSON access logs go to `/aws/vendedlogs/warden-<env>-api-access`. EKS API: `/warden/<env>/tf/my_ip_cidr` by default, IAM auth through access entries - **but open to `0.0.0.0/0` while the `EKS_PUBLIC_CIDRS` variable is set on the GitHub environment (`eks_public_access_cidrs`), and it stays open until an apply without it**. The fix, an in-VPC deploy path, is an open row in `docs/FAILURE-MODES.md` (A-I-16) |
| Outside the VPC | Aurora in express configuration (the Free plan's only form) | IAM database authentication only, no password exists |

No security group accepts `0.0.0.0/0` (a test enforces it). Egress leaves through the one NAT.
There are no ECR interface endpoints, and the placeholder image comes from `public.ecr.aws`, so image
pulls go through the NAT as well; only S3 and DynamoDB have (free) gateway endpoints. A production app with a domain would put a **public** ALB in
front with HTTPS (a free ACM certificate) and WAF; this lab has no domain, so its ALB is internal.

## Things that are deliberate

- **One NAT gateway, in one AZ** (2026-09-26): Aurora (express) is outside the VPC, so the in-VPC
  Lambdas need a way out; AWS APIs are still reached through the endpoints. ⚠ If `public[0]`'s AZ
  fails, the in-VPC Lambdas lose the database - accepted for a benchmark, a production stack runs
  one NAT per AZ. Aurora itself has no security group: its internet access gateway cannot be
  disabled, and IAM authentication (`rds-db:connect`, one database user per identity) is the control.
- **The ALB is internal**, in private subnets, and accepts traffic only from the traffic Lambda's
  security group; the traffic Lambda runs **inside** the VPC (`in_vpc = true`). The API serves
  synthetic orders.
- **EKS API endpoint locked to `/warden/<env>/tf/my_ip_cidr`**, private endpoint on (nodes join through it), plus
  WARDEN's runtime NAT addresses (`eks.tf`, read by the runtime's NAT names): the runtime VPC's range overlaps this
  one, so no peering reaches the private endpoint, and its Fargate workers arrive through their NAT. Pausing the
  runtime releases its NAT address; re-apply this stack after resuming it, or cluster reads and fixes are refused
  (and go to a person) until then. WARDEN's actor role has an access entry of its own: group `warden-remediators`, no
  access policy - the remediator RBAC and admission policy (`k8s/remediation-rbac.yaml`) decide.
- **No autoscaling on DynamoDB, no ECS circuit breaker, catalog-api rolls with maxSurge 0, cart-worker
  uses Recreate:** each would mask a fault before anything read it.
- **Rules a fault revokes are separate resources** (Redis ingress per app SG, the ECS execution
  role's secret grant, orders-api's task-role `rds-db:connect`, checkout's `WriteCarts` statement),
  so the harness can remove and restore exactly one.
- **Alarm descriptions name the symptom, never the cause** (tested).
- **The ContainerInsights alarms** (`catalog-errors`, `cart-worker-stalled`) use metric names
  documented for Container Insights with enhanced observability; they were verified on the live
  cluster on 2026-09-26 (`alarms.tf`).
