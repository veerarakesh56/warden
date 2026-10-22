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
every path over HTTPS; every code field is in `ignore_changes`, so a re-apply never rolls the apps back.

The shop's containers serve HTTPS only (Sonar python:S5332, owner row 25): each makes its own self-signed certificate
at start (`scenarios/fullstack/app/app.py`; the placeholder with the image's openssl), so nothing is stored and nothing
costs. Their only callers do not verify a target's certificate: the ALB (target group and health check on HTTPS) and the
kubelet's `scheme: HTTPS` probes. The ALB's own listener has the stack's certificate, which the traffic Lambda pins.
Kubernetes objects are not in terraform at all.

## ⛔ Cost - about USD 0.66/hour, USD 16/day (after the cost plan, with the interface endpoints of 2026-10-21)

Measured in Cost Explorer for 2026-10-15 (a full day, before credits: USD 0.65/hour for this stack,
USD 0.99/hour with WARDEN's runtime), ap-south-2 prices from the AWS Price List API the same day, then
the cost plan of 2026-10-16/17 subtracted. WARDEN's runtime (terraform/runtime) adds about USD
0.28/hour (was 0.34; every zone stays on on-demand Fargate): together about USD 0.94/hour, so about USD 22.5/day (was 19.4
before the endpoints, 23.81 before the cost plan).

| resource | per hour | note |
|---|---|---|
| EKS node, 1 x m7i-flex.large on-demand (0.1008) + 20 GB | ~0.103 | was 2; production shape is 2 |
| EKS control plane | 0.10 | standard support pinned; extended support would be 0.60 |
| Aurora Serverless v2 (express), 1 instance at the 0.5 ACU floor (0.18 per ACU-hour) | ~0.095 | does not scale to zero at a 0.5 floor |
| Container Insights enhanced (EKS add-on) | ~0.07 | per observation; the pod_status alarms read it. No X-Ray copy of the traces while Datadog is on |
| Interface endpoints: secretsmanager, sqs, logs, ecr.api, ecr.dkr, each in 2 AZs (0.013 per endpoint-hour per AZ) + 0.01/GB | 0.13 | owner decision 2026-10-21: the AWS calls stay off the internet; USD 94.90 a month |
| NAT gateway (one, public[0]) + data processed | ~0.06 | Aurora express, the public API (traffic Lambda), the placeholder image |
| Fargate, 2 x (0.25 vCPU, 0.5 GB) on-demand, x86 | ~0.026 | ARM would be ~0.014 |
| ALB | ~0.024 | |
| ElastiCache, 1 x cache.t4g.micro | 0.02 | was 2 with failover |
| Public IPv4 address (the NAT gateway's Elastic IP only) | 0.005 | |
| DynamoDB, alarms, secrets, Lambda/SQS/SNS/API calls, Config's share | ~0.03 | |
| **total** | **~0.66** | |

Interface endpoints again since 2026-10-21 (owner: AWS calls off the internet; the price is from the AWS Price List
API for ap-south-2, published 2026-10-16); see main.tf. The one
EKS node and the one cache node no longer survive a zone outage: Helios (R56) lets those two through
only because they are listed in `helios/regressions.json`, the owner's choice of 2026-10-17. Back to
production shape: 2 nodes, 2 cache nodes with failover, and that file deleted.

**Budget:** this stack carries its own alarm, `warden-<env>-guard` (USD 500 a month by default,
`budget_usd`), on the whole account's GROSS spend (credits excluded: counted, a Free-plan account
reads USD 0.00 until the credits are gone - and then the Free plan closes the account), emailing the
address in SSM `/warden/<env>/tf/budget_email` (SecureString) on forecast 60%/90% and actual 50%/100%.

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

## After an apply that changes the network (interface endpoints and least egress, PR 129)

A timeout here is silent: nothing fails at apply time, a pull or a call just hangs later. So after the apply that
brings the endpoints (and after any later change to `main.tf`'s security groups), check every path once, in this
order. `E=dev`, run from `terraform/fullstack` with the environment's deploy role.

1. **Before the apply**, read the plan: no `aws_security_group` may be **replaced** (a group's description forces
   that, and an ALB, a task or a Lambda ENI holding the old group makes the destroy hang). Expected: the endpoint group,
   its 4 ingress rules, the 5 interface endpoints, the `traffic` group, the separate egress rules, the traffic
   Lambda's `vpc_config`, the ALB's ingress rule.
2. **Once, after that first apply**: the `ecs` and `lambda` groups still hold the old allow-all egress rule (inline
   rules taken out of the configuration are left in AWS, not revoked). Revoke it:

       for g in ecs lambda; do
         id=$(aws ec2 describe-security-groups --filters Name=group-name,Values=warden-$E-$g --query 'SecurityGroups[0].GroupId' --output text)
         aws ec2 revoke-security-group-egress --group-id "$id" --ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]'
       done

   Then each group's egress must be exactly what `main.tf` declares (ecs: 443 endpoints, 443 + 5432 to 0.0.0.0/0,
   6379 redis; lambda: 443 endpoints, 5432, 6379 redis; traffic: 443 to 0.0.0.0/0) and no `-1`:

       aws ec2 describe-security-group-rules --filters Name=group-id,Values="$id" \
         --query 'SecurityGroupRules[?IsEgress].[IpProtocol,FromPort,CidrIpv4,ReferencedGroupInfo.GroupId]' --output table
3. **A second plan must say `No changes.`** Anything else (a rule removed and added again, a group in-place update)
   means a group mixes inline and separate rules: fix the configuration, do not apply over it.

       WARDEN_ENV=$E terraform plan -detailed-exitcode   # exit code 0, not 2
4. **The endpoints**: five interface endpoints, `available`, with private DNS:

       aws ec2 describe-vpc-endpoints --filters Name=vpc-endpoint-type,Values=Interface Name=tag:Environment,Values=$E \
         --query 'VpcEndpoints[].[ServiceName,State,PrivateDnsEnabled]' --output table
5. **orders-api (ECR, Secrets Manager, Logs through the endpoints)**: a running task fetched its image and secret at
   start, before the change, so start new ones, on the APPS pipeline's image (the placeholder comes from
   `public.ecr.aws` through the NAT and proves nothing about the endpoints - run `deploy ecs` first if the service
   still runs it):

       aws ecs update-service --cluster warden-$E-ecs --service "$(terraform output -raw ecs_service)" --force-new-deployment >/dev/null
       aws ecs wait services-stable --cluster warden-$E-ecs --services "$(terraform output -raw ecs_service)"
       aws ecs describe-tasks --cluster warden-$E-ecs --tasks $(aws ecs list-tasks --cluster warden-$E-ecs --query 'taskArns' --output text) \
         --query 'tasks[].[lastStatus,containers[0].image]' --output table

   Every task `RUNNING`, every image starting with `terraform output -raw ecr_repository_url`, and new log streams
   in `/ecs/warden-$E-orders-api`.
6. **The in-VPC Lambdas (Secrets Manager, SQS through the endpoints)**: a warm environment keeps the secret it read
   before the change, so force cold starts (a configuration update replaces the environments; the second update puts
   the description back, so the plan stays empty), then run them:

       for f in order-processor reconciler traffic ops; do
         aws lambda update-function-configuration --function-name warden-$E-$f --description cold-start >/dev/null
         aws lambda wait function-updated --function-name warden-$E-$f
         aws lambda update-function-configuration --function-name warden-$E-$f --description "" >/dev/null
         aws lambda wait function-updated --function-name warden-$E-$f
       done
       aws lambda invoke --function-name warden-$E-traffic /dev/stdout      # no FunctionError; it also feeds order-processor
       aws lambda invoke --function-name warden-$E-reconciler /dev/stdout   # no FunctionError

   Then order-processor's `Errors` metric stays 0 and the orders queue drains (its dead-letter queue stays empty).
7. **EKS (ECR and Logs through the endpoints, from the cluster security group)**: running pods keep the images they
   pulled before the change, so pull again - the shop image and an add-on image:

       kubectl -n shop rollout restart deployment/catalog-api deployment/cart-worker
       kubectl -n shop rollout status deployment/catalog-api --timeout=5m
       kubectl -n shop rollout status deployment/cart-worker --timeout=5m
       kubectl -n kube-system rollout restart deployment/coredns
       kubectl -n kube-system rollout status deployment/coredns --timeout=5m
       kubectl -n shop get events --field-selector reason=Pulled          # the new pulls
       kubectl get events -A --field-selector reason=Failed               # no ErrImagePull / ImagePullBackOff

8. **Container Insights still arrives** (the observability agent writes through the `logs` endpoint): the newest
   stream of `/aws/containerinsights/warden-$E-eks/performance` has an event from the last 5 minutes, and the two
   pod alarms (`warden-$E-catalog-errors`, `warden-$E-cart-worker-stalled`, missing data = breaching) are `OK`:

       aws logs describe-log-streams --log-group-name /aws/containerinsights/warden-$E-eks/performance \
         --order-by LastEventTime --descending --max-items 1 --query 'logStreams[0].lastEventTimestamp'
       aws cloudwatch describe-alarms --alarm-names warden-$E-catalog-errors warden-$E-cart-worker-stalled \
         --query 'MetricAlarms[].[AlarmName,StateValue]' --output table

A step that hangs or fails names its path: add the missing rule or endpoint with a test (`tests/test_iac_hardening_sonar.py`), never a wider rule.

## Destroy

    WARDEN_ENV=dev python aurora_express.py destroy  # FIRST: terraform does not know the cluster exists
    terraform destroy
    python scripts/account_sweep.py     # every region, every service, never trusts tags

`aurora_express.py destroy` never deletes the cluster without a final snapshot, `warden-<env>-aurora-final-<UTC time>`
(for example `warden-dev-aurora-final-20261017t113000z`), tagged like the cluster; it stops the teardown if the
snapshot is missing afterwards. The environment's boundary denies deleting or sharing a snapshot, so the sweep lists
each final snapshot until the owner deletes it with the operator role once it is no longer wanted (snapshot storage
bills by the GB-month). Apart from those, the sweep must end `clean` (exit 0). A tag-filtered listing is not enough: an untagged resource bills
the same, and it would be invisible to a tag filter. Expect the security-group deletes to wait up to ~20 minutes
while Lambda releases the in-VPC functions' network interfaces; that is AWS, not a hang.

## Network: what is public and what is not (2026-09-27 review)

| Where | What | Reachable from |
|---|---|---|
| Public subnets | the NAT gateway (its Elastic IP) only; `map_public_ip_on_launch = false` | nothing inbound |
| Private subnets | ECS tasks (no public IP), EKS nodes and control-plane interfaces, in-VPC Lambdas, Redis, the ALB (**internal**) | inside the VPC only; the ALB only from the traffic Lambda's security group |
| AWS-managed, public by design | API Gateway (the shop's public API), the EKS API endpoint | API Gateway: throttled; `POST /checkout` needs a bearer token, which the checkout Lambda checks in constant time against a Secrets Manager secret written write-only (in no plan or state, `api_auth.tf`); `GET /health` is open and touches nothing; JSON access logs go to `/aws/vendedlogs/warden-<env>-api-access`. EKS API: `/warden/<env>/tf/my_ip_cidr` by default, IAM auth through access entries - **but open to `0.0.0.0/0` while the `EKS_PUBLIC_CIDRS` variable is set on the GitHub environment (`eks_public_access_cidrs`), and it stays open until an apply without it**. The fix, an in-VPC deploy path, is an open row in `docs/FAILURE-MODES.md` (A-I-16) |
| Outside the VPC | Aurora in express configuration (the Free plan's only form) | IAM database authentication only, no password exists |

No security group accepts `0.0.0.0/0` (a test enforces it). Egress leaves through the one NAT, and the application groups allow only what the apps use (owner B28, `tests/test_iac_hardening_sonar.py`): HTTPS to AWS goes to the interface endpoints only (Secrets Manager, SQS, CloudWatch Logs, ECR; S3 and DynamoDB through
free gateway endpoints), Redis 6379 to the cache's group only. Private DNS sends the whole VPC's calls to those
services to the endpoints, so the endpoint group admits 443 from the application groups AND from the EKS cluster
security group (the nodes' image pulls, the add-ons, the Container Insights agent). Each group's egress is separate
`aws_vpc_security_group_egress_rule` resources, never inline blocks mixed with them. The internet is left only where no endpoint can serve,
each with its reason in main.tf: PostgreSQL 5432 to Aurora express (no VPC, no security group, no fixed address),
HTTPS 443 for orders-api's placeholder image on `public.ecr.aws`, and HTTPS 443 for the traffic Lambda - in a group of
its own - which calls the shop's public API and reaches the internal load balancer over HTTPS 443. A production app with a domain would put a **public** ALB in
front with HTTPS (a free ACM certificate) and WAF; this lab has no domain, so its ALB is internal - and still HTTPS only
(2026-10-17): the stack makes a self-signed certificate for the ALB's DNS name and imports it into ACM (no charge),
and the traffic Lambda trusts that one certificate (`ALB_CA_PEM`). Its access logs go to `warden-<env>-alb-logs-*`
(14 days), and the order-events topic is encrypted with the AWS-managed `aws/sns` key.

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
