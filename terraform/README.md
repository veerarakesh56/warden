# Deploying WARDEN on AWS

An ECS Fargate task definition, its roles, an egress-only security group and a log group.

```hcl
module "warden" {
  source = "github.com/veerarakesh56/warden//terraform"

  image                = "<acct>.dkr.ecr.ap-south-1.amazonaws.com/warden:v0.1.0"
  cluster_arn          = aws_ecs_cluster.platform.arn
  vpc_id               = module.vpc.vpc_id
  subnet_ids           = module.vpc.private_subnets
  anthropic_secret_arn = aws_secretsmanager_secret.anthropic.arn

  tags = { Team = "platform" }
}
```

## The two decisions worth arguing about

**1. The task role cannot change anything.** It has `logs:*Get*`, `cloudwatch:Get*` and
`ecs:Describe*` — read-only. WARDEN reads evidence and proposes a remediation; a human executes it.
Granting write access to the infrastructure it reasons about would defeat the design, and "it only
uses them when the verifier approves" is not a security boundary — IAM is.

**2. The API key never enters Terraform state.** It is passed as a **Secrets Manager ARN** and
injected by ECS at container start. A key passed as a Terraform variable ends up in state, and state
files get committed, copied into buckets and shared far more often than anyone plans for.

## Also set deliberately

- **Private subnets only**, with a validation rule that rejects an empty list. WARDEN reads telemetry;
  nothing connects *to* it, so it has no reason to be publicly routable.
- **Egress on 443 only** — model API, AWS APIs, OTLP collector.
- **`readonlyRootFilesystem = true`** and **non-root user 10001**, matching the Dockerfile.
- **Log retention defaults to 30 days.** Incident context contains production detail; keeping it
  forever by accident is a liability, not a feature.
- **The cluster is an input, not a resource.** Clusters are shared infrastructure that should outlive
  any single workload.

## Honest status

⚠ **Validated in CI (`terraform validate` on a clean runner), never `terraform apply`-ed.** It has
not been run against a live AWS account. Treat it as a reviewed starting point, not as
battle-tested infrastructure.

⚠ **`task_readonly` uses `resources = ["*"]`.** The services being diagnosed are not known ahead of
time, so the read scope is broad. In a real deployment, narrow it with condition blocks or scope it
to specific log groups — and say so in review rather than letting it pass unnoticed.

⚠ **No trigger is included.** Wiring an EventBridge rule from Alertmanager or Datadog to
`ecs:RunTask` is deployment-specific and deliberately left out.
