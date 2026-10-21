# The worker (G6; requirement R20, changed by the owner 2026-10-14 from EC2 to Fargate): one service per trust zone
# (register S15), each `warden worker --zone <zone>` from the runtime image with its own task role (iam.tf), in the
# private subnets of at least two availability zones. On Fargate each task is its own micro-VM - no kernel shared with
# another zone - and has no instance metadata service, so a task holds only its own zone's role, which writes nothing
# itself. The task's root filesystem is read-only, as the non-root user.
resource "aws_ecs_cluster" "runtime" {
  # warden-<env>-*: the environment boundary lets its deploy role touch ECS services in such clusters only.
  name = "warden-${var.environment}-runtime"
  # Off (cost plan, 2026-10-16): Container Insights published 137 custom metrics here at USD 0.30 each, about USD 40
  # a month, and no alarm, tool or test reads them. The free AWS/ECS service metrics (CPU and memory utilisation) and
  # the zones' own WARDEN/<env> heartbeat stay.
  setting {
    name  = "containerInsights"
    value = "disabled"
  }
  tags = { Project = "warden", Environment = var.environment }
}

resource "aws_ecs_cluster_capacity_providers" "runtime" {
  count = var.paused ? 0 : 1
  # Fargate (owner decision 2026-10-14): each zone's task in its own micro-VM, no shared kernel, no instance metadata
  # service at all, and none of the account's EC2 vCPUs - those went to the test stack's EKS node.
  cluster_name       = aws_ecs_cluster.runtime.name
  capacity_providers = ["FARGATE"]
  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

resource "aws_iam_role" "execution" {
  name                 = "warden-${var.environment}-task-execution"
  permissions_boundary = var.permissions_boundary_arn
  description          = "WARDEN ${var.environment}: pulls the runtime image and writes the worker's logs"
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_trust.json
  tags                 = { Project = "warden", Environment = var.environment }
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/warden/${var.environment}/worker"
  retention_in_days = 90
  tags              = { Project = "warden", Environment = var.environment }
}

resource "aws_ecs_task_definition" "zone" {
  for_each                 = local.zones
  family                   = "warden-${var.environment}-${each.key}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.zone_sizes[each.key].cpu
  memory                   = var.zone_sizes[each.key].memory
  task_role_arn            = aws_iam_role.zone[each.key].arn
  execution_role_arn       = aws_iam_role.execution.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64" # the runtime image is built for it
  }
  # /tmp: Fargate has no tmpfs; a task-local volume, gone with the task (the image declares it, Dockerfile.runtime).
  volume {
    name = "tmp"
  }
  container_definitions = jsonencode([{
    name      = "worker"
    image     = var.runtime_image
    essential = true
    # The platforms a zone reads or writes a watched environment through (iam.tf `platforms`); none where it cannot.
    command                = ["worker", "--zone", each.key, "--platform", length(each.value.platforms) > 0 ? join(",", each.value.platforms) : "none"]
    user                   = "10001"
    readonlyRootFilesystem = true
    mountPoints            = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]
    environment = [for k, v in merge({
      WARDEN_ENV                   = var.environment
      WARDEN_AUDIT_KMS_KEY_ID      = aws_kms_alias.audit_signer.name
      WARDEN_AUDIT_ANCHOR_BUCKET   = aws_s3_bucket.anchors.bucket
      WARDEN_HEARTBEAT_NAMESPACE   = "WARDEN/${var.environment}"
      WARDEN_APPROVAL_RP_ID        = var.approval_domain
      WARDEN_AWS_ROLE_ARN_TEMPLATE = "arn:aws:iam::${local.account}:role/warden-{env}-{role}"
      WARDEN_AUDIT_DSN             = local.audit_dsn
      WARDEN_AUDIT_IAM_AUTH        = "1"
      # The model, for the llm zone only (the only zone that calls one); never loaded from SSM (settings.py).
      }, each.key == "llm" && var.model_provider != "" ? { WARDEN_PROVIDER = var.model_provider, WARDEN_MODEL = var.model } : {},
      # The model's budget per incident, across the investigation loop's rounds (owner decision 2026-10-10).
      each.key == "llm" ? { WARDEN_MAX_CALLS = "6", WARDEN_MAX_USD = "0.25" } : {},
      # Eldane, the AI critic, for the critic zone only - its own model, never loaded from SSM (settings.py).
      each.key == "critic" && var.critic_provider != "" ? { WARDEN_ELDANE_PROVIDER = var.critic_provider } : {},
      # The notify zone posts for real - the only zone that does. chatops.py is dry-run unless this is set, and it is
      # never loaded from SSM; without it every report was dropped silently (2026-10-09).
      each.key == "notify" ? { WARDEN_CHATOPS_LIVE = "1" } : {},
      # AWS's documentation on the evidence's error codes, as reference - fetched where the evidence is read
      # (aws_docs.py, owner decision 2026-10-10). Over the 443 egress the group already has.
      each.key == "read" ? { WARDEN_AWS_DOCS = "on" } : {},
      # The read zone gathers the evidence: every resource the alarm names, through each watched environment's reader
      # role (aws_stack.py, G9-A2b; it reuses aws_backend for ECS).
      each.key == "read" ? { WARDEN_BACKEND = "stack" } : {}) :
    { name = k, value = v }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.worker.name
        "awslogs-region"        = local.region
        "awslogs-stream-prefix" = each.key
      }
    }
  }])
  tags = { Project = "warden", Environment = var.environment }
}

resource "aws_ecs_service" "zone" {
  for_each        = var.paused ? {} : local.zones
  name            = "warden-${var.environment}-${each.key}"
  cluster         = aws_ecs_cluster.runtime.id
  task_definition = aws_ecs_task_definition.zone[each.key].arn
  desired_count   = var.worker_instances
  # On-demand for every zone, never Spot (PR 44 review, 2026-10-17): ECS does not fall back from Spot to on-demand, so
  # a zone without Spot capacity would simply not run, and the heartbeat - one per task queue - does not see one
  # zone's gap.
  capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
  platform_version = "LATEST"
  # A change of capacity provider (EC2 to Fargate, 2026-10-14) needs a fresh deployment; the AWS provider refuses
  # it otherwise. It rolls the tasks only when the service itself changes.
  force_new_deployment = true
  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.runtime.id]
  }
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  # A deploy starts as few extra tasks as it can: the account's Fargate vCPU limit refused the extra tasks a default
  # rolling deploy starts, and ECS rolled zones back (2026-10-15, twice). One copy is stopped and then started again
  # - a short gap Temporal absorbs, its work waiting in the zone's queue - with Availability Zone rebalancing off,
  # which refuses a maximum of 100% and has nothing to rebalance with one task. Two or more copies are replaced one
  # at a time, one extra task at most, and rebalanced across the zones.
  deployment_minimum_healthy_percent = var.worker_instances > 1 ? 50 : 0
  deployment_maximum_percent         = var.worker_instances > 1 ? 150 : 100
  availability_zone_rebalancing      = var.worker_instances > 1 ? "ENABLED" : "DISABLED"
  # On Fargate every task is its own micro-VM, spread over the subnets' availability zones by ECS itself: placement
  # rules are an EC2 matter (Fargate refuses them).
  propagate_tags = "SERVICE"
  tags           = { Project = "warden", Environment = var.environment }
  depends_on     = [aws_ecs_cluster_capacity_providers.runtime]
}

moved {
  from = aws_ecs_cluster_capacity_providers.runtime
  to   = aws_ecs_cluster_capacity_providers.runtime[0]
}
