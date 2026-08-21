# AEGIS on ECS Fargate.
#
# Two deliberate choices worth reading before you copy this:
#
# 1. The task role has **no permissions to change anything**. AEGIS reads logs, metrics and deploy
#    history and proposes a remediation. It does not execute one. Giving it write access to the
#    infrastructure it reasons about would defeat the entire design.
# 2. The API key is passed by **secret ARN reference**, never as a Terraform variable, so it never
#    lands in state. State files get committed, copied and shared far more often than anyone plans.

locals {
  tags = merge(var.tags, {
    Application = var.name
    ManagedBy   = "terraform"
  })
}

data "aws_region" "current" {}

# --------------------------------------------------------------------------- logs

resource "aws_cloudwatch_log_group" "aegis" {
  name              = "/ecs/${var.name}"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

# --------------------------------------------------------------------------- iam

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# Execution role: what ECS itself needs to start the container (pull image, write logs, read secret).
resource "aws_iam_role" "execution" {
  name               = "${var.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "read_secret" {
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.anthropic_secret_arn]
  }
}

resource "aws_iam_role_policy" "execution_secret" {
  name   = "${var.name}-read-secret"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.read_secret.json
}

# Task role: what the RUNNING application may do. Read-only, on purpose.
resource "aws_iam_role" "task" {
  name               = "${var.name}-task"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  tags               = local.tags
}

data "aws_iam_policy_document" "task_readonly" {
  statement {
    sid    = "ReadObservabilitySignals"
    effect = "Allow"

    actions = [
      "logs:FilterLogEvents",
      "logs:GetLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "cloudwatch:GetMetricData",
      "cloudwatch:GetMetricStatistics",
      "cloudwatch:ListMetrics",
      "ecs:DescribeServices",
      "ecs:DescribeTaskDefinition",
      "ecs:ListTasks",
    ]

    # Read-only actions across the account being diagnosed. Narrow with a condition block in a real
    # deployment; kept broad here because the services under investigation are not known in advance.
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "task_readonly" {
  name   = "${var.name}-readonly"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task_readonly.json
}

# --------------------------------------------------------------------------- networking

resource "aws_security_group" "aegis" {
  name        = "${var.name}-task"
  description = "AEGIS task. Egress only - nothing connects to it."
  vpc_id      = var.vpc_id
  tags        = local.tags

  egress {
    description = "HTTPS to the model API, AWS APIs and the OTLP collector."
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --------------------------------------------------------------------------- task

resource "aws_ecs_task_definition" "aegis" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  tags                     = local.tags

  container_definitions = jsonencode([
    {
      name      = var.name
      image     = var.image
      essential = true

      environment = [
        { name = "AEGIS_MOCK", value = "0" },
        { name = "AEGIS_MAX_USD", value = var.max_usd_per_run },
        { name = "AEGIS_TOOL_TIMEOUT", value = var.tool_timeout_seconds },
        { name = "OTEL_EXPORTER_OTLP_ENDPOINT", value = var.otlp_endpoint },
      ]

      secrets = [
        { name = "ANTHROPIC_API_KEY", valueFrom = var.anthropic_secret_arn },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.aegis.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "ecs"
        }
      }

      readonlyRootFilesystem = true
      user                   = "10001"
    }
  ])
}
