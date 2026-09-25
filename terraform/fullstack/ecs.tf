# The container side: ECR, the orders-api service on Fargate behind an ALB.
#
# ⛔ Terraform registers only a PLACEHOLDER task definition (a public image answering 200 on every
# path, so the service is healthy before any app exists). The APPS pipeline pushes the real image
# and registers the real revision - with the DB credentials injected from Secrets Manager - and
# `task_definition` is ignored here so a re-apply never rolls it back.

resource "aws_ecr_repository" "app" {
  name                 = "${local.name}-app"
  image_tag_mutability = "MUTABLE"
  force_delete         = true # a destroy must not stop at a non-empty repository
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "keep the last 10 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 10 }
      action       = { type = "expire" }
    }]
  })
}

resource "aws_cloudwatch_log_group" "orders_api" {
  name              = "/ecs/${local.name}-orders-api"
  retention_in_days = 3
}

resource "aws_ecs_cluster" "this" {
  name = "${local.name}-ecs"
  setting {
    name  = "containerInsights"
    value = "disabled" # AWS/ECS and ALB metrics suffice; Container Insights is billed per metric
  }
}

resource "aws_iam_role" "ecs_execution" {
  name                 = "${local.name}-ecs-exec"
  permissions_boundary = local.permissions_boundary
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Its own inline policy so fs-18 can remove exactly this grant and the harness can restore it.
resource "aws_iam_role_policy" "ecs_execution_secret" {
  name = "${local.name}-read-db-secret"
  role = aws_iam_role.ecs_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadDbSecret"
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.db_app.arn]
    }]
  })
}

resource "aws_ecs_task_definition" "orders_api" {
  family                   = "${local.name}-orders-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution.arn

  container_definitions = jsonencode([{
    name         = "orders-api"
    image        = "public.ecr.aws/docker/library/python:3.12-alpine"
    essential    = true
    portMappings = [{ containerPort = 8080, protocol = "tcp" }]
    command = [
      "python", "-u", "-c",
      "import http.server as h\nclass H(h.BaseHTTPRequestHandler):\n    def do_GET(s):\n        s.send_response(200); s.end_headers(); s.wfile.write(b'placeholder')\nh.HTTPServer(('', 8080), H).serve_forever()\n",
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.orders_api.name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "orders-api"
      }
    }
  }])
}

# --------------------------------------------------------------------------- ALB

resource "aws_lb" "orders" {
  name               = "${local.name}-alb"
  load_balancer_type = "application"
  internal           = false
  subnets            = aws_subnet.public[*].id
  security_groups    = [aws_security_group.alb.id]
}

resource "aws_lb_target_group" "orders" {
  name                 = "${local.name}-orders"
  port                 = 8080
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = aws_vpc.this.id
  deregistration_delay = 10
  health_check {
    path                = "/health" # fs-19 changes it to /healthz
    matcher             = "200"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.orders.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.orders.arn
  }
}

# --------------------------------------------------------------------------- service

resource "aws_ecs_service" "orders_api" {
  name                              = "${local.name}-orders-api"
  cluster                           = aws_ecs_cluster.this.id
  task_definition                   = aws_ecs_task_definition.orders_api.arn
  desired_count                     = 2
  launch_type                       = "FARGATE" # not Spot: an interruption mid-fault is a second fault
  health_check_grace_period_seconds = 30

  # 50/100: a rollout replaces one task at a time, so a revision that cannot start shows up as
  # 1 of 2 healthy instead of hiding behind the old tasks. No circuit breaker: an automatic
  # rollback would undo the fault before anything read it.
  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 100

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true # no NAT gateway
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.orders.arn
    container_name   = "orders-api"
    container_port   = 8080
  }

  lifecycle {
    ignore_changes = [task_definition, desired_count] # the APPS pipeline and the harness own these
  }

  depends_on = [aws_lb_listener.http, aws_iam_role_policy_attachment.ecs_execution]
}
