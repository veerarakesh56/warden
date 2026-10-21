# The container side: ECR, the orders-api service on Fargate behind an ALB.
#
# ⛔ Terraform registers only a PLACEHOLDER task definition (a public image answering 200 on every
# path, so the service is healthy before any app exists). The APPS pipeline pushes the real image
# and registers the real revision - with the task role below and one value injected from the
# metadata secret - and `task_definition` is ignored here so a re-apply never rolls it back.

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
  name = "/ecs/${local.name}-orders-api"
  # 14 days (Sonar terraform:S6413, 2026-10-16): enough to look back at an incident found days later.
  retention_in_days = 14
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

# orders-api's OWN identity (the task role, not the execution role): it signs IAM database tokens
# as the application user. Its only grant is its own inline policy, so fs-21 can remove exactly it and the
# harness can put it back.
resource "aws_iam_role" "ecs_task" {
  name                 = "${local.name}-orders-api-task"
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

resource "aws_iam_role_policy" "ecs_task_db" {
  name = "${local.name}-db-connect"
  role = aws_iam_role.ecs_task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ConnectAsApp"
      Effect   = "Allow"
      Action   = ["rds-db:connect"]
      Resource = [local.dbuser_arn["app"]]
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
    name = "orders-api"
    # The app image's own base (demo-app/app/Dockerfile), for its openssl: the placeholder serves HTTPS like
    # the app (Sonar python:S5332, owner row 25), with a certificate it makes for itself at start.
    image        = "public.ecr.aws/docker/library/python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f"
    essential    = true
    portMappings = [{ containerPort = 8080, protocol = "tcp" }]
    command = [
      "sh", "-c",
      "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=placeholder -days 365 -keyout /tmp/k.pem -out /tmp/c.pem 2>/dev/null && exec python -u -c \"$PLACEHOLDER\"",
    ]
    environment = [{
      name  = "PLACEHOLDER"
      value = "import http.server as h, ssl\nclass H(h.BaseHTTPRequestHandler):\n    def do_GET(s):\n        s.send_response(200); s.end_headers(); s.wfile.write(b'placeholder')\nc = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\nc.minimum_version = ssl.TLSVersion.TLSv1_2\nc.load_cert_chain('/tmp/c.pem', '/tmp/k.pem')\ns = h.HTTPServer(('', 8080), H)\ns.socket = c.wrap_socket(s.socket, server_side=True)\ns.serve_forever()\n"
    }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.orders_api.name
        "awslogs-region"        = local.region
        "awslogs-stream-prefix" = "orders-api"
      }
    }
  }])
}

# --------------------------------------------------------------------------- ALB

resource "aws_lb" "orders" {
  name               = "${local.name}-alb"
  load_balancer_type = "application"
  # ⛔ INTERNAL, in private subnets (2026-09-27 network review). Its only caller is the traffic
  # Lambda inside the VPC; nothing on the internet can reach it. A production app with a domain puts
  # a public ALB here with HTTPS (a free ACM certificate) - this lab has no domain, so it has no TLS
  # to terminate, and the safe answer is not to be public at all.
  internal        = true
  subnets         = aws_subnet.private[*].id
  security_groups = [aws_security_group.alb.id]
  # Every request, kept 14 days (Sonar terraform:S6258, 2026-10-17): what the ALB answered, to whom and how fast, for an
  # incident found later. ELB charges nothing for access logs; S3 stores a few hundred kilobytes a day.
  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    enabled = true
  }
  depends_on = [aws_s3_bucket_policy.alb_logs] # ELB checks it may write before it saves the attribute
}

# ----------------------------------------------------------------- the ALB's access logs
# ⚠ The environment's boundary must allow s3:PutBucketPolicy and s3:PutBucketPublicAccessBlock on
# warden-<env>-alb-logs-* (infra/iam/templates/boundary.json, DenyS3Policy) and the deploy role must hold s3 on those names
# (infra/iam/templates/deploy-ec2.json, AlbLogsBucket) before this applies. force_destroy: the stack is ephemeral, and a
# destroy must not stop on a bucket of logs.
resource "aws_s3_bucket" "alb_logs" {
  bucket_prefix = "${local.name}-alb-logs-"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SSE-S3: the only encryption ELB log delivery supports.
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    id     = "keep-14-days"
    status = "Enabled"
    filter {}
    expiration { days = 14 }
    noncurrent_version_expiration { noncurrent_days = 1 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
  rule {
    id     = "drop-expired-delete-markers"
    status = "Enabled"
    filter {}
    expiration { expired_object_delete_marker = true }
  }
  depends_on = [aws_s3_bucket_versioning.alb_logs]
}

# ELB's log delivery writes as the logdelivery.elasticloadbalancing service principal, AWS's policy for regions available
# from August 2022 - this stack's region (environments.yaml) among them. AWS's ALB guide (as quoted in search results,
# 2026-10-21; the page itself is not reachable from here) names it the current policy and keeps an older one, the
# region's ELB account as principal, for regions available before August 2022. That form cannot be written for this
# region at all: the provider's aws_elb_service_account has no account for regions after August 2022 and fails there
# (terraform-provider-aws v6.66.0, internal/service/elb/service_account_data_source.go, read 2026-10-21). An apply in
# a pre-2022 region that refused this policy would fail loudly at the ALB's access_logs. For this account's load
# balancers only; S3's own access logs of this bucket under s3-access/; TLS only.
resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "OnlyOverTls"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.alb_logs.arn, "${aws_s3_bucket.alb_logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "ElbAccessLogs"
        Effect    = "Allow"
        Principal = { Service = "logdelivery.elasticloadbalancing.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.alb_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
      },
      {
        Sid       = "S3ServerAccessLogs"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.alb_logs.arn}/s3-access/*"
        Condition = {
          ArnLike      = { "aws:SourceArn" = aws_s3_bucket.alb_logs.arn }
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      },
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.alb_logs]
}

# The log bucket's own access logs, into itself under s3-access/: AWS allows a bucket to be its own target (each
# delivery then logs the one before - a trickle, expired with the rest after 14 days), and a second bucket only to log
# the first would be one more thing to create and destroy.
resource "aws_s3_bucket_logging" "alb_logs" {
  bucket        = aws_s3_bucket.alb_logs.id
  target_bucket = aws_s3_bucket.alb_logs.id
  target_prefix = "s3-access/"
  depends_on    = [aws_s3_bucket_policy.alb_logs]
}

resource "aws_lb_target_group" "orders" {
  name                 = "${local.name}-orders"
  port                 = 8080
  protocol             = "HTTPS" # the tasks serve HTTPS themselves (owner row 25); the ALB does not verify their certificate
  target_type          = "ip"
  vpc_id               = aws_vpc.this.id
  deregistration_delay = 10
  health_check {
    protocol            = "HTTPS"
    path                = "/health" # fs-19 changes it to /healthz
    matcher             = "200"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
  }
}

# HTTPS inside the VPC too (Sonar terraform:S5332, 2026-10-17). The ALB has no domain, so no public certificate: the
# stack makes its own - a self-signed ECDSA P-256 certificate for the ALB's DNS name - and imports it into ACM, which
# charges nothing for an imported certificate. Its one caller, the traffic Lambda, trusts exactly this certificate
# (ALB_CA_PEM, lambda.tf) and verifies the name, so a man in the middle has nothing to offer it. The private key is in
# the state, as every secret this stack generates; it protects synthetic shop traffic only. Two years, renewed by the
# first apply in its last 30 days (create_before_destroy: the listener moves to the new one first).
resource "tls_private_key" "alb" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "alb" {
  private_key_pem = tls_private_key.alb.private_key_pem
  subject {
    common_name = "${local.name}-orders-alb" # a name, not the DNS name: a CN holds 64 characters at most
  }
  dns_names             = [aws_lb.orders.dns_name]
  validity_period_hours = 17520
  early_renewal_hours   = 720
  allowed_uses          = ["digital_signature", "server_auth"]
}

resource "aws_acm_certificate" "alb" {
  private_key      = tls_private_key.alb.private_key_pem
  certificate_body = tls_self_signed_cert.alb.cert_pem
  lifecycle {
    create_before_destroy = true
  }
}

moved {
  from = aws_lb_listener.http
  to   = aws_lb_listener.https
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.orders.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.alb.arn
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
  propagate_tags                    = "SERVICE" # tasks carry Project/Environment too
  enable_ecs_managed_tags           = true

  # 50/100: a rollout replaces one task at a time, so a revision that cannot start shows up as
  # 1 of 2 healthy instead of hiding behind the old tasks. No circuit breaker: an automatic
  # rollback would undo the fault before anything read it.
  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 100

  network_configuration {
    subnets         = aws_subnet.private[*].id
    security_groups = [aws_security_group.ecs.id]
    # Private: no public IP. There are no ECR interface endpoints and the placeholder image is on
    # public.ecr.aws, so image pulls go through the NAT (only S3 has a gateway endpoint); the rest of
    # the egress uses the NAT the stack already has, so this adds no fixed cost.
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.orders.arn
    container_name   = "orders-api"
    container_port   = 8080
  }

  lifecycle {
    ignore_changes = [task_definition, desired_count] # the APPS pipeline and the harness own these
  }

  depends_on = [aws_lb_listener.https, aws_iam_role_policy_attachment.ecs_execution]
}
