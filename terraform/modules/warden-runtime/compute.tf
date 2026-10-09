# The worker (G6; requirement R20: ECS on an EC2 capacity provider, not Fargate): one service per trust zone (register
# S15), each `warden worker --zone <zone>` from the runtime image with its own task role (iam.tf), in the private
# subnets of at least two availability zones. The instances' metadata service needs a session token and is one hop
# away, and tasks are blocked from it entirely (ECS_AWSVPC_BLOCK_IMDS), so a task holds only its own zone's role, which
# writes nothing itself. The task's root filesystem is read-only, as the non-root user.
data "aws_ssm_parameter" "ecs_ami" {
  # AWS's own pointer to the current ECS-optimized Amazon Linux 2023 image.
  name = "/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
}

resource "aws_ecs_cluster" "runtime" {
  # warden-<env>-*: the environment boundary lets its deploy role touch ECS services in such clusters only.
  name = "warden-${var.environment}-runtime"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  tags = { Project = "warden", Environment = var.environment }
}

data "aws_iam_policy_document" "ec2_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name                 = "warden-${var.environment}-ecs-instance"
  permissions_boundary = var.permissions_boundary_arn
  description          = "WARDEN ${var.environment}: the ECS container instances (registering with the cluster only)"
  assume_role_policy   = data.aws_iam_policy_document.ec2_trust.json
  tags                 = { Project = "warden", Environment = var.environment }
}

resource "aws_iam_role_policy_attachment" "instance" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

resource "aws_iam_instance_profile" "instance" {
  name = "warden-${var.environment}-ecs-instance"
  role = aws_iam_role.instance.name
}

resource "aws_security_group" "instances" {
  name_prefix = "warden-${var.environment}-instances-"
  description = "WARDEN ${var.environment}: ECS container instances (the ECS agent reaches AWS over HTTPS)"
  vpc_id      = var.vpc_id
  egress {
    description = "HTTPS out: the ECS and ECR endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Project = "warden", Environment = var.environment }
}

resource "aws_launch_template" "instances" {
  name_prefix            = "warden-${var.environment}-"
  image_id               = data.aws_ssm_parameter.ecs_ami.value
  instance_type          = var.worker_instance_types[0]
  vpc_security_group_ids = [aws_security_group.instances.id]
  iam_instance_profile {
    arn = aws_iam_instance_profile.instance.arn
  }
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      encrypted   = true
      volume_type = "gp3"
      volume_size = 30
    }
  }
  user_data = base64encode(<<-EOT
    #!/bin/bash
    cat >> /etc/ecs/ecs.config <<'CFG'
    ECS_CLUSTER=${aws_ecs_cluster.runtime.name}
    ECS_AWSVPC_BLOCK_IMDS=true
    ECS_ENABLE_TASK_IAM_ROLE=true
    CFG
  EOT
  )
  tag_specifications {
    resource_type = "instance"
    tags          = { Project = "warden", Environment = var.environment, Name = "warden-${var.environment}-ecs" }
  }
}

# Paused (var.paused), the group, its capacity provider and the services are removed, the instances force-deleted:
# with no task ECS managed scaling kept CapacityProviderReservation at 100 and never scaled in (2026-10-10).
resource "aws_autoscaling_group" "instances" {
  count               = var.paused ? 0 : 1
  name_prefix         = "warden-${var.environment}-"
  force_delete        = true # its instances carry scale-in protection; removing the group must not wait on them
  vpc_zone_identifier = var.private_subnet_ids
  # Each task has its own network interface (awsvpc), so an instance holds only worker_tasks_per_instance tasks (2 on a
  # large type without ENI trunking): enough instances for every zone's tasks, plus one for a rolling deployment. The
  # capacity provider scales between min and max (2026-10-09: max = workers + 1 left a zone's task pending).
  min_size              = var.worker_instances
  max_size              = ceil(length(var.zone_sizes) * var.worker_instances / var.worker_tasks_per_instance) + 1
  desired_capacity      = var.worker_instances
  protect_from_scale_in = true
  mixed_instances_policy {
    instances_distribution {
      on_demand_allocation_strategy            = "prioritized" # the list's order
      on_demand_base_capacity                  = 0
      on_demand_percentage_above_base_capacity = 100 # on-demand only (the boundary denies spot)
    }
    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.instances.id
        version            = "$Latest"
      }
      dynamic "override" {
        for_each = var.worker_instance_types
        content {
          instance_type = override.value
        }
      }
    }
  }
  tag {
    key                 = "AmazonECSManaged"
    value               = "true"
    propagate_at_launch = true
  }
  lifecycle {
    ignore_changes = [desired_capacity] # the capacity provider scales it
  }
}

resource "aws_ecs_capacity_provider" "instances" {
  count = var.paused ? 0 : 1
  name  = "warden-${var.environment}-ec2"
  auto_scaling_group_provider {
    auto_scaling_group_arn         = aws_autoscaling_group.instances[0].arn
    managed_termination_protection = "ENABLED"
    managed_scaling {
      status          = "ENABLED"
      target_capacity = 100
    }
  }
  tags = { Project = "warden", Environment = var.environment }
}

resource "aws_ecs_cluster_capacity_providers" "runtime" {
  count              = var.paused ? 0 : 1
  cluster_name       = aws_ecs_cluster.runtime.name
  capacity_providers = [aws_ecs_capacity_provider.instances[0].name]
  default_capacity_provider_strategy {
    capacity_provider = aws_ecs_capacity_provider.instances[0].name
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
  requires_compatibilities = ["EC2"]
  cpu                      = var.zone_sizes[each.key].cpu
  memory                   = var.zone_sizes[each.key].memory
  task_role_arn            = aws_iam_role.zone[each.key].arn
  execution_role_arn       = aws_iam_role.execution.arn
  container_definitions = jsonencode([{
    name      = "worker"
    image     = var.runtime_image
    essential = true
    # The AWS platform where a zone reads or writes a watched environment; none where it cannot (iam.tf).
    command                = ["worker", "--zone", each.key, "--platform", length(each.value.assumes) > 0 ? "aws" : "none"]
    user                   = "10001"
    readonlyRootFilesystem = true
    linuxParameters        = { tmpfs = [{ containerPath = "/tmp", size = 256 }] }
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
      # The notify zone posts for real - the only zone that does. chatops.py is dry-run unless this is set, and it is
      # never loaded from SSM; without it every report was dropped silently (2026-10-09).
      each.key == "notify" ? { WARDEN_CHATOPS_LIVE = "1" } : {},
      # The read zone gathers the evidence: live AWS, through each watched environment's reader role (aws_backend.py).
      each.key == "read" ? { WARDEN_BACKEND = "aws" } : {}) :
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
  capacity_provider_strategy {
    capacity_provider = aws_ecs_capacity_provider.instances[0].name
    weight            = 1
  }
  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.runtime.id]
  }
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  # One task of each zone per instance, the instances spread over the subnets' availability zones: losing one
  # instance loses one task of each zone, never a zone.
  placement_constraints {
    type = "distinctInstance"
  }
  propagate_tags = "SERVICE"
  tags           = { Project = "warden", Environment = var.environment }
  depends_on     = [aws_ecs_cluster_capacity_providers.runtime]
}

# One instance of each, before the paused switch made them counted (2026-10-10).
moved {
  from = aws_autoscaling_group.instances
  to   = aws_autoscaling_group.instances[0]
}

moved {
  from = aws_ecs_capacity_provider.instances
  to   = aws_ecs_capacity_provider.instances[0]
}

moved {
  from = aws_ecs_cluster_capacity_providers.runtime
  to   = aws_ecs_cluster_capacity_providers.runtime[0]
}
