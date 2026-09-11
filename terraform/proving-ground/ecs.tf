# ECS: the thing WARDEN's `aws` backend actually reads.
#
# THREE task definition revisions are registered here, and the count is not arbitrary:
#
#   revision 1  HEALTHY   - sleeps quietly and logs a heartbeat
#   revision 2  HEALTHY   - byte-for-byte identical to revision 1
#   revision 3  BAD       - a DIFFERENT image, and it allocates more memory than the task is given
#
# ⭐ Revision 2 exists because the service must start on a revision that HAS a predecessor.
# WARDEN calls something a deploy only when the running revision's images differ from the previous
# revision's, and on revision 1 there is nothing to compare against — so a service left on
# revision 1 would report its first rollout as a deploy and the restart test below could not
# distinguish anything. Starting on revision 2 is what makes the comparison real.
#
# It is also the most common thing that actually happens in a pipeline: **CI re-registers a task
# definition on every run whether or not anything changed.** Revision 2 is that, exactly.
#
# `scripts/aws_proof.sh` then stages three situations, and the middle one is the point:
#
#   A  healthy, on revision 2  -> real task counts and real CloudWatch metrics, and NO deploy:
#                                 revision 2 is a re-registration of revision 1, not a change
#   B  --force-new-deployment  -> a NEW deployment record, same revision, same images. Still NO
#                                 deploy, so policy P5 is not handed evidence for a rollback that
#                                 could not possibly help
#   C  switch to revision 3    -> a REAL image change plus real OOM kills, so the rollback is both
#                                 proposed and permitted
#
# Staging a real OOM rather than writing "OOM" into a log line is the whole point: the evidence is
# produced by ECS and CloudWatch, not by us.

resource "aws_cloudwatch_log_group" "service" {
  name              = local.log_group
  retention_in_days = 1 # a throwaway environment; retention is a cost, not a feature, here
}

resource "aws_ecs_cluster" "this" {
  name = local.name

  setting {
    name  = "containerInsights"
    value = "disabled" # Container Insights is billed per metric; the free AWS/ECS metrics suffice
  }
}

resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name       = aws_ecs_cluster.this.name
  capacity_providers = ["FARGATE_SPOT", "FARGATE"]

  default_capacity_provider_strategy {
    # Spot by default, because a task that gets reclaimed mid-proof is a realistic incident rather
    # than a problem, and it is roughly 70% cheaper. Overridable because Spot is not available in
    # every region - see var.capacity_provider.
    capacity_provider = var.capacity_provider
    weight            = 1
  }
}

resource "aws_iam_role" "task_execution" {
  permissions_boundary = local.permissions_boundary
  name                 = "${local.name}-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "task_execution" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_security_group" "service" {
  name        = "${local.name}-service"
  description = "Proving-ground workload. Egress only - nothing connects to it."
  vpc_id      = aws_vpc.this.id

  egress {
    description = "Image pull and CloudWatch Logs."
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

locals {
  # 512 MiB task. The bad revision asks for 900 MiB inside it, so the kill is certain rather than
  # probabilistic - a flaky incident is worse than no incident.
  task_memory_mib = 512

  healthy_command = [
    "python", "-u", "-c",
    "import time,sys\nprint('checkout: started, healthy', flush=True)\nwhile True:\n    print('checkout: heartbeat ok', flush=True)\n    time.sleep(15)\n",
  ]

  # ⚠ Reads as a crash, and is meant to. The allocation is written so the log line lands BEFORE the
  # kernel takes the process, otherwise CloudWatch shows a container that died saying nothing.
  oom_command = [
    "python", "-u", "-c",
    "import time\nprint('checkout: started, build 2.0.0', flush=True)\nprint('checkout: WARN allocating cache, memory pressure rising', flush=True)\ntime.sleep(2)\nprint('checkout: allocating 900MiB cache', flush=True)\ntime.sleep(1)\nblob = bytearray(900*1024*1024)\nprint('unreachable', flush=True)\n",
  ]
}

resource "aws_ecs_task_definition" "healthy" {
  family                   = local.service_name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = tostring(local.task_memory_mib)
  execution_role_arn       = aws_iam_role.task_execution.arn

  container_definitions = jsonencode([{
    name      = local.service_name
    image     = var.healthy_image
    essential = true
    command   = local.healthy_command
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.service.name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])
}

# Revision 2: identical to revision 1, on purpose. This is what a CI pipeline does on every run.
# ⛔ Do not "clean this up" by deleting it — the service points here, and the restart test in
# situation B is meaningless without a predecessor to compare against.
resource "aws_ecs_task_definition" "healthy_reregistered" {
  family                   = local.service_name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = tostring(local.task_memory_mib)
  execution_role_arn       = aws_iam_role.task_execution.arn
  depends_on               = [aws_ecs_task_definition.healthy] # revision order must be 1 then 2

  container_definitions = jsonencode([{
    name      = local.service_name
    image     = var.healthy_image
    essential = true
    command   = local.healthy_command
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.service.name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])
}

# Revision 3, the BAD one. Terraform registers it but nothing points at it: the proof script
# switches the service over deliberately, so the environment comes up healthy and the failure has
# a timestamp.
#
# ⭐ The IMAGE TAG differs from the healthy revisions (`:3.12-alpine` vs `:3.12.7-alpine`) and that
# is load-bearing, not cosmetic. WARDEN calls a deploy only when the images differ between
# revisions; if this carried the same image string it would read as a restart and the whole point
# of situation C would be lost.
resource "aws_ecs_task_definition" "bad" {
  family                   = local.service_name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = tostring(local.task_memory_mib)
  execution_role_arn       = aws_iam_role.task_execution.arn
  depends_on               = [aws_ecs_task_definition.healthy_reregistered] # 1, then 2, then 3

  container_definitions = jsonencode([{
    name      = local.service_name
    image     = "public.ecr.aws/docker/library/python:3.12.7-alpine"
    essential = true
    command   = local.oom_command
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.service.name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])
}

resource "aws_ecs_service" "checkout" {
  name            = local.service_name
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.healthy_reregistered.arn # revision 2, see above
  desired_count   = 2                                                # two, so "1 of 2 running" is visible when one is killed

  capacity_provider_strategy {
    capacity_provider = var.capacity_provider
    weight            = 1
  }

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.service.id]
    assign_public_ip = true # no NAT Gateway; see the README
  }

  # The proof script changes the task definition out from under Terraform on purpose. Without this
  # the next plan would try to roll it back, and `terraform destroy` would fight the demo.
  lifecycle {
    ignore_changes = [task_definition, desired_count]
  }

  depends_on = [aws_ecs_cluster_capacity_providers.this]
}
