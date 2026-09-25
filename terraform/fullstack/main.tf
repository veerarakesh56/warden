# Wave 4 - the full stack (docs/WAVE4-FULLSTACK.md section 2). Infrastructure ONLY.
#
# ⛔ Terraform here never builds or deploys application code. Lambdas are created with a
# placeholder zip and ECS with a placeholder container; `scripts/deploy_fullstack_apps.py` (the
# APPS pipeline) owns code, images and everything in Kubernetes. Every code field is in
# `ignore_changes`, so a re-apply never rolls an app back. The product of this directory is
#
#     terraform output -json > ~/warden-fullstack-build/stack.json   (see README: sensitive values stripped)
#
# which the apps pipeline and the harness read. Neither calls terraform.
#
# Everything is named warden-pg-fs-* (the prefix the operator's permissions boundary scopes IAM to)
# and tagged Project=warden-fullstack (what every fault injector checks before it touches anything).

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws     = { source = "hashicorp/aws", version = ">= 5.80" }
    random  = { source = "hashicorp/random", version = ">= 3.6" }
    archive = { source = "hashicorp/archive", version = ">= 2.4" }
  }
  # No backend block on purpose: a local apply keeps local state. CI writes a backend_override.tf
  # (S3) before init - see .github/workflows/infra.yml.
}

provider "aws" {
  region = var.region
  default_tags {
    tags = local.tags
  }
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  name = "warden-pg-fs"
  tags = {
    Project   = "warden-fullstack"
    ManagedBy = "terraform"
    Lifecycle = "ephemeral"
    # No timestamp() tag: it changes between plan and apply and breaks every saved plan
    # (the proving ground learned this the hard way - see terraform/proving-ground/main.tf).
  }
  azs = slice(data.aws_availability_zones.available.names, 0, 2)

  permissions_boundary = var.permissions_boundary_name == "" ? null : (
    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/${var.permissions_boundary_name}"
  )
}

# --------------------------------------------------------------------------- network
#
# Public subnets for everything that needs the internet (ALB, ECS tasks with public IPs, EKS nodes,
# Aurora). Private subnets for ElastiCache and the in-VPC Lambdas. No NAT gateway: the private side
# reaches AWS APIs through endpoints only.

resource "aws_vpc" "this" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true # interface endpoints with private DNS, EKS private endpoint, Aurora
  tags                 = { Name = local.name }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = local.name }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.42.${count.index}.0/24"
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name                     = "${local.name}-public-${count.index}"
    "kubernetes.io/role/elb" = "1"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.this.id
  cidr_block        = "10.42.${10 + count.index}.0/24"
  availability_zone = local.azs[count.index]
  tags              = { Name = "${local.name}-private-${count.index}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = { Name = "${local.name}-public" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${local.name}-private" } # no default route: there is no NAT, by design
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Gateway endpoints are free.
resource "aws_vpc_endpoint" "gateway" {
  for_each          = toset(["s3", "dynamodb"])
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.public.id, aws_route_table.private.id]
  tags              = { Name = "${local.name}-${each.key}" }
}

# Interface endpoints are billed per hour per subnet, so ONE subnet each. Private DNS makes the
# public service names resolve to them for everything in the VPC.
resource "aws_vpc_endpoint" "interface" {
  for_each            = toset(["secretsmanager", "sqs"])
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private[0].id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = { Name = "${local.name}-${each.key}" }
}

# --------------------------------------------------------------------------- security groups
#
# ⚠ Descriptions: EC2 accepts only [0-9A-Za-z_ .:/()#,@[]+=&;{}!$*-]. No apostrophes.
# Rules that a fault revokes (fs-10: Redis ingress from the app SGs) are separate resources, so the
# harness can revoke and restore exactly one rule by id.

resource "aws_security_group" "endpoints" {
  name        = "${local.name}-endpoints"
  description = "Interface endpoints. HTTPS from inside the VPC only."
  vpc_id      = aws_vpc.this.id
  ingress {
    description = "HTTPS from the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.this.cidr_block]
  }
}

resource "aws_security_group" "alb" {
  name        = "${local.name}-alb"
  description = "Orders API load balancer. HTTP from anywhere: the traffic Lambda runs outside the VPC."
  vpc_id      = aws_vpc.this.id
  ingress {
    description = "HTTP from the internet. The API serves synthetic orders only."
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "To the ECS tasks"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.this.cidr_block]
  }
}

resource "aws_security_group" "ecs" {
  name        = "${local.name}-ecs"
  description = "orders-api tasks. 8080 from the load balancer only."
  vpc_id      = aws_vpc.this.id
  ingress {
    description     = "HTTP from the load balancer"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    description = "Image pull, secrets, logs, database and cache"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "lambda" {
  name        = "${local.name}-lambda"
  description = "In-VPC Lambdas. Egress only."
  vpc_id      = aws_vpc.this.id
  egress {
    description = "Database, cache and endpoints"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

locals {
  # The application security groups: what may reach the database and the cache. EKS pods use the
  # cluster security group (VPC CNI puts pods on the node ENIs).
  app_security_groups = {
    ecs    = aws_security_group.ecs.id
    lambda = aws_security_group.lambda.id
    eks    = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
  }
}
