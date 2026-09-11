# The proving ground: a throwaway VPC with real ECS, RDS and EKS in it, so WARDEN can be run
# against live AWS instead of recorded fixtures.
#
# ⛔ This is NOT how to run WARDEN in production. Read terraform/proving-ground/README.md for the
# cost sheet and for the one deliberate deviation (public subnets, no NAT Gateway).

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws    = { source = "hashicorp/aws", version = ">= 5.40" }
    random = { source = "hashicorp/random", version = ">= 3.6" }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = local.tags
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

resource "random_id" "suffix" {
  byte_length = 3
}

locals {
  name = "${var.name}-${random_id.suffix.hex}"

  tags = {
    # Every resource carries these. If a destroy half-fails, this is how the leftovers are
    # found — see the README's resourcegroupstaggingapi query.
    Project   = "warden-proving-ground"
    ManagedBy = "terraform"
    # ⛔ There was a `DeleteAfter = formatdate(..., timeadd(timestamp(), "24h"))` here. It broke
    # every apply that used a saved plan:
    #
    #     Error: Provider produced inconsistent final plan ... .tags_all: new element "Project"
    #     has appeared. This is a bug in the provider  <- it was not
    #
    # `timestamp()` is evaluated at APPLY time, so it returns a different value than the one the
    # plan recorded, and `tags_all` then mismatches on every resource. A bare `terraform apply`
    # evaluates once and hides it; `plan -out=FILE` followed by `apply FILE` does not. The error
    # blames the provider, which sends you to the wrong issue tracker.
    #
    # Nothing read the tag. `Project` is what the teardown sweep queries and the $5 budget is what
    # actually catches a forgotten environment, so the date was a nicety that cost a real apply.
    Lifecycle = "ephemeral"
  }

  # Two AZs: RDS subnet groups and EKS both require it. No third — it buys nothing here and every
  # subnet is another thing a destroy can get stuck on.
  azs = slice(data.aws_availability_zones.available.names, 0, 2)

  # The ECS service is named `checkout` because that is the service name in the bundled incidents,
  # so `warden run --incident inc-002` points at it with no override.
  service_name = "checkout"

  # The ceiling every role must carry; null when no boundary is in use. See var.permissions_boundary_name.
  permissions_boundary = var.permissions_boundary_name == "" ? null : (
    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/${var.permissions_boundary_name}"
  )
  log_group = "/ecs/${local.service_name}"
}

# --------------------------------------------------------------------------- network
#
# Public subnets with public IPs, deliberately. A private-subnet design needs a NAT Gateway, which
# at $0.045/hour costs more than every other resource in this directory combined and is the usual
# cause of a surprise bill. Exposure is bounded by security groups scoped to var.my_ip_cidr.

resource "aws_vpc" "this" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true # RDS endpoints and the EKS API are resolved by name
  tags                 = { Name = local.name }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = local.name }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(aws_vpc.this.cidr_block, 8, count.index)
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${local.name}-public-${count.index}"
    # EKS looks for this tag to decide where it may place load balancers. Harmless if unused.
    "kubernetes.io/role/elb" = "1"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = { Name = local.name }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# --------------------------------------------------------------------------- budget
#
# The cheapest insurance in this directory: free, and it is what tells you an EKS cluster survived
# a failed destroy. Notifications are on FORECASTED spend as well as actual, because by the time
# actual spend crosses $5 the cluster has already been up for two days.

resource "aws_budgets_budget" "guard" {
  name         = "${local.name}-guard"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = [
      { type = "FORECASTED", threshold = 60 },
      { type = "FORECASTED", threshold = 90 },
      { type = "ACTUAL", threshold = 100 },
    ]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value.threshold
      threshold_type             = "PERCENTAGE"
      notification_type          = notification.value.type
      subscriber_email_addresses = [var.budget_email]
    }
  }
}
