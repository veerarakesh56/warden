# The runtime's own network (G6): two availability zones, a private subnet in each for the workers, Lambdas and the
# audit database, a public one in each for the way out. One NAT gateway (a lab's size: one zone's outage cuts egress -
# Temporal Cloud, the model, Slack - not the database; two NAT gateways for production, `nat_gateways = 2`). An S3
# gateway endpoint (free) keeps the image layers and the anchors off the NAT. Tags come from the provider's
# default_tags, which the environment boundary requires on every network resource.
variable "vpc_cidr" {
  description = "The runtime VPC's address range."
  type        = string
  default     = "10.42.0.0/16"
}

variable "nat_gateways" {
  description = "1 for a lab window, 2 for production (one per zone)."
  type        = number
  default     = 1
  validation {
    condition     = contains([1, 2], var.nat_gateways)
    error_message = "nat_gateways is 1 or 2."
  }
}

data "aws_availability_zones" "here" {
  state = "available"
}

locals {
  zones = slice(data.aws_availability_zones.here.names, 0, 2)
}

resource "aws_vpc" "runtime" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "warden-${local.env}-runtime" }
}

resource "aws_subnet" "public" {
  count             = 2
  vpc_id            = aws_vpc.runtime.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = local.zones[count.index]
  tags              = { Name = "warden-${local.env}-public-${count.index}" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.runtime.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 10 + count.index)
  availability_zone = local.zones[count.index]
  tags              = { Name = "warden-${local.env}-private-${count.index}" }
}

resource "aws_internet_gateway" "runtime" {
  vpc_id = aws_vpc.runtime.id
  tags   = { Name = "warden-${local.env}-runtime" }
}

resource "aws_eip" "nat" {
  count  = local.paused ? 0 : var.nat_gateways # paused: no egress, no NAT to pay for
  domain = "vpc"
  tags   = { Name = "warden-${local.env}-nat-${count.index}" }
}

resource "aws_nat_gateway" "runtime" {
  count         = local.paused ? 0 : var.nat_gateways
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  tags          = { Name = "warden-${local.env}-nat-${count.index}" }
  depends_on    = [aws_internet_gateway.runtime]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.runtime.id
  tags   = { Name = "warden-${local.env}-public" }
}

resource "aws_route" "public_out" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.runtime.id
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  count  = 2
  vpc_id = aws_vpc.runtime.id
  tags   = { Name = "warden-${local.env}-private-${count.index}" }
}

resource "aws_route" "private_out" {
  count                  = local.paused ? 0 : 2
  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.runtime[min(count.index, var.nat_gateways - 1)].id
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.runtime.id
  service_name      = "com.amazonaws.${local.config.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.private[*].id
  tags              = { Name = "warden-${local.env}-s3" }
}
