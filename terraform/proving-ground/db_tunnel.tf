# The way to the lab database (Sonar terraform:S8793, owner 2026-10-21): the database is private, and the operator
# reaches it through an AWS Systems Manager port-forward to a t4g.nano in the VPC. Like the database, everything here
# exists only while enable_rds = true, so the lab costs nothing for it when it is off.
#
#   aws ssm start-session --region <region> --target <db_tunnel_instance_id> \
#     --document-name AWS-StartPortForwardingSessionToRemoteHost \
#     --parameters host=<db_endpoint>,portNumber=5432,localPortNumber=<db_tunnel_local_port>
#   (terraform output -raw db_tunnel_command prints exactly this; db_dsn points at that local port)
#
# No SSH key, no inbound rule, no public address: the instance talks only to Systems Manager, through three interface
# endpoints in the VPC (a public IP would be cheaper, and is what Sonar terraform:S6329 refuses), and to the database.
# IMDSv2 only, one hop. Its role holds AWS's managed SSM core policy and nothing else, under the lab's boundary.
#
# Cost while enable_rds = true (AWS Price List API, ap-south-2, read 2026-10-21): t4g.nano $0.0028/h, its 8 GiB gp3
# root ($0.0912 per GB-month) about $0.0010/h, three interface endpoints $0.013/h each - about $0.043/h, about $0.09
# for a two-hour session. Zero when the lab is off.

locals {
  db_tunnel_endpoints = toset(["ssm", "ssmmessages", "ec2messages"])
}

data "aws_ssm_parameter" "db_tunnel_ami" {
  count = var.enable_rds ? 1 : 0
  name  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64" # AWS's own, with the SSM agent
}

data "aws_iam_policy_document" "db_tunnel_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "db_tunnel" {
  count                = var.enable_rds ? 1 : 0
  name                 = "${local.name}-db-tunnel"
  assume_role_policy   = data.aws_iam_policy_document.db_tunnel_assume.json
  permissions_boundary = local.permissions_boundary
}

resource "aws_iam_role_policy_attachment" "db_tunnel_ssm" {
  count      = var.enable_rds ? 1 : 0
  role       = aws_iam_role.db_tunnel[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "db_tunnel" {
  count = var.enable_rds ? 1 : 0
  name  = "${local.name}-db-tunnel"
  role  = aws_iam_role.db_tunnel[0].name
}

resource "aws_security_group" "db_tunnel" {
  count       = var.enable_rds ? 1 : 0
  name        = "${local.name}-db-tunnel"
  description = "The database tunnel. No inbound rule; out to Systems Manager and the database only."
  vpc_id      = aws_vpc.this.id
}

resource "aws_vpc_security_group_egress_rule" "db_tunnel_ssm" {
  count                        = var.enable_rds ? 1 : 0
  security_group_id            = aws_security_group.db_tunnel[0].id
  description                  = "HTTPS to the Systems Manager endpoints in the VPC"
  referenced_security_group_id = aws_security_group.db_tunnel_endpoints[0].id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "db_tunnel_db" {
  count                        = var.enable_rds ? 1 : 0
  security_group_id            = aws_security_group.db_tunnel[0].id
  description                  = "PostgreSQL to the lab database"
  referenced_security_group_id = aws_security_group.db[0].id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_security_group" "db_tunnel_endpoints" {
  count       = var.enable_rds ? 1 : 0
  name        = "${local.name}-db-tunnel-endpoints"
  description = "Systems Manager endpoints. HTTPS from the database tunnel only."
  vpc_id      = aws_vpc.this.id
}

resource "aws_vpc_security_group_ingress_rule" "db_tunnel_endpoints" {
  count                        = var.enable_rds ? 1 : 0
  security_group_id            = aws_security_group.db_tunnel_endpoints[0].id
  description                  = "HTTPS from the database tunnel"
  referenced_security_group_id = aws_security_group.db_tunnel[0].id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_endpoint" "db_tunnel" {
  for_each            = var.enable_rds ? local.db_tunnel_endpoints : toset([])
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${local.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.public[0].id]
  security_group_ids  = [aws_security_group.db_tunnel_endpoints[0].id]
  private_dns_enabled = true
}

resource "aws_instance" "db_tunnel" {
  count                       = var.enable_rds ? 1 : 0
  ami                         = data.aws_ssm_parameter.db_tunnel_ami[0].value
  instance_type               = "t4g.nano"
  subnet_id                   = aws_subnet.public[0].id
  associate_public_ip_address = false
  vpc_security_group_ids      = [aws_security_group.db_tunnel[0].id]
  iam_instance_profile        = aws_iam_instance_profile.db_tunnel[0].name
  monitoring                  = false

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 8 # the AMI's own size, the smallest it boots with
    encrypted             = true
    delete_on_termination = true
  }

  tags       = { Name = "${local.name}-db-tunnel" }
  depends_on = [aws_vpc_endpoint.db_tunnel]
}
