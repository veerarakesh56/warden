# RDS PostgreSQL — proves that WARDEN's existing database backend works against RDS.
#
# ⛔ NOT CREATED BY DEFAULT (`enable_rds = false`). Only Wave 3 touches a database, and an instance
# that exists during an ECS-only run is pure cost plus a month-sized tail risk if a destroy fails.
#
# There is nothing AWS-specific to write for this: RDS speaks the ordinary PostgreSQL wire
# protocol, so `WARDEN_BACKEND=postgres` with the instance endpoint in the DSN is the whole
# integration. Worth stating plainly rather than implying a bespoke RDS backend exists.
#
# Cheapest instance that actually exists: db.t4g.micro (Graviton), 20 GB gp2, single AZ, no backups,
# no encryption at rest. Every one of those is wrong for production and right for an instance that
# lives for an hour. On an account under 12 months old the free tier covers it entirely.

resource "aws_db_subnet_group" "this" {
  count      = var.enable_rds ? 1 : 0
  name       = local.name
  subnet_ids = aws_subnet.public[*].id
}

resource "aws_security_group" "db" {
  count       = var.enable_rds ? 1 : 0
  name        = "${local.name}-db"
  description = "Proving-ground database. PostgreSQL from one IP only."
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "PostgreSQL from the operator's own address, and nowhere else."
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.my_ip_cidr]
  }
}

resource "aws_db_instance" "this" {
  count = var.enable_rds ? 1 : 0

  identifier     = local.name
  engine         = "postgres"
  engine_version = "16"
  instance_class = "db.t4g.micro"

  allocated_storage = 20
  storage_type      = "gp2"
  storage_encrypted = false # a throwaway instance holding no data; KMS would be cost and cleanup

  db_name  = "warden"
  username = "warden"
  password = var.db_password
  port     = 5432

  db_subnet_group_name   = aws_db_subnet_group.this[0].name
  vpc_security_group_ids = [aws_security_group.db[0].id]
  publicly_accessible    = true # no NAT Gateway and no bastion; bounded by the SG above

  multi_az                = false
  backup_retention_period = 0    # ⛔ no backups. Deliberate: it makes destroy fast and free
  skip_final_snapshot     = true # ⛔ without this, `terraform destroy` FAILS and leaves the bill running
  deletion_protection     = false
  apply_immediately       = true

  # A t4g.micro takes about six minutes to come up. Performance Insights and enhanced monitoring are
  # both billable and neither is read by anything here.
  performance_insights_enabled = false
  monitoring_interval          = 0

  lifecycle {
    precondition {
      # ⛔ Fails at plan time rather than creating a database with an empty master password. The
      # password has no default worth having, so the failure must be loud and early.
      condition     = length(var.db_password) >= 16
      error_message = "enable_rds = true requires db_password (>= 16 chars), passed with -var. The harness generates one per run; never put it in a tfvars file."
    }
  }
}
