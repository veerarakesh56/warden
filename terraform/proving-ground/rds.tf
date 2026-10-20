# RDS PostgreSQL — proves that WARDEN's existing database backend works against RDS.
#
# ⛔ NOT CREATED BY DEFAULT (`enable_rds = false`). Only Wave 3 touches a database, and an instance
# that exists during an ECS-only run is pure cost plus a month-sized tail risk if a destroy fails.
#
# There is nothing AWS-specific to write for this: RDS speaks the ordinary PostgreSQL wire
# protocol, so `WARDEN_BACKEND=postgres` with the instance endpoint in the DSN is the whole
# integration. Worth stating plainly rather than implying a bespoke RDS backend exists.
#
# Cheapest instance that actually exists: db.t4g.micro (Graviton), 20 GB gp2, single AZ, no backups.
# Every one of those is wrong for production and right for an instance that lives for an hour. On an
# account under 12 months old the free tier covers it entirely. Encrypted at rest with the AWS-managed
# key (2026-10-16, Sonar terraform:S6303): it costs nothing and leaves nothing to clean up.

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
    # ⚠ No apostrophe, deliberately. EC2 rejects any rule description outside
    # [0-9A-Za-z_ .:/()#,@[]+=&;{}!$*-], and `terraform validate` does NOT catch it - it fails at
    # plan against the live API. "operator's" shipped here once; tests/test_terraform_descriptions.py
    # now fails before that can happen again.
    description = "PostgreSQL from the operator address only, and nowhere else."
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
  storage_encrypted = true # aws/rds, the AWS-managed key: no key to create, pay for or delete
  # On an instance created before 2026-10-16 this replaces it with a new, empty database: run
  # scripts/setup_proving_ground_db.py again, so the harness's sentinel guard marks the new one (CodeRabbit, PR 46).

  db_name  = "warden"
  username = "warden"
  password = var.db_password
  port     = 5432

  # Public on purpose (Sonar terraform:S8793, by design - owner to review; tests/test_iac_leftovers_sonar.py holds every
  # point): WARDEN runs on the operator's laptop and reaches the database directly, and a private one needs a NAT
  # Gateway or a bastion, both billed. What stands in for private: the stack is off unless enable_rds = true, the
  # security group above admits 5432 from the operator's one address only, the master password is 16+ characters
  # from a per-run generator (precondition below), PostgreSQL 16 on RDS refuses a connection without TLS
  # (rds.force_ssl defaults to 1 from 15 on), and the instance lives for one session.
  db_subnet_group_name   = aws_db_subnet_group.this[0].name
  vpc_security_group_ids = [aws_security_group.db[0].id]
  publicly_accessible    = true # no NAT Gateway and no bastion; bounded by the SG above

  # ⛔ No backups (Sonar terraform:S6364, by design - owner to review): the AWS Free plan refuses any retention over
  # 1 day (FreeTierRestrictionError), so the rule's 7 days cannot be had here at any setting, and the instance holds
  # nothing but the benchmark's own rows for one session. 0 also keeps destroy fast and leaves no backup behind.
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
      error_message = "enable_rds = true requires db_password (>= 16 chars). Generate it into TF_VAR_db_password: export TF_VAR_db_password=\"$(python -c 'import secrets; print(secrets.token_urlsafe(24))')\". Never -var (shell history) and never a tfvars file."
    }
  }
}
