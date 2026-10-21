# RDS PostgreSQL — proves that WARDEN's existing database backend works against RDS.
#
# ⛔ NOT CREATED BY DEFAULT (`enable_rds = false`). Only Wave 3 touches a database, and an instance
# that exists during an ECS-only run is pure cost plus a month-sized tail risk if a destroy fails.
#
# There is nothing AWS-specific to write for this: RDS speaks the ordinary PostgreSQL wire
# protocol, so `WARDEN_BACKEND=postgres` with the instance endpoint in the DSN is the whole
# integration. Worth stating plainly rather than implying a bespoke RDS backend exists.
#
# Cheapest instance that actually exists: db.t4g.micro (Graviton), 20 GB gp2, single AZ, 7 days of automated
# backups (deleted with the instance). The first three are wrong for production and right for an instance that lives
# for an hour. On an
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
  description = "Proving-ground database. PostgreSQL from the database tunnel only."
  vpc_id      = aws_vpc.this.id

  ingress {
    # ⚠ No apostrophe, deliberately. EC2 rejects any rule description outside
    # [0-9A-Za-z_ .:/()#,@[]+=&;{}!$*-], and `terraform validate` does NOT catch it - it fails at
    # plan against the live API. "operator's" shipped here once; tests/test_terraform_descriptions.py
    # now fails before that can happen again. Inline, so db-06 (scenarios/ops_db.py) revokes and re-authorises it
    # exactly as declared and a later plan sees no drift.
    description     = "PostgreSQL from the database tunnel only, and nowhere else."
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.db_tunnel[0].id]
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

  # Private (Sonar terraform:S8793, owner 2026-10-21): no public address; the operator reaches it through the SSM
  # port-forward in db_tunnel.tf, and PostgreSQL 16 on RDS refuses a connection without TLS (rds.force_ssl defaults to 1
  # from 15 on).
  db_subnet_group_name   = aws_db_subnet_group.this[0].name
  vpc_security_group_ids = [aws_security_group.db[0].id]
  publicly_accessible    = false

  # Seven days of automated backups (Sonar terraform:S6364, owner 2026-10-20). No extra cost: RDS keeps backup storage
  # up to the database's size free, and a destroy deletes the automated backups with the instance
  # (delete_automated_backups defaults to true; skip_final_snapshot below leaves no snapshot either). Developers report
  # that AWS Free plan accounts refuse more than 1 day (FreeTierRestrictionError); no AWS page says so (searched
  # 2026-10-20), so the rule's 7 days stand, and an apply on such an account fails loudly at create, before any cost.
  multi_az                 = false
  backup_retention_period  = 7
  delete_automated_backups = true
  skip_final_snapshot      = true # ⛔ without this, `terraform destroy` FAILS and leaves the bill running
  deletion_protection      = false
  apply_immediately        = true

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
