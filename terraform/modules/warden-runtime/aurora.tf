# The shared audit (G6): every worker and Lambda appends to one hash chain here (src/warden/audit.py, PostgreSQL).
# Register O4: automated backups with point-in-time recovery, deletion protection, a final snapshot, encryption; the
# restore drill is window W2's. The master password is managed by RDS in Secrets Manager; the runtime's own user
# (SELECT and INSERT only) comes from `warden audit migrate`. Serverless v2 pauses to 0 capacity when idle.
resource "aws_db_subnet_group" "audit" {
  name_prefix = "warden-${var.environment}-audit-"
  subnet_ids  = var.private_subnet_ids
  tags        = { Project = "warden", Environment = var.environment }
}

resource "aws_rds_cluster" "audit" {
  count                               = var.aws_free_plan ? 0 : 1
  cluster_identifier                  = "warden-${var.environment}-audit"
  engine                              = "aurora-postgresql"
  engine_mode                         = "provisioned"
  engine_version                      = var.audit_db_engine_version
  database_name                       = "warden_audit"
  master_username                     = "warden_admin"
  manage_master_user_password         = true
  iam_database_authentication_enabled = true
  storage_encrypted                   = true
  backup_retention_period             = var.audit_db_backup_days
  preferred_backup_window             = "20:00-21:00" # UTC: 01:30-02:30 IST
  copy_tags_to_snapshot               = true
  deletion_protection                 = true
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "warden-${var.environment}-audit-final"
  db_subnet_group_name                = aws_db_subnet_group.audit.name
  vpc_security_group_ids              = [aws_security_group.audit_db.id]
  enabled_cloudwatch_logs_exports     = ["postgresql"]
  serverlessv2_scaling_configuration {
    min_capacity             = 0
    max_capacity             = var.audit_db_max_acu
    seconds_until_auto_pause = 3600
  }
  tags = { Project = "warden", Environment = var.environment }
}

resource "aws_rds_cluster_instance" "audit" {
  count              = var.aws_free_plan ? 0 : var.audit_db_instances
  identifier         = "warden-${var.environment}-audit-${count.index}"
  cluster_identifier = aws_rds_cluster.audit[0].id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.audit[0].engine
  engine_version     = aws_rds_cluster.audit[0].engine_version
  tags               = { Project = "warden", Environment = var.environment }
}

# The AWS Free plan creates Aurora only "WithExpressConfiguration" (FreeTierRestrictionError, 2026-10-09; already
# recorded for Wave 4 in terraform/fullstack/aurora_express.py): no VPC, reachable through an internet gateway, and not
# settable from the AWS provider. A lab on that plan gets one RDS PostgreSQL instance instead (a Free plan class), in the
# same private subnets and security group, with the same protections - one AZ, no reader. Never in production.
resource "aws_db_instance" "audit" {
  count                               = var.aws_free_plan ? 1 : 0
  identifier                          = "warden-${var.environment}-audit"
  engine                              = "postgres"
  engine_version                      = split(".", var.audit_db_engine_version)[0] # the major; RDS picks its minor
  instance_class                      = "db.t4g.micro"
  allocated_storage                   = 20
  storage_type                        = "gp3"
  db_name                             = "warden_audit"
  username                            = "warden_admin"
  manage_master_user_password         = true
  iam_database_authentication_enabled = true
  storage_encrypted                   = true
  backup_retention_period             = var.audit_db_backup_days
  backup_window                       = "20:00-21:00" # UTC: 01:30-02:30 IST
  copy_tags_to_snapshot               = true
  deletion_protection                 = true
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "warden-${var.environment}-audit-final"
  db_subnet_group_name                = aws_db_subnet_group.audit.name
  vpc_security_group_ids              = [aws_security_group.audit_db.id]
  publicly_accessible                 = false
  enabled_cloudwatch_logs_exports     = ["postgresql"]
  tags                                = { Project = "warden", Environment = var.environment }
}

# What the rest of the module reads, from whichever of the two exists.
locals {
  audit_db = var.aws_free_plan ? {
    host          = aws_db_instance.audit[0].address
    database      = aws_db_instance.audit[0].db_name
    resource_id   = aws_db_instance.audit[0].resource_id
    master_secret = aws_db_instance.audit[0].master_user_secret[0].secret_arn
    } : {
    host          = aws_rds_cluster.audit[0].endpoint
    database      = aws_rds_cluster.audit[0].database_name
    resource_id   = aws_rds_cluster.audit[0].cluster_resource_id
    master_secret = aws_rds_cluster.audit[0].master_user_secret[0].secret_arn
  }
}
