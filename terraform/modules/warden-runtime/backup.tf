# Audit backups kept at least 180 days (B19, owner decision 2026-10-20). The signed audit chain is the record of every
# action; the anchors in S3 Object Lock prove its integrity but cannot restore its rows. Aurora keeps automated
# backups 35 days at most (audit_db_backup_days), so one AWS Backup copy a month, in a vault of this region with the
# AWS-managed key - no cross-region copy, no continuous backup - carries the record past that.
#
# Kept until a person deletes it: the environment boundary denies rds:DeleteDBClusterSnapshot to every role, this
# backup role included (DenyAlways), so a lifecycle rule could not delete a copy either - none is set. A copy older
# than 180 days is listed for a person (aws backup list-recovery-points-by-backup-vault). Price, ap-south-2 (AWS Price
# List API, read 2026-10-20): USD 0.023 per GB-month of Aurora PostgreSQL backup storage beyond the free allocation
# (the cluster's own size); the audit database is small, so a copy a month is cents. Off with audit_monthly_backup.
locals {
  audit_backup = var.audit_monthly_backup && !var.aws_free_plan ? 1 : 0 # the Free plan's lab instance: not covered
}

resource "aws_backup_vault" "audit" {
  count = local.audit_backup
  name  = "warden-${var.environment}-audit"
  tags  = { Project = "warden", Environment = var.environment }
}

resource "aws_backup_plan" "audit" {
  count = local.audit_backup
  name  = "warden-${var.environment}-audit-monthly"
  rule {
    rule_name         = "monthly"
    target_vault_name = aws_backup_vault.audit[0].name
    # The 1st of each month at 21:00 UTC (02:30 IST): after the automated backup window (20:00-21:00 UTC).
    schedule            = "cron(0 21 1 * ? *)"
    start_window        = 60
    completion_window   = 360
    recovery_point_tags = { Project = "warden", Environment = var.environment }
  }
  tags = { Project = "warden", Environment = var.environment }
}

data "aws_iam_policy_document" "backup_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account]
    }
  }
}

resource "aws_iam_role" "audit_backup" {
  count                = local.audit_backup
  name                 = "warden-${var.environment}-audit-backup"
  permissions_boundary = var.permissions_boundary_arn
  description          = "WARDEN ${var.environment}: AWS Backup's monthly copy of the audit database, nothing else"
  assume_role_policy   = data.aws_iam_policy_document.backup_trust.json
  tags                 = { Project = "warden", Environment = var.environment }
}

# The Aurora part of AWS's own AWSBackupServiceRolePolicyForBackup (v30), on this cluster and this vault only - not the
# managed policy, which reaches every database, table and volume in the account.
resource "aws_iam_role_policy" "audit_backup" {
  count = local.audit_backup
  name  = "warden-${var.environment}-audit-backup"
  role  = aws_iam_role.audit_backup[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SnapshotTheAuditCluster"
        Effect   = "Allow"
        Action   = ["rds:CreateDBClusterSnapshot", "rds:AddTagsToResource"]
        Resource = [local.audit_db.arn, "arn:aws:rds:${local.region}:${local.account}:cluster-snapshot:awsbackup:*"]
      },
      {
        Sid      = "ReadIt"
        Effect   = "Allow"
        Action   = ["rds:DescribeDBClusters", "rds:DescribeDBClusterSnapshots", "rds:ListTagsForResource", "tag:GetResources"]
        Resource = "*"
      },
      {
        Sid      = "IntoTheVault"
        Effect   = "Allow"
        Action   = ["backup:DescribeBackupVault", "backup:CopyIntoBackupVault"]
        Resource = aws_backup_vault.audit[0].arn
      },
      {
        Sid      = "TagTheCopy"
        Effect   = "Allow"
        Action   = "backup:TagResource"
        Resource = "arn:aws:backup:${local.region}:${local.account}:recovery-point:*"
      },
      { Sid = "TheClustersKey", Effect = "Allow", Action = "kms:DescribeKey", Resource = "*" },
      {
        Sid       = "GrantsForTheSnapshotOnly"
        Effect    = "Allow"
        Action    = "kms:CreateGrant"
        Resource  = "*"
        Condition = { Bool = { "kms:GrantIsForAWSResource" = "true" } }
      },
    ]
  })
}

resource "aws_backup_selection" "audit" {
  count        = local.audit_backup
  name         = "audit-cluster"
  plan_id      = aws_backup_plan.audit[0].id
  iam_role_arn = aws_iam_role.audit_backup[0].arn
  resources    = [local.audit_db.arn]
}
