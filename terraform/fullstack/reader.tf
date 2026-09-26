# WARDEN's AWS identity for Wave 4: role `warden-pg-fs-reader`, assumed per run by the harness.
#
# Expects from the other files in this module (declared there, not here):
#   var.permissions_boundary_name, var.region, local.tags, data.aws_caller_identity.current
#
# ⭐ The policy below is EXACTLY the calls src/warden/aws_stack.py makes, plus the ones
# src/warden/aws_backend.py makes (the stack backend reuses it for ECS and for log reads).
# tests/test_aws_stack.py walks both modules' AST and asserts set equality with this list in BOTH
# directions, so the grant can neither fall behind the code (an AccessDenied mid-incident) nor
# drift ahead of it (a standing grant nothing uses). Every action is a read. Deliberately absent:
# secretsmanager:GetSecretValue (DescribeSecret is metadata only), s3:GetObject (the Lambda package
# comes through the pre-signed URL lambda:GetFunction returns, which needs no S3 grant), and
# ssm:GetParameter*. One grant is not an API call: rds-db:connect as warden_ro (see its statement).

data "aws_iam_policy_document" "fs_reader_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type = "AWS"
      # Any principal in this account that is itself allowed to assume it - same trust as the
      # proving-ground reader, for the same reason (laptop or CI OIDC role, no per-run edits).
      identifiers = [data.aws_caller_identity.current.account_id]
    }
  }
}

data "aws_iam_policy_document" "fs_reader" {
  statement {
    sid    = "ReadStack"
    effect = "Allow"
    actions = [
      "cloudwatch:GetMetricData",
      "dynamodb:DescribeTable",
      "ec2:DescribeSecurityGroups",
      "ecs:DescribeServices",
      "ecs:DescribeTaskDefinition",
      "elasticache:DescribeCacheClusters",
      "elasticache:DescribeEvents",
      "elasticache:DescribeReplicationGroups",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetHealth",
      "eks:DescribeCluster",
      "events:DescribeRule",
      "lambda:GetAlias",
      "lambda:GetFunction",
      "lambda:GetFunctionConcurrency",
      "lambda:GetFunctionConfiguration",
      "lambda:ListEventSourceMappings",
      "lambda:ListVersionsByFunction",
      "logs:FilterLogEvents",
      "rds:DescribeDBClusters",
      "rds:DescribeDBInstances",
      "rds:DescribeEvents",
      "secretsmanager:DescribeSecret",
      "sns:ListSubscriptionsByTopic",
      "sqs:GetQueueAttributes",
      "sqs:GetQueueUrl",
      "sts:GetCallerIdentity",
    ]
    resources = ["*"]
  }

  # ⭐ NOT a call WARDEN makes. The harness signs WARDEN's warden_ro database token with THIS role's
  # credentials (scenarios/fullstack_cli.py), so the database login WARDEN uses is authorised by the
  # role WARDEN runs as - and by nothing else. tests/test_aws_stack.py names it as the one exception
  # to "grant exactly what the code calls". User warden_ro holds pg_monitor only (bootstrap.sql).
  statement {
    sid       = "ConnectAsWardenRo"
    effect    = "Allow"
    actions   = ["rds-db:connect"]
    resources = ["arn:aws:rds-db:${var.region}:${data.aws_caller_identity.current.account_id}:dbuser:*/warden_ro"]
  }

  # API Gateway v2 has no per-API read action: `GetApis` is apigateway:GET on the /apis resource.
  statement {
    sid       = "ReadHttpApis"
    effect    = "Allow"
    actions   = ["apigateway:GET"]
    resources = ["arn:aws:apigateway:${var.region}::/apis", "arn:aws:apigateway:${var.region}::/apis/*"]
  }
}

resource "aws_iam_role" "fs_reader" {
  name = "warden-pg-fs-reader"
  permissions_boundary = var.permissions_boundary_name == "" ? null : (
    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/${var.permissions_boundary_name}"
  )
  assume_role_policy   = data.aws_iam_policy_document.fs_reader_assume.json
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role_policy" "fs_reader" {
  name   = "warden-readonly"
  role   = aws_iam_role.fs_reader.id
  policy = data.aws_iam_policy_document.fs_reader.json
}
