# WARDEN's AWS identity for Wave 4: role `warden-dev-reader`, assumed per run by the harness.
#
# Expects from the other files in this module (declared there, not here):
#   local.permissions_boundary, local.region, local.tags, data.aws_caller_identity.current
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

locals {
  reader_arn = "${local.region}:${data.aws_caller_identity.current.account_id}"
}

data "aws_iam_policy_document" "fs_reader" {
  # Scoped to the stack's own names wherever the action takes a resource AND the code passes its identity -
  # AWS's Service Reference, read 2026-10-01 (audit A-I-19: every read was Resource "*"). The arn local is
  # the region and account this stack lives in.
  statement {
    sid    = "ReadOwnStack"
    effect = "Allow"
    actions = [
      "cloudwatch:DescribeAlarms",
      "dynamodb:DescribeTable",
      "ecs:DescribeServices",
      "elasticache:DescribeReplicationGroups",
      "eks:DescribeCluster",
      "events:DescribeRule",
      "lambda:GetAlias",
      "lambda:GetFunction",
      "lambda:GetFunctionConcurrency",
      "lambda:GetFunctionConfiguration",
      "lambda:ListVersionsByFunction",
      "logs:FilterLogEvents",
      "logs:StartQuery",
      "rds:DescribeDBClusters",
      "secretsmanager:DescribeSecret",
      "sns:ListSubscriptionsByTopic",
      "sqs:GetQueueAttributes",
      "sqs:GetQueueUrl",
    ]
    resources = [
      "arn:aws:cloudwatch:${local.reader_arn}:alarm:${local.name}-*",
      "arn:aws:dynamodb:${local.reader_arn}:table/${local.name}-*",
      "arn:aws:ecs:${local.reader_arn}:service/${local.name}-*",
      "arn:aws:elasticache:${local.reader_arn}:replicationgroup:${local.name}-*",
      "arn:aws:eks:${local.reader_arn}:cluster/${local.name}-*",
      "arn:aws:events:${local.reader_arn}:rule/${local.name}-*",
      "arn:aws:lambda:${local.reader_arn}:function:${local.name}-*",
      "arn:aws:logs:${local.reader_arn}:log-group:/aws/lambda/${local.name}-*",
      "arn:aws:logs:${local.reader_arn}:log-group:/ecs/${local.name}-*",
      "arn:aws:rds:${local.reader_arn}:cluster:${local.name}-*",
      "arn:aws:secretsmanager:${local.reader_arn}:secret:${local.name}-*",
      "arn:aws:sns:${local.reader_arn}:${local.name}-*",
      "arn:aws:sqs:${local.reader_arn}:${local.name}-*",
    ]
  }

  # An ECS service's stopped tasks (G10-C1): task actions are scoped by their cluster, not a resource name.
  statement {
    sid       = "StoppedTasksOfOwnClusters"
    effect    = "Allow"
    actions   = ["ecs:DescribeTasks", "ecs:ListTasks"]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "ecs:cluster"
      values   = ["arn:aws:ecs:${local.reader_arn}:cluster/${local.name}-*"]
    }
  }

  # G10-C2: a cluster's node groups and their health, and a state machine's failed executions.
  statement {
    sid    = "NodeGroupsAndFailedExecutionsOfOwnStack"
    effect = "Allow"
    actions = [
      "eks:DescribeNodegroup",
      "eks:ListNodegroups",
      "states:DescribeExecution",
      "states:ListExecutions",
    ]
    resources = [
      "arn:aws:eks:${local.reader_arn}:cluster/${local.name}-*",
      "arn:aws:eks:${local.reader_arn}:nodegroup/${local.name}-*/*/*",
      "arn:aws:states:${local.reader_arn}:stateMachine:${local.name}-*",
      "arn:aws:states:${local.reader_arn}:execution:${local.name}-*:*",
    ]
  }

  # Actions that take no resource ("*" only), or that the code calls without an identity: a list of cache
  # clusters, the instances of a cluster by filter.
  statement {
    sid    = "ReadAnywhere"
    effect = "Allow"
    actions = [
      "autoscaling:DescribeScalingActivities",
      "cloudtrail:LookupEvents",
      "cloudwatch:GetMetricData",
      "cloudwatch:ListMetrics",
      "ec2:DescribeNetworkAcls",
      "ec2:DescribeRouteTables",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ecs:DescribeTaskDefinition",
      "elasticache:DescribeCacheClusters",
      "elasticache:DescribeEvents",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetHealth",
      "lambda:ListEventSourceMappings",
      "logs:GetQueryResults",
      "logs:StopQuery",
      "rds:DescribeDBInstances",
      "rds:DescribeEvents",
      "sts:GetCallerIdentity",
    ]
    resources = ["*"]
  }

  # Performance Insights (requirement R22): a member's metrics are named by its DbiResourceId, a random id, not by the
  # stack's name - so this account's and region's RDS metrics, read only.
  statement {
    sid       = "ReadDatabaseLoad"
    effect    = "Allow"
    actions   = ["pi:GetResourceMetrics"]
    resources = ["arn:aws:pi:${local.reader_arn}:metrics/rds/*"]
  }

  # ⭐ NOT a call WARDEN makes. The harness signs WARDEN's warden_<env>_ro database token with THIS role's
  # credentials (scenarios/fullstack_cli.py), so the database login WARDEN uses is authorised by the
  # role WARDEN runs as - and by nothing else. tests/test_aws_stack.py names it as the one exception
  # to "grant exactly what the code calls". That user holds pg_monitor only (bootstrap.sql).
  statement {
    sid       = "ConnectAsWardenRo"
    effect    = "Allow"
    actions   = ["rds-db:connect"]
    resources = [local.dbuser_arn["ro"]]
  }

  # API Gateway v2 has no per-API read action: `GetApis` is apigateway:GET on the /apis resource.
  statement {
    sid       = "ReadHttpApis"
    effect    = "Allow"
    actions   = ["apigateway:GET"]
    resources = ["arn:aws:apigateway:${local.region}::/apis", "arn:aws:apigateway:${local.region}::/apis/*"]
  }
}

resource "aws_iam_role" "fs_reader" {
  name                 = "${local.name}-reader"
  permissions_boundary = local.permissions_boundary
  assume_role_policy   = data.aws_iam_policy_document.fs_reader_assume.json
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role_policy" "fs_reader" {
  name   = "warden-readonly"
  role   = aws_iam_role.fs_reader.id
  policy = data.aws_iam_policy_document.fs_reader.json
}
