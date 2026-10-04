# Who the runtime is (G6). The worker's task role is `warden-<env>-worker` - for the `ops` runtime that is
# `warden-ops-worker`, the principal iam/templates/actor-trust.json and platform-reader-trust.json trust. It holds no
# standing write to any watched resource: it may only assume, per incident, a watched environment's platform reader,
# and for one approved plan its actor (src/warden/identity.py), each naming the incident and - for the actor - the
# approvers. The Lambdas' role is narrower still: no AWS role to assume, no model.
data "aws_region" "current" {}

locals {
  account = data.aws_caller_identity.current.account_id
  region  = data.aws_region.current.region
  # The roles the worker may assume: each watched environment's reader and actor, by exact name.
  assumable = flatten([for e in var.watched_environments : [
    "arn:aws:iam::${local.account}:role/warden-${e}-platform-reader",
    "arn:aws:iam::${local.account}:role/warden-${e}-actor",
  ]])
  # What every runtime identity reads and writes of its own: its secrets, its settings, its metrics, the audit key
  # and the anchors.
  own = [
    {
      Sid      = "ItsOwnSecrets"
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = "arn:aws:secretsmanager:${local.region}:${local.account}:secret:warden/${var.environment}/*"
    },
    {
      Sid    = "ItsOwnSettings"
      Effect = "Allow"
      Action = ["ssm:GetParametersByPath"]
      # The path the code reads (settings.load_from_ssm: /warden/<env>/env/) and what is under it, nothing wider.
      Resource = ["arn:aws:ssm:${local.region}:${local.account}:parameter/warden/${var.environment}/env",
      "arn:aws:ssm:${local.region}:${local.account}:parameter/warden/${var.environment}/env/*"]
    },
    {
      Sid      = "WhoMayApprove"
      Effect   = "Allow"
      Action   = ["ssm:GetParameter"]
      Resource = "arn:aws:ssm:${local.region}:${local.account}:parameter/warden/${var.environment}/approvers"
    },
    {
      Sid       = "ItsOwnMetrics"
      Effect    = "Allow"
      Action    = ["cloudwatch:PutMetricData"]
      Resource  = "*"
      Condition = { StringEquals = { "cloudwatch:namespace" = "WARDEN/${var.environment}" } }
    },
    {
      Sid      = "SignAuditCheckpoints"
      Effect   = "Allow"
      Action   = ["kms:Sign", "kms:GetPublicKey"]
      Resource = aws_kms_key.audit_signer.arn
    },
    {
      Sid      = "AnchorCheckpoints"
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:PutObjectRetention"]
      Resource = "${aws_s3_bucket.anchors.arn}/anchors/*"
    },
  ]
}

data "aws_iam_policy_document" "ecs_tasks_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account]
    }
  }
}

resource "aws_iam_role" "worker" {
  name                 = "warden-${var.environment}-worker"
  permissions_boundary = var.permissions_boundary_arn
  description          = "WARDEN ${var.environment}: the worker's task role - assumes a watched environment's reader or actor, never writes itself"
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_trust.json
  tags                 = { Project = "warden", Environment = var.environment }
}

resource "aws_iam_role_policy" "worker" {
  name = "warden-${var.environment}-worker"
  role = aws_iam_role.worker.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(local.own, [
      {
        Sid      = "AWatchedEnvironmentsReaderOrActorPerIncident"
        Effect   = "Allow"
        Action   = ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"]
        Resource = local.assumable
      },
      ], length(var.bedrock_model_arns) == 0 ? [] : [{
        Sid      = "TheQualifiedModelOnly"
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel"]
        Resource = var.bedrock_model_arns
    }])
  })
}

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name                 = "warden-${var.environment}-front-door"
  permissions_boundary = var.permissions_boundary_arn
  description          = "WARDEN ${var.environment}: the intake, webhook and approval-page Lambdas - no AWS role to assume, no model"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
  tags                 = { Project = "warden", Environment = var.environment }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "warden-${var.environment}-front-door"
  role   = aws_iam_role.lambda.id
  policy = jsonencode({ Version = "2012-10-17", Statement = local.own })
}

# In the VPC (the audit database), and their own logs: AWS's managed policy for exactly that.
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}
