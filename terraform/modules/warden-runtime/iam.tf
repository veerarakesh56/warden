# Who the runtime is (G6). The worker runs as five processes, one per trust zone (register S15), each with its own
# task role `warden-<env>-<zone>` - for the `ops` runtime, `warden-ops-read`, `-notify` and `-act` are the principals
# iam/templates/platform-reader-trust.json and actor-trust.json trust. No zone holds a standing write to any watched
# resource: the read and notify zones may assume a watched environment's platform reader, and only the act zone - for
# one approved plan - its actor (src/warden/identity.py), each naming the incident and, for the actor, the approvers.
# Only the llm zone may call the model. Each zone reads only its own secrets (settings.ZONE_SECRETS). The Lambdas'
# role is narrower still: no AWS role to assume, no model.
data "aws_region" "current" {}

locals {
  account    = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  secret_arn = "arn:aws:secretsmanager:${local.region}:${local.account}:secret:warden/${var.environment}"
  # What every runtime identity reads and writes of its own: its settings, who may approve, its metrics, the audit key
  # and the anchors. Its secrets are per identity, below.
  own = [
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
      # The audit, as its writer (migrate.tf): an IAM token instead of a password.
      Sid      = "ConnectAsTheAuditWriter"
      Effect   = "Allow"
      Action   = ["rds-db:connect"]
      Resource = "arn:aws:rds-db:${local.region}:${local.account}:dbuser:${aws_rds_cluster.audit.cluster_resource_id}/${local.audit_writer}"
    },
    {
      Sid      = "AnchorCheckpoints"
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:PutObjectRetention"]
      Resource = "${aws_s3_bucket.anchors.arn}/anchors/*"
    },
  ]
  # Register S15, as settings.ZONE_SECRETS and settings.secret_id name them (tests/test_runtime_module_g6.py holds the
  # two together): every zone's own, and each zone's. Each zone also reads its own Temporal key, temporal-api-key-<zone>.
  every_zone_secrets = ["temporal-key", "temporal-key-previous", "audit-dsn", "audit-key-passphrase"]
  zones = {
    core   = { secrets = [], assumes = [], model = false }
    read   = { secrets = ["db-dsn", "stack-db-writer-dsn", "stack-db-reader-dsn"], assumes = ["platform-reader"], model = false }
    llm    = { secrets = ["gemini-api-key", "google-api-key", "openai-api-key", "anthropic-api-key"], assumes = [], model = true }
    notify = { secrets = ["slack-bot-token", "slack-webhook", "teams-webhook", "webhook-url", "pagerduty-routing-key", "github-token"], assumes = ["platform-reader"], model = false }
    # Every write re-reads its target first (platforms/aws.py), so the act zone reads as well as acts.
    act = { secrets = ["db-admin-dsn"], assumes = ["platform-reader", "actor"], model = false }
  }
  # The Lambdas: the codec, their Temporal key, the audit, the Alertmanager webhook's secrets (settings.RESTRICTED).
  lambda_secrets = ["temporal-key", "temporal-key-previous", "temporal-api-key", "audit-dsn", "alertmanager-token",
  "alertmanager-token-previous"]
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

resource "aws_iam_role" "zone" {
  for_each             = local.zones
  name                 = "warden-${var.environment}-${each.key}"
  permissions_boundary = var.permissions_boundary_arn
  description          = "WARDEN ${var.environment}: the ${each.key} zone's task role - never writes itself"
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_trust.json
  tags                 = { Project = "warden", Environment = var.environment }
}

resource "aws_iam_role_policy" "zone" {
  for_each = local.zones
  name     = "warden-${var.environment}-${each.key}"
  role     = aws_iam_role.zone[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(local.own, [
      {
        Sid    = "ItsOwnSecrets"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        # Secrets Manager adds six characters to each name; `??????` matches exactly those.
        Resource = [for s in concat(local.every_zone_secrets, each.value.secrets, ["temporal-api-key-${each.key}"]) :
        "${local.secret_arn}/${s}-??????"]
      },
      ], length(each.value.assumes) == 0 ? [] : [{
        Sid      = "AWatchedEnvironmentsRolePerIncident"
        Effect   = "Allow"
        Action   = ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"]
        Resource = flatten([for e in var.watched_environments : [for r in each.value.assumes : "arn:aws:iam::${local.account}:role/warden-${e}-${r}"]])
        }], each.value.model && length(var.bedrock_model_arns) > 0 ? [{
        Sid      = "TheQualifiedModelOnly"
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel"]
        Resource = var.bedrock_model_arns
    }] : [])
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
  name = "warden-${var.environment}-front-door"
  role = aws_iam_role.lambda.id
  policy = jsonencode({ Version = "2012-10-17", Statement = concat(local.own, [{
    Sid      = "ItsOwnSecrets"
    Effect   = "Allow"
    Action   = ["secretsmanager:GetSecretValue"]
    Resource = [for s in local.lambda_secrets : "${local.secret_arn}/${s}-??????"]
  }]) })
}

# In the VPC (the audit database), and their own logs: AWS's managed policy for exactly that.
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}
