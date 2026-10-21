# Who the runtime is (G6). The worker runs as five processes, one per trust zone (register S15), each with its own
# task role `warden-<env>-<zone>` - for the `ops` runtime, `warden-ops-read`, `-notify` and `-act` are the principals
# iam/templates/platform-reader-trust.json and actor-trust.json trust. No zone holds a standing write to any watched
# resource: the read and notify zones may assume a watched environment's platform reader, and only the act zone - for
# one approved plan - its actor (src/warden/identity.py), each naming the incident and, for the actor, the approvers.
# No zone calls a model through AWS (no Bedrock: owner, 2026-10-09). Each zone reads only its own secrets
# (settings.ZONE_SECRETS). Each Lambda has a role of its own, narrower still: no AWS role to assume, and only the
# secrets and settings its own handler reads (settings.LAMBDA_SECRETS).
data "aws_region" "current" {}

locals {
  account    = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  secret_arn = "arn:aws:secretsmanager:${local.region}:${local.account}:secret:warden/${var.environment}"
  # What every runtime identity reads and writes of its own: its settings, the audit, its key and the anchors. Who may
  # approve and its metrics are each zone's, and of the Lambdas only the one that uses them. Secrets are per identity.
  audit_and_settings = [
    {
      Sid    = "ItsOwnSettings"
      Effect = "Allow"
      Action = ["ssm:GetParametersByPath"]
      # The path the code reads (settings.load_from_ssm: /warden/<env>/env/) and what is under it, nothing wider.
      Resource = ["arn:aws:ssm:${local.region}:${local.account}:parameter/warden/${var.environment}/env",
      "arn:aws:ssm:${local.region}:${local.account}:parameter/warden/${var.environment}/env/*"]
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
      Resource = "arn:aws:rds-db:${local.region}:${local.account}:dbuser:${local.audit_db.resource_id}/${local.audit_writer}"
    },
    {
      Sid      = "AnchorCheckpoints"
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:PutObjectRetention"]
      Resource = "${aws_s3_bucket.anchors.arn}/anchors/*"
    },
  ]
  who_may_approve = {
    Sid      = "WhoMayApprove"
    Effect   = "Allow"
    Action   = ["ssm:GetParameter"]
    Resource = "arn:aws:ssm:${local.region}:${local.account}:parameter/warden/${var.environment}/approvers"
  }
  its_own_metrics = {
    Sid       = "ItsOwnMetrics"
    Effect    = "Allow"
    Action    = ["cloudwatch:PutMetricData"]
    Resource  = "*"
    Condition = { StringEquals = { "cloudwatch:namespace" = "WARDEN/${var.environment}" } }
  }
  own = concat(local.audit_and_settings, [local.who_may_approve, local.its_own_metrics])
  acknowledge_pages = [
    { Sid = "ListPages", Effect = "Allow", Action = ["s3:ListBucket"], Resource = [aws_s3_bucket.anchors.arn] },
    { Sid = "ReadPages", Effect = "Allow", Action = ["s3:GetObject"], Resource = ["${aws_s3_bucket.anchors.arn}/pages/*", "${aws_s3_bucket.anchors.arn}/acks/*"] },
    { Sid = "Acknowledge", Effect = "Allow", Action = ["s3:PutObject"], Resource = ["${aws_s3_bucket.anchors.arn}/acks/*"] },
  ]
  # Register S15, as settings.ZONE_SECRETS and settings.secret_id name them (tests/test_runtime_module_g6.py holds the
  # two together): every zone's own, and each zone's. Each zone also reads its own Temporal key, temporal-api-key-<zone>.
  every_zone_secrets = ["temporal-key"]
  # `platforms`: what the zone's worker connects (`warden worker --platform`, compute.tf). The read zone reads every
  # platform's targets and health, the act zone writes through each; notify reads AWS alarms only. Kubernetes and the
  # database are each watched environment's own (WARDEN_EKS_CLUSTERS, WARDEN_DB_ENVIRONMENT): one without them reads
  # and changes nothing there, and its plans go to a person.
  zones = {
    core   = { secrets = [], assumes = [], platforms = [] }
    read   = { secrets = ["stack-db-writer-dsn", "stack-db-reader-dsn", "datadog-api-key", "datadog-app-key", "github-read-token"], assumes = ["platform-reader"], platforms = ["aws", "k8s", "db", "infra"] }
    llm    = { secrets = ["anthropic-api-key"], assumes = [], platforms = [] }
    notify = { secrets = ["slack-bot-token", "slack-app-token", "slack-webhook", "github-token"], assumes = ["platform-reader"], platforms = ["aws"] }
    # Every write re-reads its target first (platforms/aws.py), so the act zone reads as well as acts. Its secrets: the
    # terminate login's DSN - no password in it: each close signs in with a token the plan's actor signs - and (B17) the
    # token that dispatches the infra workflow's apply-plan (platforms/infra.py).
    act = { secrets = ["db-admin-dsn", "github-actions-token"], assumes = ["platform-reader", "actor"], platforms = ["aws", "k8s", "db", "infra"] }
    # Eldane, the AI critic (eldane.py): the diagnosis's Claude key (owner, 2026-10-17) and its own signing key; it
    # reads the audit and assumes nothing.
    critic = { secrets = ["anthropic-api-key", "eldane-key"], assumes = [], platforms = [] }
  }
  # The Lambdas (frontdoor.tf), as settings.LAMBDA_SECRETS names what each handler reads (tests/test_runtime_module_g6.py
  # runs each one's load and holds the two together). Only the approval page reads who may approve; only actor-use
  # counts a metric - and reads no secret: the audit's address is its environment's (frontdoor.tf), and KMS signs.
  front_door_access = {
    alarm        = { secrets = ["temporal-key", "temporal-api-key"], approvers = false, metrics = false }
    alertmanager = { secrets = ["temporal-key", "temporal-api-key", "datadog-webhook-token", "datadog-api-key", "datadog-app-key"], approvers = false, metrics = false }
    approval     = { secrets = ["temporal-key", "temporal-api-key", "slack-client-secret"], approvers = true, metrics = true }
    actor-use    = { secrets = [], approvers = false, metrics = true }
  }
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

# One role per Lambda (secrets audit, 2026-10-16): the internet-facing approval page held the webhook's Datadog keys and
# bearer secrets because all four shared one role. No moved block: every name changes, so each is a new role either
# way, and Terraform deletes the old one only after the functions have moved to theirs.
resource "aws_iam_role" "front_door" {
  for_each             = local.front_door_access
  name                 = "warden-${var.environment}-${each.key}-lambda"
  permissions_boundary = var.permissions_boundary_arn
  description          = "WARDEN ${var.environment}: the ${each.key} Lambda - no AWS role to assume, no model, its own secrets only"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
  tags                 = { Project = "warden", Environment = var.environment }
}

resource "aws_iam_role_policy" "front_door" {
  for_each = local.front_door_access
  name     = "warden-${var.environment}-${each.key}-lambda"
  role     = aws_iam_role.front_door[each.key].id
  policy = jsonencode({ Version = "2012-10-17", Statement = concat(local.audit_and_settings,
    each.value.approvers ? [local.who_may_approve] : [], each.value.metrics ? [local.its_own_metrics] : [],
    # WARDEN's own pages (paging.tf): the approval page shows them and writes an approver's acknowledgement.
    [for s in local.acknowledge_pages : s if each.key == "approval"],
    # B35: an event the function failed on every time goes to the dead-letter queue (frontdoor.tf), never nowhere.
    contains(local.async_front_doors, each.key) ? [{ Sid = "KeepWhatFailed", Effect = "Allow", Action = ["sqs:SendMessage"], Resource = aws_sqs_queue.alarm_dlq.arn }] : [],
    length(each.value.secrets) == 0 ? [] : [{
      Sid      = "ItsOwnSecrets"
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [for s in each.value.secrets : "${local.secret_arn}/${s}-??????"]
  }]) })
}

# In the VPC (the audit database), and their own logs: AWS's managed policy for exactly that.
resource "aws_iam_role_policy_attachment" "front_door_vpc" {
  for_each   = local.front_door_access
  role       = aws_iam_role.front_door[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}
