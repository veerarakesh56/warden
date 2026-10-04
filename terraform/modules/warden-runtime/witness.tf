# AWS's own record of what happened in the account (G6): a CloudTrail trail of management events, into a bucket of
# its own under S3 Object Lock (COMPLIANCE) with log file validation. It is the witness WARDEN does not write: every
# actor session (the `actor-use` Lambda checks each one against the audit, via EventBridge, which needs this trail),
# every kms:Sign of an audit checkpoint, every change in the watched environments. Read and write events both: an
# AssumeRole must be seen whichever way CloudTrail classes it.
locals {
  witness_trail = "warden-${var.environment}-witness"
}

resource "aws_s3_bucket" "witness" {
  bucket_prefix       = "warden-${var.environment}-witness-"
  object_lock_enabled = true
  tags                = { Project = "warden", Environment = var.environment }
}

resource "aws_s3_bucket_versioning" "witness" {
  bucket = aws_s3_bucket.witness.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "witness" {
  bucket = aws_s3_bucket.witness.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.anchor_retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.witness]
}

resource "aws_s3_bucket_public_access_block" "witness" {
  bucket                  = aws_s3_bucket.witness.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SSE-S3: CloudTrail writes as its service principal, which an AWS-managed KMS key would refuse.
resource "aws_s3_bucket_server_side_encryption_configuration" "witness" {
  bucket = aws_s3_bucket.witness.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

# CloudTrail's documented bucket policy, held to this trail by aws:SourceArn, plus TLS only.
resource "aws_s3_bucket_policy" "witness" {
  bucket = aws_s3_bucket.witness.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "OnlyOverTls"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.witness.arn, "${aws_s3_bucket.witness.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "AWSCloudTrailAclCheck20150319"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.witness.arn
        Condition = { StringEquals = { "aws:SourceArn" = "arn:aws:cloudtrail:${local.region}:${local.account}:trail/${local.witness_trail}" } }
      },
      {
        Sid       = "AWSCloudTrailWrite20150319"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.witness.arn}/AWSLogs/${local.account}/*"
        Condition = { StringEquals = {
          "s3:x-amz-acl"  = "bucket-owner-full-control"
          "aws:SourceArn" = "arn:aws:cloudtrail:${local.region}:${local.account}:trail/${local.witness_trail}"
        } }
      },
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.witness]
}

resource "aws_cloudtrail" "witness" {
  name                          = local.witness_trail
  s3_bucket_name                = aws_s3_bucket.witness.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  tags                          = { Project = "warden", Environment = var.environment }
  depends_on                    = [aws_s3_bucket_policy.witness]
}

# ----------------------------------------------------------------- actor sessions -> the actor-use check -> a page

resource "aws_cloudwatch_event_rule" "actor_use" {
  name        = "warden-${var.environment}-actor-use"
  description = "WARDEN ${var.environment}: every session of a watched environment's actor role, to the actor-use check"
  # ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS: a rule in plain ENABLED misses read-only management events.
  state = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
  event_pattern = jsonencode({
    source        = ["aws.sts"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource       = ["sts.amazonaws.com"]
      eventName         = ["AssumeRole"]
      requestParameters = { roleArn = [for e in var.watched_environments : { suffix = ":role/warden-${e}-actor" }] }
    }
  })
  tags = { Project = "warden", Environment = var.environment }
}

resource "aws_cloudwatch_event_target" "actor_use" {
  rule = aws_cloudwatch_event_rule.actor_use.name
  arn  = aws_lambda_function.front_door["actor-use"].arn
  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }
  dead_letter_config {
    arn = aws_sqs_queue.alarm_dlq.arn
  }
}

resource "aws_lambda_permission" "actor_use" {
  statement_id  = "EventBridgeActorSessions"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.front_door["actor-use"].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.actor_use.arn
}

resource "aws_cloudwatch_metric_alarm" "unapproved_actor" {
  alarm_name          = "warden-${var.environment}-unapproved-actor"
  alarm_description   = "An actor role was assumed without an approval WARDEN's audit holds, or one the check could not read. Treat it as a security incident: docs/RUNBOOK-WARDEN-INCIDENT.md."
  namespace           = "WARDEN/${var.environment}"
  metric_name         = "UnapprovedActorUse"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.page_topic_arn]
  tags                = { Project = "warden", Environment = var.environment }
}
