# Register S12: each audit checkpoint is also written here, under S3 Object Lock in COMPLIANCE mode - until its
# retention ends nobody, the account's root included, can delete or overwrite it. A history rewritten afterwards no
# longer matches its anchors, and `warden audit verify --anchor-bucket` says so.
resource "aws_s3_bucket" "anchors" {
  bucket_prefix       = "warden-${var.environment}-anchors-"
  object_lock_enabled = true
  tags                = { Project = "warden", Environment = var.environment }
}

resource "aws_s3_bucket_versioning" "anchors" {
  bucket = aws_s3_bucket.anchors.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "anchors" {
  bucket = aws_s3_bucket.anchors.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.anchor_retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.anchors]
}

resource "aws_s3_bucket_public_access_block" "anchors" {
  bucket                  = aws_s3_bucket.anchors.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "anchors" {
  bucket = aws_s3_bucket.anchors.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "anchors" {
  bucket = aws_s3_bucket.anchors.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OnlyOverTls"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.anchors.arn, "${aws_s3_bucket.anchors.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.anchors]
}

# ----------------------------------------------------------------- server access logs: the anchors' and the witness's
# Who read or wrote the audit's anchors and AWS's witness record (Sonar terraform:S6258, 2026-10-17): S3 server access
# logs for both buckets, delivered here (witness.tf turns on the witness's). Each bucket's logging sits in the bucket's
# own file, where a reader - and Sonar, which reads one file at a time - finds it. CloudTrail (witness.tf) records
# management events only, so without these a GetObject or a refused PutObject on either bucket left no trace. Neither
# bucket can be its own log target: AWS does not deliver server access logs to a bucket with an Object Lock default
# retention.
#
# Cost: S3 charges nothing to enable or deliver server access logs, only the storage of the log objects - a few
# kilobytes a day here (CloudTrail's delivery every few minutes, a checkpoint now and then), kept 90 days like the
# runtime's log groups. Log delivery supports SSE-S3 only, so the bucket uses it.
#
# ⚠ The runtime's permissions boundary must allow s3:PutBucketPolicy and s3:PutBucketPublicAccessBlock on
# warden-<env>-access-logs-* before this applies (iam/templates/runtime-boundary.json, DenyBucketPolicy).

resource "aws_s3_bucket" "access_logs" {
  bucket_prefix = "warden-${var.environment}-access-logs-"
  tags          = { Project = "warden", Environment = var.environment }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    id     = "keep-90-days"
    status = "Enabled"
    filter {}
    expiration { days = 90 }
    noncurrent_version_expiration { noncurrent_days = 1 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
  rule {
    id     = "drop-expired-delete-markers"
    status = "Enabled"
    filter {}
    expiration { expired_object_delete_marker = true }
  }
  depends_on = [aws_s3_bucket_versioning.access_logs]
}

# AWS's documented policy for server access logs: the logging service, for these two source buckets in this account
# only, writes under their prefixes; nothing else is granted. Plus TLS only, as every bucket here.
resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "OnlyOverTls"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.access_logs.arn, "${aws_s3_bucket.access_logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "S3ServerAccessLogsPolicy"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = ["${aws_s3_bucket.access_logs.arn}/anchors/*", "${aws_s3_bucket.access_logs.arn}/witness/*"]
        Condition = {
          ArnLike      = { "aws:SourceArn" = [aws_s3_bucket.anchors.arn, aws_s3_bucket.witness.arn] }
          StringEquals = { "aws:SourceAccount" = local.account }
        }
      },
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.access_logs]
}

resource "aws_s3_bucket_logging" "anchors" {
  bucket        = aws_s3_bucket.anchors.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "anchors/"
  depends_on    = [aws_s3_bucket_policy.access_logs]
}
