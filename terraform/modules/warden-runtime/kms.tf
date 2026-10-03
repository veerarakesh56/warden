# Register S12: the key that signs every audit checkpoint is an Ed25519 key held by AWS KMS. Nobody - WARDEN included
# - can export it, so a copy of the database and the code is not enough to sign a rewritten history; CloudTrail records
# every kms:Sign as an independent witness. The runtime signs through it when WARDEN_AUDIT_KMS_KEY_ID names it
# (src/warden/runtime.py audit_signer). An asymmetric key has no automatic rotation: a new key is a new alias target,
# and `warden audit verify` keeps the retired public keys (docs/OPERATIONS.md).
data "aws_caller_identity" "current" {}

resource "aws_kms_key" "audit_signer" {
  description              = "WARDEN ${var.environment}: signs audit checkpoints (Ed25519, never exported)"
  customer_master_key_spec = "ECC_NIST_EDWARDS25519"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
  # The account's own IAM decides who may use it: the worker's role alone is granted kms:Sign (iam.tf).
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "TheAccountsIamDecides"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
  tags = { Project = "warden", Environment = var.environment }
}

resource "aws_kms_alias" "audit_signer" {
  name          = "alias/warden-${var.environment}-audit"
  target_key_id = aws_kms_key.audit_signer.key_id
}
