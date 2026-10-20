# The sealed vault's key (src/warden/vault.py; owner, 2026-10-20): the real values behind an incident's placeholders
# are sealed with it, and only a PERSON's path can open them. The policy is the control, so it names every principal:
#
# - the read zone (where the values are found) may SEAL - GenerateDataKey with purpose=vault - and open the
#   environment's pseudonym key (purpose=pseudonym, the HMAC key behind the stable ids), and nothing else;
# - the approval page's Lambda (the records page's reveal, a signed-in person with a reason, audited) may OPEN a sealed
#   map - Decrypt with purpose=vault - and nothing else;
# - no other zone is named: not the llm zone (the diagnosis model), not Eldane's critic zone, not the notify zone, not
#   any zone added later. A grant to them in IAM alone does nothing: the key policy does not delegate use to IAM.
# - the account may ADMINISTER the key (and make the pseudonym key without ever seeing it:
#   GenerateDataKeyWithoutPlaintext, purpose=pseudonym), never use it to read. Honest limit: an administrator can
#   change this policy; CloudTrail records that, and every Decrypt.
#
# One symmetric key, rotated yearly by KMS: US$1 a month, plus US$0.03 per 10,000 requests (one seal per evidence read,
# one Decrypt per reveal) - the lane's only cost.
resource "aws_kms_key" "vault" {
  description             = "WARDEN ${var.environment}: seals masked values for people only (never opened by an AI zone)"
  key_usage               = "ENCRYPT_DECRYPT"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AdministerNeverRead"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account}:root" }
        # Exact actions, never `kms:Create*`: that takes in CreateGrant, and a grant gives Decrypt with none of the
        # conditions below (review, 2026-10-20). Changing this policy itself stays possible (PutKeyPolicy): CloudTrail.
        Action = ["kms:CreateAlias", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*",
          "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*", "kms:TagResource", "kms:UntagResource",
        "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:RotateKeyOnDemand"]
        Resource = "*"
      },
      {
        Sid       = "MakeThePseudonymKeyUnseen"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account}:root" }
        Action    = "kms:GenerateDataKeyWithoutPlaintext"
        Resource  = "*"
        Condition = { StringEquals = { "kms:EncryptionContext:purpose" = "pseudonym" } }
      },
      {
        Sid       = "TheReadZoneSeals"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.zone["read"].arn }
        Action    = "kms:GenerateDataKey"
        Resource  = "*"
        Condition = { StringEquals = { "kms:EncryptionContext:purpose" = "vault" } }
      },
      {
        Sid       = "TheReadZoneOpensThePseudonymKey"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.zone["read"].arn }
        Action    = "kms:Decrypt"
        Resource  = "*"
        Condition = { StringEquals = { "kms:EncryptionContext:purpose" = "pseudonym" } }
      },
      {
        Sid       = "OnlyAPersonsRevealOpens"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.front_door["approval"].arn }
        Action    = "kms:Decrypt"
        Resource  = "*"
        Condition = { StringEquals = { "kms:EncryptionContext:purpose" = "vault" } }
      },
    ]
  })
  tags = { Project = "warden", Environment = var.environment }
}

resource "aws_kms_alias" "vault" {
  name          = "alias/warden-${var.environment}-vault"
  target_key_id = aws_kms_key.vault.key_id
}

# The same grants on the roles' side, as the permissions boundary requires an identity policy to allow what a key
# policy names (iam/templates/runtime-boundary.json CeilingOwnKeys): exactly the key, exactly the purpose.
resource "aws_iam_role_policy" "vault_read_zone" {
  name = "warden-${var.environment}-read-vault"
  role = aws_iam_role.zone["read"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "SealTheValuesItFinds"
        Effect    = "Allow"
        Action    = "kms:GenerateDataKey"
        Resource  = aws_kms_key.vault.arn
        Condition = { StringEquals = { "kms:EncryptionContext:purpose" = "vault" } }
      },
      {
        Sid       = "OpenThePseudonymKey"
        Effect    = "Allow"
        Action    = "kms:Decrypt"
        Resource  = aws_kms_key.vault.arn
        Condition = { StringEquals = { "kms:EncryptionContext:purpose" = "pseudonym" } }
      },
    ]
  })
}

resource "aws_iam_role_policy" "vault_reveal" {
  name = "warden-${var.environment}-approval-vault"
  role = aws_iam_role.front_door["approval"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OpenASealedMapForAPerson"
      Effect    = "Allow"
      Action    = "kms:Decrypt"
      Resource  = aws_kms_key.vault.arn
      Condition = { StringEquals = { "kms:EncryptionContext:purpose" = "vault" } }
    }]
  })
}
