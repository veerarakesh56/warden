# The sealed vault's keys (src/warden/vault.py; owner, 2026-10-20/21): the real values behind an incident's placeholders
# are sealed with the vault key, and only a PERSON's path can open them. The policies are the control, so they name
# every principal:
#
# - the read zone (where the values are found) may SEAL - GenerateDataKey with purpose=vault - and compute the stable
#   ids with the pseudonym HMAC key (GenerateMac). It holds NO kms:Decrypt on the vault key.
# - the approval page's Lambda (the records page's reveal, a signed-in person with a reason, audited) is the ONLY
#   principal that may Decrypt with the vault key (purpose=vault), and it may do nothing else with either key.
# - no other zone is named: not the llm zone (the diagnosis model, the discussion chat), not Eldane's critic zone, not
#   core, notify or act, not any zone added later. A grant to them in IAM alone does nothing: neither key policy
#   delegates use to IAM.
# - the account may ADMINISTER the keys, never use them. Honest limit: an administrator can change a policy;
#   CloudTrail records that, and every Decrypt.
#
# Two keys: the vault key (symmetric, rotated yearly by KMS) and the pseudonym key (HMAC_256 - it never leaves KMS; KMS
# does not rotate HMAC keys). US$1 a month each, plus US$0.03 per 10,000 requests (one seal per evidence read, one MAC
# per masked value, one Decrypt per reveal).
locals {
  # Exact actions, never `kms:Create*`: that takes in CreateGrant, and a grant gives use with none of the conditions
  # below (review, 2026-10-20). Changing a policy itself stays possible (PutKeyPolicy): CloudTrail records it.
  vault_administration = ["kms:CreateAlias", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*",
    "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*", "kms:TagResource", "kms:UntagResource",
  "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"]
}

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
        Action    = concat(local.vault_administration, ["kms:RotateKeyOnDemand"])
        Resource  = "*"
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

# The stable ids' key: an HMAC key held by KMS. Only the read zone computes a MAC with it; nobody can read it.
resource "aws_kms_key" "pseudonym" {
  description              = "WARDEN ${var.environment}: stable ids for masked values (HMAC, never exported)"
  key_usage                = "GENERATE_VERIFY_MAC"
  customer_master_key_spec = "HMAC_256"
  deletion_window_in_days  = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AdministerNeverUse"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account}:root" }
        Action    = local.vault_administration
        Resource  = "*"
      },
      {
        Sid       = "TheReadZoneComputesIds"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.zone["read"].arn }
        Action    = "kms:GenerateMac"
        Resource  = "*"
      },
    ]
  })
  tags = { Project = "warden", Environment = var.environment }
}

resource "aws_kms_alias" "pseudonym" {
  name          = "alias/warden-${var.environment}-pseudonym"
  target_key_id = aws_kms_key.pseudonym.key_id
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
        Sid      = "ComputeTheStableIds"
        Effect   = "Allow"
        Action   = "kms:GenerateMac"
        Resource = aws_kms_key.pseudonym.arn
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
