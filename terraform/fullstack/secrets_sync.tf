# B25 (owner, 2026-10-17): the catalog signing key lives in Secrets Manager, not in a deploy run. The External Secrets
# Operator copies it into shop/catalog-secret (k8s/shop-pipeline/catalog-secret.yaml) and Reloader restarts
# catalog-api when it changes. The key is made by an ephemeral random_password and written through the write-only
# argument, so it is in neither the plan nor the state - as the API token is (api_auth.tf). Bump
# catalog_signing_key_version and apply to rotate it; the next apps deploy hands the new version to the cluster.
ephemeral "random_password" "catalog_signing_key" {
  length  = 64
  special = false
}

resource "aws_secretsmanager_secret" "catalog_signing_key" {
  name                    = "${local.name}-catalog-signing-key"
  description             = "catalog-api's signing key (made at apply; in no plan or state). Copied into the cluster by ESO."
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "catalog_signing_key" {
  secret_id                = aws_secretsmanager_secret.catalog_signing_key.id
  secret_string_wo         = ephemeral.random_password.catalog_signing_key.result
  secret_string_wo_version = var.catalog_signing_key_version
}

variable "catalog_signing_key_version" {
  description = "Raise to rotate catalog-api's signing key (B25)."
  type        = number
  default     = 1
}

# The operator's identity, through EKS Pod Identity (no long-lived key): it may read this one secret, nothing else.
resource "aws_iam_role" "external_secrets" {
  name                 = "${local.name}-external-secrets"
  permissions_boundary = local.permissions_boundary
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = ["sts:AssumeRole", "sts:TagSession"]
      Principal = { Service = "pods.eks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "external_secrets_read" {
  name = "${local.name}-read-catalog-signing-key"
  role = aws_iam_role.external_secrets.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadTheCatalogSigningKeyOnly"
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
      Resource = [aws_secretsmanager_secret.catalog_signing_key.arn]
    }]
  })
}

resource "aws_eks_pod_identity_association" "external_secrets" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = "external-secrets"
  service_account = "external-secrets"
  role_arn        = aws_iam_role.external_secrets.arn
}

output "catalog_signing_key_secret_name" {
  value = aws_secretsmanager_secret.catalog_signing_key.name
}
