# The audit's schema and its writer login (G6): `warden.lambdas.migrate`, invoked by .github/workflows/runtime.yml
# after each apply. The only identity that reads the cluster's master secret (RDS keeps it in Secrets Manager); it
# creates the tables, the append-only triggers and `warden_audit_writer` - SELECT and INSERT only, a login with no
# password that signs in with an IAM token. Every other runtime identity connects as that writer (iam.tf).
locals {
  audit_writer = "warden_audit_writer"
  # No password: _pg_connect signs in with an IAM token when WARDEN_AUDIT_IAM_AUTH=1.
  audit_dsn = "postgresql://${local.audit_writer}@${aws_rds_cluster.audit.endpoint}:5432/${aws_rds_cluster.audit.database_name}?sslmode=require"
}

resource "aws_iam_role" "migrate" {
  name                 = "warden-${var.environment}-migrate"
  permissions_boundary = var.permissions_boundary_arn
  description          = "WARDEN ${var.environment}: creates the audit schema and writer login - reads the master secret, nothing else"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
  tags                 = { Project = "warden", Environment = var.environment }
}

resource "aws_iam_role_policy" "migrate" {
  name = "warden-${var.environment}-migrate"
  role = aws_iam_role.migrate.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid      = "TheAuditClustersMasterSecretOnly"
    Effect   = "Allow"
    Action   = ["secretsmanager:GetSecretValue"]
    Resource = aws_rds_cluster.audit.master_user_secret[0].secret_arn
  }] })
}

resource "aws_iam_role_policy_attachment" "migrate_vpc" {
  role       = aws_iam_role.migrate.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_cloudwatch_log_group" "migrate" {
  name              = "/aws/lambda/warden-${var.environment}-migrate"
  retention_in_days = 90
  tags              = { Project = "warden", Environment = var.environment }
}

resource "aws_lambda_function" "migrate" {
  function_name = "warden-${var.environment}-migrate"
  role          = aws_iam_role.migrate.arn
  package_type  = "Image"
  image_uri     = var.runtime_image
  timeout       = 120
  memory_size   = 512
  image_config {
    entry_point = ["/opt/warden/bin/python", "-m", "awslambdaric"]
    command     = ["warden.lambdas.migrate"]
  }
  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.runtime.id]
  }
  environment {
    variables = {
      WARDEN_ENV                 = var.environment
      WARDEN_AUDIT_MASTER_SECRET = aws_rds_cluster.audit.master_user_secret[0].secret_arn
      WARDEN_AUDIT_HOST          = aws_rds_cluster.audit.endpoint
      WARDEN_AUDIT_DB            = aws_rds_cluster.audit.database_name
    }
  }
  tags       = { Project = "warden", Environment = var.environment }
  depends_on = [aws_cloudwatch_log_group.migrate]
}
