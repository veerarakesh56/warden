# The approval site's gate at the gateway (owner, 2026-10-21; Sonar terraform:S6333): a Lambda REQUEST authorizer on
# the routes whose function already refuses a request without what it checks (src/warden/edge_auth.py) - the Slack
# sign-in's sealed cookie for the records (/r) and WARDEN's own pages (/p), and the signature and expiry of an
# enrolment's or a kill switch link (/e, /k, /x). It adds a layer and loosens nothing: what passes is checked again
# behind it by the same code, the audit included (a link already used). The routes left open, and why, are in
# edge_auth.py and docs/DESIGN-DECISIONS.md: /a/{token} (the passkey sign-in's start: a random token only the audit
# database knows, then Slack and a passkey), /s/* (the sign-in itself) and POST /s/interact (answered, nothing read).
# Throttling and access logs are the stage's (frontdoor.tf): every route, the authorizer's refusals included.
locals {
  edge_gated = toset(["GET /r", "GET /r/{incident}", "GET /p", "POST /p/{step}",
    "GET /e/{token}", "POST /e/{token}/{step}", "GET /k/{token}", "POST /k/{token}/{step}",
  "GET /x/{token}", "POST /x/{token}/{step}"])
}

resource "aws_apigatewayv2_authorizer" "edge" {
  api_id                            = aws_apigatewayv2_api.front.id
  name                              = "warden-${var.environment}-approval-edge"
  authorizer_type                   = "REQUEST"
  authorizer_uri                    = aws_lambda_function.edge_auth.invoke_arn
  authorizer_payload_format_version = "2.0"
  enable_simple_responses           = true
  # No identity source and no cache: what it checks - a cookie, the token in the path - is read from the whole
  # request each time. Caching needs an identity source and would answer every route that shares it from one cookie;
  # with none and TTL 0 the gateway asks for every request (API Gateway developer guide, "Working with AWS Lambda
  # authorizers for HTTP APIs": identity sources and caching, read 2026-10-21).
  identity_sources                 = []
  authorizer_result_ttl_in_seconds = 0
}

# The runtime image (it has the approver list's Ed25519 check and the cookie's seal), outside the VPC: it reads the
# Slack app's secret, this environment's plain settings and the approver list, and nothing else - no audit, no key.
resource "aws_iam_role" "edge_auth" {
  name                 = "warden-${var.environment}-edge-auth"
  permissions_boundary = var.permissions_boundary_arn
  description          = "WARDEN ${var.environment}: the approval site's gate at the gateway - reads the Slack app secret and the approver list"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
  tags                 = { Project = "warden", Environment = var.environment }
}

resource "aws_iam_role_policy" "edge_auth" {
  name = "warden-${var.environment}-edge-auth"
  role = aws_iam_role.edge_auth.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      local.audit_and_settings[0], # ItsOwnSettings: /warden/<env>/env/ (plain values; settings.load_from_ssm)
      local.who_may_approve,
      {
        Sid      = "TheSlackAppSecret"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = ["${local.secret_arn}/slack-client-secret-??????"]
      },
      {
        Sid      = "ItsOwnLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.edge_auth.arn}:*"
      },
    ]
  })
}

resource "aws_cloudwatch_log_group" "edge_auth" {
  name              = "/aws/lambda/warden-${var.environment}-edge-auth"
  retention_in_days = 90
  tags              = { Project = "warden", Environment = var.environment }
}

resource "aws_lambda_function" "edge_auth" {
  function_name = "warden-${var.environment}-edge-auth"
  role          = aws_iam_role.edge_auth.arn
  package_type  = "Image"
  image_uri     = var.runtime_image
  timeout       = 10
  memory_size   = 1769 # a whole vCPU for the image's cold start, as the approval page (frontdoor.tf)
  image_config {
    entry_point = ["/opt/warden/bin/python", "-m", "awslambdaric"]
    command     = ["warden.edge_auth.handler"]
  }
  environment {
    variables = { WARDEN_ENV = var.environment }
  }
  tags       = { Project = "warden", Environment = var.environment }
  depends_on = [aws_cloudwatch_log_group.edge_auth]
}

resource "aws_lambda_permission" "edge_auth" {
  statement_id  = "HttpApiApprovalEdge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.edge_auth.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.front.execution_arn}/authorizers/${aws_apigatewayv2_authorizer.edge.id}"
}
