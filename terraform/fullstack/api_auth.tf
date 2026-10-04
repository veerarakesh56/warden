# Audit A-I-13: the shop's public HTTP API takes a bearer token on POST /checkout (GET /health stays open: it touches
# nothing). The token is made by an ephemeral random_password and written through Secrets Manager's write-only
# argument, so it is in neither the plan nor the state; the checkout Lambda checks it, the traffic Lambda - the only
# caller - sends it, each reading it from Secrets Manager. Bump api_token_version to rotate it.
ephemeral "random_password" "api_token" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "api_token" {
  name                    = "${local.name}-api-token"
  description             = "The bearer token POST /checkout requires (made at apply; in no plan or state)."
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "api_token" {
  secret_id                = aws_secretsmanager_secret.api_token.id
  secret_string_wo         = ephemeral.random_password.api_token.result
  secret_string_wo_version = var.api_token_version
}

variable "api_token_version" {
  description = "Raise to rotate the API's bearer token (A-I-13)."
  type        = number
  default     = 1
}
