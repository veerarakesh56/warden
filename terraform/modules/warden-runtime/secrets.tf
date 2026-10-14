# Decision D5: every secret the runtime reads lives in Secrets Manager, as warden/<env>/<name> - the names
# src/warden/settings.py's SECRETS loads (secret_id). Terraform creates the slots only; a person sets each value in the
# console, and no secret value is ever in Terraform state (tests/test_runtime_module_g6.py holds the list to the code).
locals {
  secrets = toset([
    "slack-bot-token", "slack-webhook", "teams-webhook", "webhook-url",
    "db-dsn", "db-admin-dsn", "stack-db-writer-dsn", "stack-db-reader-dsn",
    "gemini-api-key", "google-api-key", "openai-api-key", "anthropic-api-key",
    "audit-key-passphrase", "temporal-key", "temporal-api-key", "github-token", "temporal-key-previous",
    "audit-dsn", "alertmanager-token", "alertmanager-token-previous", "pagerduty-routing-key",
    "slack-client-secret", # Sign in with Slack on the approval page (slack_login.py): the approval Lambda's alone
    "slack-app-token",     # the discussion channel's Socket Mode connection (discuss.py): the notify zone's alone
    "datadog-api-key",     # Datadog's API key (datadog.py): the read zone's, with the scoped application key below;
    #                        the proving ground's agent sends with it too
    "datadog-app-key", # Datadog's application key, scoped to logs_read_data, apm_read, timeseries_query,
    #                    events_read, monitors_read
    "grafana-read-token",    # Grafana's read-only access-policy token (grafana.py): the read zone's alone
    "datadog-webhook-token", # the bearer secret Datadog's webhook sends (webhooks.receive_datadog); set by the setup
    #                          script together with the webhook itself
    # Register S15: each zone's own Temporal Cloud service account key (settings.PER_ZONE).
    "temporal-api-key-core", "temporal-api-key-read", "temporal-api-key-llm", "temporal-api-key-notify",
    "temporal-api-key-act",
  ])
}

resource "aws_secretsmanager_secret" "runtime" {
  for_each                = local.secrets
  name                    = "warden/${var.environment}/${each.key}"
  description             = "WARDEN ${var.environment}: ${each.key} (set by a person; read by the runtime only)"
  recovery_window_in_days = 7
  tags                    = { Project = "warden", Environment = var.environment }
}
