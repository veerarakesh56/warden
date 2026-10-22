# Decision D5: every secret the runtime reads lives in Secrets Manager, as warden/<env>/<name> - the names
# src/warden/settings.py's SECRETS loads (secret_id). Terraform creates the slots only; a person sets each value in the
# console, and no secret value is ever in Terraform state. Only the secrets a zone or a Lambda of this runtime reads
# have a slot (settings.ZONE_SECRETS, settings.LAMBDA_SECRETS; tests/test_runtime_module_g6.py holds the list to them):
# a slot nobody reads is one more place a value could be left (secrets audit, 2026-10-16).
locals {
  secrets = toset([
    "slack-bot-token", "slack-webhook", "stack-db-writer-dsn", "stack-db-reader-dsn", "anthropic-api-key",
    "temporal-key", "temporal-api-key", "github-token",
    "db-admin-dsn",        # the terminate login's DSN, no password (WARDEN_DB_TERMINATE_DSN, platforms/db.py): the act zone's alone
    "slack-client-secret", # Sign in with Slack on the approval page (slack_login.py): the approval Lambda's alone
    "slack-app-token",     # the discussion channel's Socket Mode connection (discuss.py): the notify zone's alone
    "datadog-api-key",     # Datadog's API key (datadog.py), with the scoped application key below: the read zone's
    #                        and the webhook Lambda's (it asks whether a monitor is alerting). The proving ground's
    #                        agent sends with a key of its own, warden-<stack>-datadog-api-key
    "datadog-app-key", # Datadog's application key, scoped to logs_read_data, logs_read_index_data, apm_read,
    #                    timeseries_query, events_read, monitors_read
    "datadog-webhook-token", # the bearer secret Datadog's webhook sends (webhooks.receive_datadog); set by the setup
    #                          script together with the webhook itself
    "github-actions-token", # B17: dispatches the infra workflow's apply-plan (platforms/infra.py); the act zone's alone.
    #                         A fine-grained token on the one repository: Actions: Read and write, and Contents:
    #                         Read (the branch head re-read before dispatching), nothing else
    "github-read-token", # the read-only GitHub token (tools.github_read_token): the deploy's commits and code review's
    #                      findings on its pull request; the read zone's alone
    # Register S15: each zone's own Temporal Cloud service account key (settings.PER_ZONE).
    "temporal-api-key-core", "temporal-api-key-read", "temporal-api-key-llm", "temporal-api-key-notify",
    "temporal-api-key-act", "temporal-api-key-critic",
    "eldane-key",         # Eldane's own Ed25519 signing key (PEM): the critic zone's alone
    "eldane-slack-token", # Eldane's own Slack bot token (eldane_slack.py, B2): the critic zone's alone; it only posts
  ])
}

resource "aws_secretsmanager_secret" "runtime" {
  for_each                = local.secrets
  name                    = "warden/${var.environment}/${each.key}"
  description             = "WARDEN ${var.environment}: ${each.key} (set by a person; read by the runtime only)"
  recovery_window_in_days = 7
  tags                    = { Project = "warden", Environment = var.environment }
}
