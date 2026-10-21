variable "environment" {
  description = "The WARDEN runtime environment this module serves (environments.yaml)."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}$", var.environment))
    error_message = "environment is a lower-case environments.yaml name."
  }
}

variable "page_topic_arn" {
  description = "The SNS topic that pages a person about WARDEN itself (its own on-call, never WARDEN's intake)."
  type        = string
}

variable "heartbeat_period_seconds" {
  description = "How often a worker beats (WARDEN_HEARTBEAT_SECONDS); the alarm reads one period at a time."
  type        = number
  default     = 300
}

variable "missed_beats_to_page" {
  description = "Consecutive periods without a beat before a person is paged."
  type        = number
  default     = 2
}

variable "page_repeat_minutes" {
  description = "How often an open page of WARDEN's own is said again, Slack and email, until a person acknowledges it (owner, 2026-10-16: 15)."
  type        = number
  default     = 15
  validation {
    condition     = var.page_repeat_minutes >= 5 && var.page_repeat_minutes <= 120
    error_message = "page_repeat_minutes is 5 to 120: the pager runs every five minutes."
  }
}

variable "temporal_key_warn_days" {
  description = "Days before a Temporal Cloud API key's end (SSM env/WARDEN_TEMPORAL_KEY_EXPIRES) that it pages."
  type        = number
  default     = 7
}

variable "audit_db_max_connections" {
  description = "Connections to the audit database above which, for 10 minutes, a person is paged."
  type        = number
  default     = 60
}

variable "audit_db_max_gib" {
  description = "Aurora audit storage, in GiB, above which a person is paged: far more than a year of incidents."
  type        = number
  default     = 10
}

variable "monthly_budget_usd" {
  description = "A monthly cost budget, before credits, that emails the page topic at 80% spent and 100% forecast. 0: none (it needs budgets:* for the deploy role and a topic policy for budgets.amazonaws.com)."
  type        = number
  default     = 0
  nullable    = false
}

variable "anchor_retention_days" {
  description = "How long an audit checkpoint's anchor cannot be deleted or overwritten by anyone (S3 Object Lock, COMPLIANCE mode). 1 in the lab; an install sets its own audit retention."
  type        = number
  default     = 1
  validation {
    condition     = var.anchor_retention_days >= 1
    error_message = "anchor_retention_days is at least 1."
  }
}

variable "vpc_id" {
  description = "The VPC the runtime runs in (the install's own network)."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets in at least two availability zones: workers, Lambdas and the audit database live here."
  type        = list(string)
  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "give private subnets in at least two availability zones."
  }
}

variable "audit_db_engine_version" {
  description = "Aurora PostgreSQL version of the audit database (17.10: the latest 17 minor AWS lists, read 2026-10-03)."
  type        = string
  default     = "17.10"
}

variable "audit_db_instances" {
  description = "Audit database instances: 2 (a writer and a reader in two zones) in production; 1 in the lab."
  type        = number
  default     = 2
}

variable "audit_db_max_acu" {
  description = "The audit database's ceiling in Aurora capacity units; it pauses to 0 when idle."
  type        = number
  default     = 2
}

variable "audit_db_backup_days" {
  description = "Automated backups and point-in-time recovery window, in days (register O4)."
  type        = number
  default     = 7
  nullable    = false
  validation {
    # The AWS Free plan refuses longer retention (FreeTierRestrictionError, 2026-10-09): a lab on it keeps 1 day.
    condition     = var.audit_db_backup_days >= 7 || (var.aws_free_plan && var.audit_db_backup_days >= 1)
    error_message = "keep at least 7 days of point-in-time recovery for the audit (1 only on the AWS Free plan)."
  }
}

variable "aws_free_plan" {
  description = "The account is on the AWS Free plan: its limits (backup retention, instance types) apply. Never in production."
  type        = bool
  default     = false
  nullable    = false
}

variable "watched_environments" {
  description = "The environments this runtime diagnoses and fixes: their platform-reader and actor roles (infra/iam/<env>/) are the only roles the worker may assume."
  type        = list(string)
  validation {
    condition     = length(var.watched_environments) > 0 && alltrue([for e in var.watched_environments : can(regex("^[a-z][a-z0-9-]{1,30}$", e))])
    error_message = "name at least one environment, lower-case environments.yaml names."
  }
}

variable "runtime_image" {
  description = "The runtime image (Dockerfile.runtime) by digest: the ECR URI ending @sha256:... that warden-runtime-deploy.yml built, signed and attested."
  type        = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.runtime_image))
    error_message = "runtime_image is pinned by digest (...@sha256:<64 hex>), never by a tag."
  }
}

variable "approval_domain" {
  description = "The approval page's domain - the passkeys' relying party (decision D17), e.g. approve.warden.<your domain>. Empty: no approval page."
  type        = string
  default     = ""
}

variable "approval_certificate_arn" {
  description = "An ACM certificate for approval_domain, in this Region (DNS-validated)."
  type        = string
  default     = ""
}

variable "api_rate_limit" {
  description = "Steady requests per second the HTTP API accepts across its routes (register N10: flooding)."
  type        = number
  default     = 10
}

variable "api_burst_limit" {
  description = "Burst the HTTP API accepts above the steady rate (register N10)."
  type        = number
  default     = 20
}

variable "worker_instances" {
  description = "Tasks of each zone's service, and the fewest instances, spread over the private subnets' zones."
  type        = number
  default     = 2
  validation {
    condition     = var.worker_instances >= 1
    error_message = "run at least one worker."
  }
}

variable "watched_db_egress" {
  description = "Let the workers reach a watched PostgreSQL at a public endpoint (Aurora express) on 5432."
  type        = bool
  default     = false
  nullable    = false
}

variable "paused" {
  description = "Between test windows: no worker task, no instance, no alarm intake, no self-pages for a silent worker. The audit, its keys, the secrets and the witness stay; set false and apply to resume."
  type        = bool
  default     = false
  nullable    = false
}

variable "zone_sizes" {
  description = "CPU units and memory (MiB) of each trust zone's task (register S15). The read zone holds the tripwire model."
  type        = map(object({ cpu = number, memory = number }))
  # llm: its synthetic incidents run the whole pipeline, detector included - peak 774 MiB over 72 h with a synthetic run
  # in 30 of them (2026-10-14..17), so 2048 is 2.6x the peak (cost plan, 2026-10-17; was 3072). read peaked at 1368 MiB:
  # 2048 would be under 1.5x, so it stays at 3072.
  default = {
    core   = { cpu = 256, memory = 512 }
    read   = { cpu = 1024, memory = 3072 } # Prompt Guard 2 (1.1 GB of weights) and torch: R47, 2026-10-14
    llm    = { cpu = 512, memory = 2048 }
    notify = { cpu = 256, memory = 512 } # Fargate's least memory for a quarter vCPU
    act    = { cpu = 256, memory = 512 }
    critic = { cpu = 256, memory = 512 } # Eldane: two model calls per plan, no local model
  }
  validation {
    condition     = toset(keys(var.zone_sizes)) == toset(["core", "read", "llm", "notify", "act", "critic"])
    error_message = "zone_sizes names every trust zone: core, read, llm, notify, act, critic."
  }
}

variable "permissions_boundary_arn" {
  description = "The permissions boundary every role here carries (the environment's WardenEnvBoundary-<env>, whose deploy role may create no role without it). Null: none."
  type        = string
  default     = null
}

variable "model_provider" {
  description = "The provider the llm zone calls (warden/src/warden/providers.py: gemini, bedrock, ...); empty: the CLI's default. It must be qualified (register M20) or every incident is escalated on the rules alone."
  type        = string
  default     = ""
}

variable "critic_provider" {
  description = "The provider Eldane, the AI critic, calls in the critic zone (warden/src/warden/eldane.py): anthropic, with the diagnosis's key, using for each incident the Claude model that did not diagnose it (data/providers.yaml critic); empty: no Eldane, and a person approves every plan as before."
  type        = string
  default     = "anthropic"
  validation {
    condition     = contains(["", "anthropic"], var.critic_provider)
    error_message = "critic_provider is empty or anthropic."
  }
}

variable "model" {
  description = "The pinned model id for model_provider (a dated id; register M15)."
  type        = string
  default     = ""
  validation {
    condition     = var.model == "" || can(regex("^[a-z0-9][a-z0-9.:_-]{1,80}$", var.model))
    error_message = "model is a plain model id."
  }
}

# Item 7b: WARDEN's spans (observability.py) over OTLP/HTTP to a collector of the owner's choosing. Off by default:
# nothing leaves the workers but what they send today. On, every zone gets OTEL_EXPORTER_OTLP_ENDPOINT and nothing
# else - the app reads it only when it is set, and the image carries the official exporter (pyproject's `otlp` extra,
# already in uv.lock). HTTPS on 443 only, through the egress the workers already have: no new port or rule. A
# collector that needs a key is not wired here (a key belongs in a secret slot, not an environment variable).
variable "otlp_exporter" {
  description = "Send WARDEN's OpenTelemetry spans over OTLP/HTTP to otlp_endpoint. Off by default."
  type        = bool
  default     = false
  nullable    = false
  validation {
    condition     = !var.otlp_exporter || var.otlp_endpoint != ""
    error_message = "otlp_exporter needs otlp_endpoint."
  }
}

variable "otlp_endpoint" {
  description = "The OTLP/HTTP collector's base URL (the exporter adds /v1/traces): https, port 443, no credentials or query in it. Read only when otlp_exporter is true."
  type        = string
  default     = ""
  nullable    = false
  validation {
    condition     = var.otlp_endpoint == "" || (can(regex("^https://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:443)?(/[A-Za-z0-9._~-]+)*/?$", var.otlp_endpoint)) && !can(regex("/v1/traces/?$", var.otlp_endpoint)))
    error_message = "otlp_endpoint is an https base URL on port 443 with a lower-case host, and no credentials, query, fragment or /v1/traces (the exporter adds it)."
  }
}
