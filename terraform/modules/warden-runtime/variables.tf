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
  validation {
    condition     = var.audit_db_backup_days >= 7
    error_message = "keep at least 7 days of point-in-time recovery for the audit."
  }
}

variable "watched_environments" {
  description = "The environments this runtime diagnoses and fixes: their platform-reader and actor roles (iam/<env>/) are the only roles the worker may assume."
  type        = list(string)
  validation {
    condition     = length(var.watched_environments) > 0 && alltrue([for e in var.watched_environments : can(regex("^[a-z][a-z0-9-]{1,30}$", e))])
    error_message = "name at least one environment, lower-case environments.yaml names."
  }
}

variable "bedrock_model_arns" {
  description = "The Bedrock inference profile and the foundation-model ARNs it routes to (decision D12): the only models the worker may invoke. Empty: no Bedrock."
  type        = list(string)
  default     = []
}

variable "runtime_image" {
  description = "The runtime image (Dockerfile.runtime) by digest: the ECR URI ending @sha256:... that runtime.yml built, signed and attested."
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
  description = "Workers (one ECS task per EC2 instance), spread over the private subnets' zones."
  type        = number
  default     = 2
  validation {
    condition     = var.worker_instances >= 1
    error_message = "run at least one worker."
  }
}

variable "worker_instance_type" {
  description = "The EC2 instance type of the ECS capacity provider (x86_64: the runtime image is built for it)."
  type        = string
  default     = "t3.small"
}

variable "worker_cpu" {
  description = "CPU units of the worker task."
  type        = number
  default     = 1024
}

variable "worker_memory" {
  description = "Memory (MiB) of the worker task."
  type        = number
  default     = 1536
}

variable "permissions_boundary_arn" {
  description = "The permissions boundary every role here carries (the environment's WardenEnvBoundary-<env>, whose deploy role may create no role without it). Null: none."
  type        = string
  default     = null
}
