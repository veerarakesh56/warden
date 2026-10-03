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
