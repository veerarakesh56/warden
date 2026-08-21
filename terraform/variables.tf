variable "name" {
  description = "Name prefix for every resource this module creates."
  type        = string
  default     = "aegis"
}

variable "image" {
  description = "Container image URI for AEGIS (e.g. <acct>.dkr.ecr.<region>.amazonaws.com/aegis:v0.1.0)."
  type        = string
}

variable "cluster_arn" {
  description = "Existing ECS cluster to run the task in. Not created here - clusters are shared infrastructure and should outlive this module."
  type        = string
}

variable "subnet_ids" {
  description = "PRIVATE subnet IDs. AEGIS reads logs and metrics; it has no reason to sit in a public subnet."
  type        = list(string)

  validation {
    condition     = length(var.subnet_ids) > 0
    error_message = "At least one private subnet is required."
  }
}

variable "vpc_id" {
  description = "VPC the task runs in."
  type        = string
}

variable "anthropic_secret_arn" {
  description = "Secrets Manager ARN holding the Anthropic API key. Passed by reference - the key is never a Terraform variable, so it never lands in state."
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch log retention. Incident context is sensitive; do not keep it forever by accident."
  type        = number
  default     = 30
}

variable "task_cpu" {
  description = "Fargate CPU units. AEGIS is I/O bound - it waits on tools and the model."
  type        = string
  default     = "512"
}

variable "task_memory" {
  description = "Fargate memory (MiB)."
  type        = string
  default     = "1024"
}

variable "max_usd_per_run" {
  description = "Hard cost ceiling per run, enforced in application code (LLMClient), not just billed after the fact."
  type        = string
  default     = "0.50"
}

variable "tool_timeout_seconds" {
  description = "Wall-clock ceiling per context tool."
  type        = string
  default     = "5.0"
}

variable "otlp_endpoint" {
  description = "Optional OTLP collector endpoint for traces. Empty string disables export."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
