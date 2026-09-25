variable "region" {
  description = "AWS region. The operator policies and the boundary are pinned to ap-south-2."
  type        = string
  default     = "ap-south-2"
}

variable "my_ip_cidr" {
  description = "YOUR public IP as a /32. Aurora and the EKS API endpoint are reachable from this address only. curl -s https://checkip.amazonaws.com"
  type        = string
  validation {
    condition     = var.my_ip_cidr != "0.0.0.0/0" && can(cidrhost(var.my_ip_cidr, 0))
    error_message = "my_ip_cidr must be a real CIDR and must not be 0.0.0.0/0."
  }
}

variable "db_master_password" {
  description = "Aurora master password for warden_admin. ONLY through TF_VAR_db_master_password, generated: python -c \"import secrets; print(secrets.token_urlsafe(24))\". No default, never -var, never a tfvars file. It is stored in plaintext in terraform state."
  type        = string
  sensitive   = true
  validation {
    condition     = length(var.db_master_password) >= 16
    error_message = "db_master_password must be at least 16 characters."
  }
}

variable "permissions_boundary_name" {
  description = "IAM permissions boundary every role here carries. The boundary itself DENIES creating a role without it, so leaving this empty makes CreateRole fail - loudly, before anything is built without the ceiling."
  type        = string
  default     = "WardenProvingGroundBoundary"
}

variable "aurora_engine_version" {
  description = "Aurora PostgreSQL 16 minor version that ap-south-2 offers for db.serverless. Checked 2026-09-25: 16.8, 16.9, 16.10, 16.11, 16.13, 16.14 (16.6 exists there only as 16.6-limitless). Re-check: aws rds describe-orderable-db-instance-options --engine aurora-postgresql --db-instance-class db.serverless --region ap-south-2 --query \"OrderableDBInstanceOptions[].EngineVersion\""
  type        = string
  default     = "16.14"
}

variable "kubernetes_version" {
  description = "EKS version. null = the current default. Pinned support type STANDARD (eks.tf) so an old version never slides into extended support at 0.60 USD/hour."
  type        = string
  default     = null
}

variable "eks_public_access_cidrs" {
  description = "Override for who may reach the EKS API endpoint. null means [my_ip_cidr]. A GitHub-hosted runner deploying k8s needs [\"0.0.0.0/0\"] (IAM auth and an access entry still apply)."
  type        = list(string)
  default     = null
}

variable "eks_admin_principal_arns" {
  description = "Extra IAM principals (e.g. the CI deploy role) given cluster-admin access entries, besides whoever runs terraform."
  type        = list(string)
  default     = []
}

variable "budget_usd" {
  description = "Monthly cost budget for the account, in USD (the owner's cap for Wave 4: 50)."
  type        = number
  default     = 50
}

variable "budget_email" {
  description = "Where the budget alarms go. Set it in terraform.tfvars (gitignored) - never in the repo."
  type        = string
}
