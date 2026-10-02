variable "region" {
  description = "AWS region override. Default: src/warden/data/environments.yaml aws_region (R17)."
  type        = string
  default     = null
}

variable "kubernetes_version" {
  description = "EKS version. null = the current default. Pinned support type STANDARD (eks.tf) so an old version never slides into extended support at 0.60 USD/hour."
  type        = string
  default     = null
}

variable "eks_public_access_cidrs" {
  description = "Override for who may reach the EKS API endpoint. null means [/warden/<env>/tf/my_ip_cidr]. A GitHub-hosted runner deploying k8s needs [\"0.0.0.0/0\"] (IAM auth and an access entry still apply)."
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

