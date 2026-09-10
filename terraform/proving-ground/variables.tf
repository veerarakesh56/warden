variable "region" {
  description = "AWS region. Anything works; pick the one closest to you - latency here is only your own patience."
  type        = string
  default     = "ap-south-2"
}

variable "name" {
  description = "Name prefix. Also the ECS cluster name WARDEN reads evidence from."
  type        = string
  default     = "warden-pg"
}

variable "capacity_provider" {
  description = <<-EOT
    FARGATE_SPOT (default, ~70% cheaper) or FARGATE.

    ⚠ Fargate Spot is NOT available in every region, and the whole benchmark runs on it. In a region
    without it, every task fails to place, the service never reaches a healthy baseline, and Wave 1
    measures nothing while looking like a catastrophic failure of the tool. Verify before applying:

      aws ecs put-cluster-capacity-providers --help   # no: this does not tell you
      aws ec2 describe-instance-type-offerings ...    # no: Fargate is not an instance type

    There is no clean API for it. The honest check is to apply and watch whether tasks reach RUNNING;
    if they sit in PROVISIONING and stop with a capacity error, set this to FARGATE and re-apply. On
    FARGATE the cost estimate in outputs.tf roughly triples and is still under a cent an hour.
  EOT
  type        = string
  default     = "FARGATE_SPOT"

  validation {
    condition     = contains(["FARGATE_SPOT", "FARGATE"], var.capacity_provider)
    error_message = "capacity_provider must be FARGATE_SPOT or FARGATE."
  }
}

variable "my_ip_cidr" {
  description = "YOUR public IP as a /32, e.g. \"203.0.113.7/32\". Everything reachable from outside the VPC (RDS, the EKS API endpoint) is restricted to this. Find it with: curl -s https://checkip.amazonaws.com"
  type        = string

  validation {
    # 0.0.0.0/0 would open a database with a known username to the internet. Refuse it outright
    # rather than trusting a comment nobody reads.
    condition     = var.my_ip_cidr != "0.0.0.0/0" && can(cidrhost(var.my_ip_cidr, 0))
    error_message = "my_ip_cidr must be a real CIDR and must not be 0.0.0.0/0."
  }
}

variable "budget_email" {
  description = "Where the budget alarm goes. An alarm nobody receives is not a guard."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.budget_email))
    error_message = "budget_email must be an email address."
  }
}

variable "budget_usd" {
  description = "Monthly budget for the whole account, in USD. The point is to be told early, so keep it small."
  type        = number
  default     = 5
}

## ⭐ COST SWITCHES. Both default to FALSE, and that is the single most effective cost control in
## this directory — far more than any instance-size choice.
##
## The dominant risk is not the hourly rate, it is FORGETTING. An EKS control plane left running for
## a month is ~$73 and an RDS instance ~$15, while Wave 1 of the benchmark touches neither. Creating
## them by default would mean every ECS-only run paid for two idle services and carried a month-sized
## tail risk for nothing.
##
## Turn one on for the wave that needs it, and only for as long as that wave runs.

variable "enable_eks" {
  description = "Create the EKS cluster. THE EXPENSIVE ONE: $0.10/hour for the control plane whether or not anything runs on it, plus a node. Needed only by Wave 2."
  type        = bool
  default     = false
}

variable "enable_rds" {
  description = "Create the RDS instance. ~$0.021/hour, or free for the first 12 months on a new account. Needed only by Wave 3."
  type        = bool
  default     = false
}

variable "db_password" {
  description = "RDS master password. Generated per run by the harness and passed with -var; never written to a file. Ignored entirely when enable_rds is false. A throwaway instance reachable only from my_ip_cidr, but it is still a real credential."
  type        = string
  sensitive   = true
  # Empty default so an ECS-only run (the common case) needs no password at all. The RDS resource
  # is guarded by a validation that refuses to build with a blank one.
  default = ""
}

variable "healthy_image" {
  description = "A small public image for the HEALTHY task definition revision. Public ECR is used rather than Docker Hub so an anonymous pull is not rate-limited."
  type        = string
  default     = "public.ecr.aws/docker/library/python:3.12-alpine"
}
