# WARDEN's own runtime (G6): the root configuration that deploys terraform/modules/warden-runtime for one runtime
# environment - `ops` - from .github/workflows/runtime.yml, with the runtime image that workflow built, signed and
# attested, by digest. Infrastructure only, like terraform/fullstack: no code is built here.
#
# THE ENVIRONMENT IS THE WORKSPACE (`terraform workspace select -or-create ops`), refused unless it is environments.yaml's
# `runtime:` - WARDEN's own environment, never an application one. Every per-install value comes from SSM Parameter Store, /warden/<env>/tf/*, never a tfvars file and never a
# literal in this repository (owner rule: no environment, region or account literals in code).
terraform {
  required_version = ">= 1.15.0, < 1.17.0" # CI pins 1.16.4; a later minor is a deliberate change
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.0, < 7.0" }
  }
  # No backend block on purpose: CI writes a backend_override.tf (S3) before init, as for terraform/fullstack.
}

variable "runtime_image" {
  description = "The runtime image by digest (runtime.yml passes the digest it signed and attested)."
  type        = string
}

locals {
  config  = yamldecode(file("${path.module}/../../src/warden/data/environments.yaml"))
  env     = terraform.workspace
  runtime = local.config.runtime
  # Per-install values; the optional ones may be absent.
  tf = { for i, name in data.aws_ssm_parameters_by_path.tf.names :
  trimprefix(name, "/warden/${local.env}/tf/") => nonsensitive(data.aws_ssm_parameters_by_path.tf.values[i]) }
  csv = { for k, v in local.tf : k => [for x in split(",", v) : trimspace(x) if trimspace(x) != ""] }
}

provider "aws" {
  region = local.config.aws_region
  default_tags {
    tags = { Project = "warden", Environment = local.env, ManagedBy = "terraform" }
  }
}

data "aws_caller_identity" "current" {}

data "aws_ssm_parameters_by_path" "tf" {
  path = "/warden/${local.env}/tf"
}

resource "terraform_data" "environment_is_known" {
  lifecycle {
    precondition {
      condition     = local.env == local.runtime
      error_message = "the workspace must be the runtime environment, environments.yaml's runtime: (terraform workspace select -or-create <it>)."
    }
    precondition {
      condition     = alltrue([for k in ["page_topic_arn", "watched_environments"] : contains(keys(local.tf), k)])
      error_message = "set /warden/<env>/tf/page_topic_arn and watched_environments in SSM first."
    }
  }
}

module "runtime" {
  source                   = "../modules/warden-runtime"
  environment              = local.env
  runtime_image            = var.runtime_image
  vpc_id                   = aws_vpc.runtime.id # network.tf
  private_subnet_ids       = aws_subnet.private[*].id
  page_topic_arn           = lookup(local.tf, "page_topic_arn", "")
  watched_environments     = lookup(local.csv, "watched_environments", [])
  approval_domain          = lookup(local.tf, "approval_domain", "")
  approval_certificate_arn = lookup(local.tf, "approval_certificate_arn", "")
  bedrock_model_arns       = lookup(local.csv, "bedrock_model_arns", [])
  audit_db_instances       = tonumber(lookup(local.tf, "audit_db_instances", "2"))
  worker_instances         = tonumber(lookup(local.tf, "worker_instances", "2"))
  worker_instance_types    = lookup(local.csv, "worker_instance_types", null) # the Free plan: free-tier-eligible types
  audit_db_backup_days     = try(tonumber(local.tf["audit_db_backup_days"]), null)
  aws_free_plan            = lookup(local.tf, "aws_free_plan", "false") == "true"
  permissions_boundary_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/WardenEnvBoundary-${local.env}"
  # The model the llm zone calls (decision D12; the owner's 2026-10-04 window: gemini). Unqualified, it is refused
  # (register M20) and every incident is escalated on the rules alone.
  model_provider = lookup(local.tf, "model_provider", "")
  model          = lookup(local.tf, "model", "")
  depends_on     = [terraform_data.environment_is_known]
}

# A slot the owner made by hand before the first apply (the Slack webhook, moved off the laptop in W0-now) is adopted,
# not created again: the first apply failed with ResourceExistsException (2026-10-09). Once in state, an import is a no-op.
locals {
  adopt = ["slack-webhook"]
}

data "aws_secretsmanager_secrets" "adopt" {
  for_each = toset(local.adopt)
  filter {
    name   = "name"
    values = ["warden/${local.env}/${each.key}"] # a prefix match: only an exact, single hit is adopted below
  }
}

import {
  for_each = { for n in local.adopt : n => one(data.aws_secretsmanager_secrets.adopt[n].arns)
  if data.aws_secretsmanager_secrets.adopt[n].names == toset(["warden/${local.env}/${n}"]) }
  to = module.runtime.aws_secretsmanager_secret.runtime[each.key]
  id = each.value
}

output "runtime" {
  description = "What the runtime needs set elsewhere: the audit key alias, the anchor bucket, the front door, the approval domain's DNS target."
  value = {
    audit_signer_key_id = module.runtime.audit_signer_key_id
    anchor_bucket       = module.runtime.anchor_bucket
    front_door_url      = module.runtime.front_door_url
    approval_dns_target = module.runtime.approval_dns_target
    audit_db_endpoint   = module.runtime.audit_db_endpoint
    migrate_function    = module.runtime.migrate_function
  }
}
