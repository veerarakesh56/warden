# AWS Config's recorder (B15): WARDEN's undo (revert_change, platforms/aws.py) reads what it recorded. One recorder per
# account and Region, made once by the owner (docs/SETUP.md, "AWS Config"). This stack ADOPTS it and never creates a
# second: every instance below exists only together with an import block of the same key, so a name that is not in
# the account fails the plan ("Cannot import non-existent remote object") instead of creating anything. Nothing here
# is managed until SSM /warden/<env>/tf/config_recorder_name names the recorder ("default" when made in the console);
# the delivery channel also needs tf/config_bucket.
#
# Adopted as it is: the recorder's role, what it records and the channel's settings are the owner's (a Control Tower
# or console role, all supported types, a KMS key or an SNS topic on the channel all stay) - Terraform writes none of
# them (ignore_changes), so it never calls PutConfigurationRecorder or PutDeliveryChannel. What it holds: neither is
# destroyed (prevent_destroy; the deploy role may not stop or delete them), and the recorder stays ON (the status). That
# it records every type the undo reads is checked by scripts/check_live_config.py.
locals {
  config_recorder = toset(compact([lookup(local.tf, "config_recorder_name", "")]))
  config_channel  = lookup(local.tf, "config_bucket", "") == "" ? toset([]) : toset([for r in local.config_recorder : lookup(local.tf, "config_delivery_channel_name", "default")])
}

import {
  for_each = local.config_recorder
  to       = aws_config_configuration_recorder.this[each.key]
  id       = each.key
}

resource "aws_config_configuration_recorder" "this" {
  for_each = local.config_recorder
  name     = each.key
  role_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
  lifecycle {
    prevent_destroy = true
    ignore_changes  = all # the owner's definition, as imported
  }
}

import {
  for_each = local.config_channel
  to       = aws_config_delivery_channel.this[each.key]
  id       = each.key
}

resource "aws_config_delivery_channel" "this" {
  for_each       = local.config_channel
  name           = each.key
  s3_bucket_name = lookup(local.tf, "config_bucket", "")
  depends_on     = [aws_config_configuration_recorder.this]
  lifecycle {
    prevent_destroy = true
    ignore_changes  = all # the owner's settings (KMS key, prefix, SNS topic, snapshot delivery), as imported
  }
}

import {
  for_each = local.config_recorder
  to       = aws_config_configuration_recorder_status.this[each.key]
  id       = each.key
}

# The one thing Terraform holds: the recorder records. A stopped recorder is started again (StartConfigurationRecorder).
resource "aws_config_configuration_recorder_status" "this" {
  for_each   = local.config_recorder
  name       = each.key
  is_enabled = true
  depends_on = [aws_config_delivery_channel.this]
  lifecycle {
    prevent_destroy = true
  }
}
