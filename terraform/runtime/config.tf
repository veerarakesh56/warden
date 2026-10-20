# AWS Config's recorder (B15): WARDEN's undo (revert_change, platforms/aws.py) reads what it recorded. One recorder per
# account and Region, made once by the owner (docs/SETUP.md, "AWS Config"). This stack ADOPTS it and never creates a
# second: every instance below exists only together with an import block of the same key, so a name that is not in
# the account fails the plan ("Cannot import non-existent remote object") instead of creating anything. Nothing here
# is managed until SSM /warden/<env>/tf/config_recorder_name names the recorder ("default" when made in the console);
# the delivery channel also needs tf/config_bucket. The deploy role may not delete or stop either (deploy-config).
locals {
  config_recorder = toset(compact([lookup(local.tf, "config_recorder_name", "")]))
  config_channel  = lookup(local.tf, "config_bucket", "") == "" ? toset([]) : toset([for r in local.config_recorder : lookup(local.tf, "config_delivery_channel_name", "default")])
  # Every resource type the undo reads (src/warden/platforms/aws.py; tests/test_config_recorder.py holds the two equal).
  config_types = [
    "AWS::ApiGateway::Stage", "AWS::AutoScaling::AutoScalingGroup", "AWS::DynamoDB::Table", "AWS::EC2::RouteTable",
    "AWS::ECS::Service", "AWS::Kinesis::Stream", "AWS::Lambda::Function", "AWS::SQS::Queue",
  ]
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
  recording_group {
    all_supported                 = false
    include_global_resource_types = false
    resource_types                = local.config_types
    recording_strategy {
      use_only = "INCLUSION_BY_RESOURCE_TYPES"
    }
  }
  recording_mode {
    recording_frequency = "CONTINUOUS" # a change between two daily snapshots would be lost
  }
  lifecycle {
    prevent_destroy = true
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
  }
}

import {
  for_each = local.config_recorder
  to       = aws_config_configuration_recorder_status.this[each.key]
  id       = each.key
}

resource "aws_config_configuration_recorder_status" "this" {
  for_each   = local.config_recorder
  name       = each.key
  is_enabled = true
  depends_on = [aws_config_delivery_channel.this]
  lifecycle {
    prevent_destroy = true
  }
}
