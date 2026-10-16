# The undo lab (owner, 2026-10-11): the smallest system on which WARDEN's undo of a recorded change can be proven on
# real AWS, end to end - a person's change, an alarm that follows it, the diagnosis, a passkey-approved plan, the
# write, the alarm reading OK again, and a rollback. Request-priced and inside the Free plan's allowances: one
# provisioned table (5 read / 10 write units), one queue and its dead-letter queue, two small functions, one schedule.
#
# What runs: every minute the schedule invokes the producer, which writes WRITES items over the same keys (the table
# does not grow) and sends a few messages; the consumer drains the queue. Each alarm follows ONE setting a person can
# change and WARDEN can set back (scripts/undo_lab.py makes those changes, as the fault-injection role):
#
#   orders-write-throttles   the table's write capacity cut            -> dynamodb_restore_capacity
#   producer-dropped         the producer's reserved concurrency at 0  -> lambda_restore_concurrency
#   producer-errors          the producer's timeout cut under its work -> lambda_restore_settings
#   tick-silent              the schedule disabled                     -> events_enable_rule
#   jobs-age                 the consumer's queue mapping disabled     -> lambda_enable_esm (exploratory: the alarm
#                            names the queue, the fix is on the function)
#
# Terraform never repairs a fault: every setting a fault changes is in `ignore_changes`, so an apply made while one is
# in place leaves it there (scripts/undo_lab.py restore sets the baseline back).
#
# Everything is named warden-<env>-lab-* (the prefix the environment's boundary and WARDEN's reader and actor roles
# scope to) and tagged Project=warden. An alarm's description never names its cause.

terraform {
  required_version = ">= 1.15.0, < 1.17.0" # CI pins 1.16.4, as terraform/fullstack
  required_providers {
    aws     = { source = "hashicorp/aws", version = ">= 6.0, < 7.0" }
    archive = { source = "hashicorp/archive", version = ">= 2.4, < 3.0" }
  }
  # No backend block on purpose: CI writes a backend_override.tf (S3) before init, as for terraform/fullstack.
}

provider "aws" {
  region = local.region
  default_tags {
    tags = local.tags
  }
}

data "aws_caller_identity" "current" {}

variable "region" {
  description = "AWS region override. Default: src/warden/data/environments.yaml aws_region (R17)."
  type        = string
  default     = null
}

variable "writes_per_minute" {
  description = "Items the producer writes each minute. Above 60 (what one write unit serves in a minute) so that a cut to one unit throttles once the table's burst allowance is spent; far under what 10 units serve."
  type        = number
  default     = 150
  validation {
    condition     = var.writes_per_minute > 60 && var.writes_per_minute <= 300
    error_message = "writes_per_minute must be above 60 and at most 300."
  }
}

locals {
  region       = coalesce(var.region, yamldecode(file("${path.module}/../../src/warden/data/environments.yaml")).aws_region)
  env          = terraform.workspace # the environment IS the workspace, as in terraform/fullstack
  environments = keys(yamldecode(file("${path.module}/../../src/warden/data/environments.yaml")).environments)
  name         = "warden-${local.env}-lab"
  # Only where its fault-injection role exists: environments.yaml `fault_environments`, never named here.
  lab_environments = yamldecode(file("${path.module}/../../src/warden/data/environments.yaml")).fault_environments
  tags = {
    Project     = "warden"
    Environment = local.env
    ManagedBy   = "terraform"
    Lifecycle   = "ephemeral"
  }
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/WardenEnvBoundary-${local.env}"
  write_units          = 10
  work_seconds         = 2
  write_seconds        = 12 # the producer stops writing after this long: a throttled table never times it out
  timeout_seconds      = 30
}

resource "terraform_data" "environment" {
  lifecycle {
    precondition {
      condition     = contains(local.environments, local.env) && contains(local.lab_environments, local.env)
      error_message = "The workspace must be an environment of environments.yaml in which the lab may exist (terraform workspace select -or-create dev)."
    }
  }
}

# --------------------------------------------------------------------------- the table and the queue

resource "aws_dynamodb_table" "orders" {
  name           = "${local.name}-orders"
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = local.write_units
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  lifecycle {
    ignore_changes = [read_capacity, write_capacity] # a fault's, never Terraform's to repair
  }

  depends_on = [terraform_data.environment]
}

resource "aws_sqs_queue" "jobs_dlq" {
  name                      = "${local.name}-jobs-dlq"
  message_retention_seconds = 86400
}

resource "aws_sqs_queue" "jobs" {
  name                       = "${local.name}-jobs"
  visibility_timeout_seconds = 60
  message_retention_seconds  = 86400
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.jobs_dlq.arn
    maxReceiveCount     = 3
  })
}

# --------------------------------------------------------------------------- the two functions

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# A throttled write is counted and logged, not raised: the table's own alarm follows the table, and the function's
# error alarm stays about the function. No client retries, so every throttle reaches the table's metric.
data "archive_file" "producer" {
  type        = "zip"
  output_path = "${path.module}/.build/producer.zip"
  source {
    filename = "index.py"
    content  = <<-PY
      import os
      import time

      import boto3
      from botocore.config import Config
      from botocore.exceptions import ClientError

      ONCE = Config(retries={"max_attempts": 1, "mode": "standard"})
      TABLE = boto3.resource("dynamodb", config=ONCE).Table(os.environ["TABLE"])
      SQS = boto3.client("sqs", config=ONCE)


      def handler(event, context):
          written = throttled = 0
          started = time.monotonic()
          for i in range(int(os.environ["WRITES"])):
              # A throttled write answers slowly: without this the run outlasted its timeout, and the function's
              # error alarm fired for the table's fault (seen live, 2026-10-11).
              if time.monotonic() - started > float(os.environ["WRITE_SECONDS"]):
                  break
              try:
                  TABLE.put_item(Item={"id": f"order-{i}", "at": int(time.time())})
                  written += 1
              except ClientError as exc:
                  if exc.response["Error"]["Code"] != "ProvisionedThroughputExceededException":
                      raise
                  throttled += 1
          for i in range(int(os.environ["MESSAGES"])):
              SQS.send_message(QueueUrl=os.environ["QUEUE"], MessageBody=f"job-{i}")
          time.sleep(float(os.environ["WORK_SECONDS"]))  # the work a too-short timeout cuts off
          print(f"written={written} throttled={throttled}")
          return {"written": written, "throttled": throttled}
    PY
  }
}

data "archive_file" "consumer" {
  type        = "zip"
  output_path = "${path.module}/.build/consumer.zip"
  source {
    filename = "index.py"
    content  = <<-PY
      def handler(event, context):
          records = event.get("Records", [])
          print(f"consumed={len(records)}")
          return {"consumed": len(records)}
    PY
  }
}

resource "aws_cloudwatch_log_group" "producer" {
  name              = "/aws/lambda/${local.name}-producer"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "consumer" {
  name              = "/aws/lambda/${local.name}-consumer"
  retention_in_days = 7
}

resource "aws_iam_role" "producer" {
  name                 = "${local.name}-producer"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
  permissions_boundary = local.permissions_boundary
}

data "aws_iam_policy_document" "producer" {
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.orders.arn]
  }
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.jobs.arn]
  }
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.producer.arn}:*"]
  }
}

resource "aws_iam_role_policy" "producer" {
  name   = "${local.name}-producer"
  role   = aws_iam_role.producer.id
  policy = data.aws_iam_policy_document.producer.json
}

resource "aws_lambda_function" "producer" {
  function_name    = "${local.name}-producer"
  role             = aws_iam_role.producer.arn
  runtime          = "python3.13"
  handler          = "index.handler"
  filename         = data.archive_file.producer.output_path
  source_code_hash = data.archive_file.producer.output_base64sha256
  timeout          = local.timeout_seconds
  memory_size      = 128

  environment {
    variables = {
      TABLE         = aws_dynamodb_table.orders.name
      QUEUE         = aws_sqs_queue.jobs.url
      WRITES        = tostring(var.writes_per_minute)
      MESSAGES      = "5"
      WORK_SECONDS  = tostring(local.work_seconds)
      WRITE_SECONDS = tostring(local.write_seconds)
    }
  }

  lifecycle {
    ignore_changes = [timeout, reserved_concurrent_executions] # a fault's, never Terraform's to repair
  }

  depends_on = [aws_cloudwatch_log_group.producer, aws_iam_role_policy.producer]
}

resource "aws_iam_role" "consumer" {
  name                 = "${local.name}-consumer"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
  permissions_boundary = local.permissions_boundary
}

data "aws_iam_policy_document" "consumer" {
  statement {
    actions   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
    resources = [aws_sqs_queue.jobs.arn]
  }
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.consumer.arn}:*"]
  }
}

resource "aws_iam_role_policy" "consumer" {
  name   = "${local.name}-consumer"
  role   = aws_iam_role.consumer.id
  policy = data.aws_iam_policy_document.consumer.json
}

resource "aws_lambda_function" "consumer" {
  function_name    = "${local.name}-consumer"
  role             = aws_iam_role.consumer.arn
  runtime          = "python3.13"
  handler          = "index.handler"
  filename         = data.archive_file.consumer.output_path
  source_code_hash = data.archive_file.consumer.output_base64sha256
  timeout          = 30
  memory_size      = 128

  depends_on = [aws_cloudwatch_log_group.consumer, aws_iam_role_policy.consumer]
}

resource "aws_lambda_event_source_mapping" "jobs" {
  event_source_arn = aws_sqs_queue.jobs.arn
  function_name    = aws_lambda_function.consumer.arn
  batch_size       = 10

  lifecycle {
    ignore_changes = [enabled] # a fault's, never Terraform's to repair
  }
}

# --------------------------------------------------------------------------- the schedule

resource "aws_cloudwatch_event_rule" "tick" {
  name                = "${local.name}-tick"
  description         = "The undo lab's clock: the producer, every minute."
  schedule_expression = "rate(1 minute)"

  lifecycle {
    ignore_changes = [state] # a fault's, never Terraform's to repair
  }
}

resource "aws_cloudwatch_event_target" "tick" {
  rule = aws_cloudwatch_event_rule.tick.name
  arn  = aws_lambda_function.producer.arn
}

resource "aws_lambda_permission" "tick" {
  statement_id  = "TheLabsOwnSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.producer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.tick.arn
}

# --------------------------------------------------------------------------- the alarms
#
# One-minute periods: the verify window follows the alarm's own evaluation time (tests/test_recover_window.py). No
# alarm action: the runtime's own rule takes every warden-<env>-* alarm's state change to intake.

resource "aws_cloudwatch_metric_alarm" "orders_write_throttles" {
  alarm_name          = "${local.name}-orders-write-throttles"
  alarm_description   = "Writes to the lab's orders table are being throttled."
  namespace           = "AWS/DynamoDB"
  metric_name         = "WriteThrottleEvents"
  dimensions          = { TableName = aws_dynamodb_table.orders.name }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 2
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "notBreaching"
}

# The schedule invokes the producer asynchronously: with no concurrency left Lambda DROPS those events and counts no
# throttle (seen live 2026-10-12: Throttles stayed empty, AsyncEventsDropped read 1 a minute).
resource "aws_cloudwatch_metric_alarm" "producer_dropped" {
  alarm_name          = "${local.name}-producer-dropped"
  alarm_description   = "Events sent to the lab's producer are being dropped."
  namespace           = "AWS/Lambda"
  metric_name         = "AsyncEventsDropped"
  dimensions          = { FunctionName = aws_lambda_function.producer.function_name }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 2
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "producer_errors" {
  alarm_name          = "${local.name}-producer-errors"
  alarm_description   = "Invocations of the lab's producer are failing."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.producer.function_name }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 2
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "tick_silent" {
  alarm_name          = "${local.name}-tick-silent"
  alarm_description   = "The lab's schedule has stopped invoking its target."
  namespace           = "AWS/Events"
  metric_name         = "Invocations"
  dimensions          = { RuleName = aws_cloudwatch_event_rule.tick.name }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 3
  comparison_operator = "LessThanThreshold"
  threshold           = 1
  treat_missing_data  = "breaching"
}

resource "aws_cloudwatch_metric_alarm" "jobs_age" {
  alarm_name          = "${local.name}-jobs-age"
  alarm_description   = "The oldest message in the lab's jobs queue is waiting too long."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateAgeOfOldestMessage"
  dimensions          = { QueueName = aws_sqs_queue.jobs.name }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  comparison_operator = "GreaterThanThreshold"
  threshold           = 300
  treat_missing_data  = "notBreaching"
}

# --------------------------------------------------------------------------- what the fault script reads

output "environment" {
  value = local.env
}

output "table" {
  value = aws_dynamodb_table.orders.name
}

output "write_units" {
  value = local.write_units
}

output "producer" {
  value = aws_lambda_function.producer.function_name
}

output "producer_timeout" {
  value = local.timeout_seconds
}

output "consumer" {
  value = aws_lambda_function.consumer.function_name
}

output "rule" {
  value = aws_cloudwatch_event_rule.tick.name
}

output "queue" {
  value = aws_sqs_queue.jobs.name
}

output "alarms" {
  value = {
    table_capacity       = aws_cloudwatch_metric_alarm.orders_write_throttles.alarm_name
    producer_concurrency = aws_cloudwatch_metric_alarm.producer_dropped.alarm_name
    producer_timeout     = aws_cloudwatch_metric_alarm.producer_errors.alarm_name
    schedule_disabled    = aws_cloudwatch_metric_alarm.tick_silent.alarm_name
    consumer_disabled    = aws_cloudwatch_metric_alarm.jobs_age.alarm_name
  }
}
