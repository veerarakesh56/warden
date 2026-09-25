# Messaging (SQS, SNS), the six Lambdas, their triggers (SQS mappings, EventBridge, API Gateway).
#
# ⛔ The Lambdas are created from a PLACEHOLDER zip and every code field is ignored afterwards. The
# real code is deployed by `scripts/deploy_fullstack_apps.py deploy lambdas`, which also publishes a
# version and moves checkout's `live` alias. Configuration (env, timeout, memory, VPC) stays here.

# --------------------------------------------------------------------------- SQS + SNS

resource "aws_sqs_queue" "dlq" {
  for_each                  = toset(["orders", "notifications"])
  name                      = "${local.name}-${each.key}-dlq"
  message_retention_seconds = 345600
}

resource "aws_sqs_queue" "main" {
  for_each = {
    orders        = 120 # visibility >= 6 x the order-processor timeout (20 s)
    notifications = 60
  }
  name                       = "${local.name}-${each.key}"
  visibility_timeout_seconds = each.value
  message_retention_seconds  = 86400
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq[each.key].arn
    maxReceiveCount     = 3
  })
}

resource "aws_sns_topic" "order_events" {
  name = "${local.name}-order-events"
}

# fs-08 replaces this policy with one that no longer allows the topic; the harness restores it.
resource "aws_sqs_queue_policy" "notifications" {
  queue_url = aws_sqs_queue.main["notifications"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowOrderEventsTopic"
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.main["notifications"].arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_sns_topic.order_events.arn } }
    }]
  })
}

resource "aws_sns_topic_subscription" "notifications" {
  topic_arn            = aws_sns_topic.order_events.arn
  protocol             = "sqs"
  endpoint             = aws_sqs_queue.main["notifications"].arn
  raw_message_delivery = true
}

# --------------------------------------------------------------------------- placeholder code

data "archive_file" "placeholder" {
  type        = "zip"
  output_path = "${path.module}/.terraform/placeholder-lambda.zip"
  source {
    filename = "app.py"
    content  = <<-PY
      # Placeholder created by terraform/fullstack. The APPS pipeline replaces this code:
      #   python scripts/deploy_fullstack_apps.py deploy lambdas
      def handler(event, context):
          print("placeholder code: the apps pipeline has not deployed this function yet")
          return {"statusCode": 503, "body": "not deployed"}
    PY
  }
}

# --------------------------------------------------------------------------- functions

locals {
  db_env = {
    DB_NAME    = aws_rds_cluster.aurora.database_name
    SECRET_ARN = aws_secretsmanager_secret.db_app.arn
  }

  lambdas = {
    checkout = {
      timeout = 10
      memory  = 256
      in_vpc  = false
      env = {
        TABLE_NAME = aws_dynamodb_table.carts.name
        TOPIC_ARN  = aws_sns_topic.order_events.arn
        # Fault flags at their baseline values, so the variable NAMES never change during a fault
        # (scenarios/ops_fullstack.py FLAGS): fs-01 sets v2, fs-02 sets 2000.
        CHECKOUT_PAYLOAD_SCHEMA = "v1"
        DDB_EXTRA_LATENCY_MS    = "0"
      }
    }
    order-processor = {
      timeout = 20
      memory  = 256
      in_vpc  = true
      env = merge(local.db_env, {
        DB_HOST = aws_rds_cluster.aurora.endpoint # fs-14 / fs-15 repoint this
      })
    }
    notifier = {
      timeout = 10
      memory  = 128
      in_vpc  = false
      env     = {}
    }
    reconciler = {
      timeout = 90 # fs-16 makes the lookup scan; let it run long enough to be seen
      memory  = 256
      in_vpc  = true
      env = merge(local.db_env, {
        DB_HOST          = aws_rds_cluster.aurora.reader_endpoint
        REDIS_HOST       = aws_elasticache_replication_group.redis.primary_endpoint_address
        RECONCILE_LOOKUP = "by_id" # fs-16 sets by_customer
      })
    }
    traffic = {
      timeout = 55
      memory  = 128
      in_vpc  = false
      env = {
        API_URL           = aws_apigatewayv2_api.api.api_endpoint
        ALB_URL           = "http://${aws_lb.orders.dns_name}"
        ORDERS_QUEUE_URL  = aws_sqs_queue.main["orders"].id
        CHECKOUTS_PER_MIN = "10"
        ORDERS_PER_MIN    = "10"
      }
    }
    ops = {
      timeout = 60
      memory  = 256
      in_vpc  = true
      env = {
        REDIS_HOST = aws_elasticache_replication_group.redis.primary_endpoint_address
      }
    }
  }

  # Least privilege per function. Each statement has its own Sid so a fault (fs-05) can remove
  # exactly one grant and the harness can put exactly that one back.
  lambda_statements = {
    checkout = [
      { Sid = "WriteCarts", Effect = "Allow", Action = ["dynamodb:PutItem"], Resource = [aws_dynamodb_table.carts.arn] },
      { Sid = "PublishOrderEvents", Effect = "Allow", Action = ["sns:Publish"], Resource = [aws_sns_topic.order_events.arn] },
    ]
    order-processor = [
      { Sid = "ConsumeOrders", Effect = "Allow", Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], Resource = [aws_sqs_queue.main["orders"].arn] },
      { Sid = "ReadDbSecret", Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = [aws_secretsmanager_secret.db_app.arn] },
    ]
    notifier = [
      { Sid = "ConsumeNotifications", Effect = "Allow", Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], Resource = [aws_sqs_queue.main["notifications"].arn] },
    ]
    reconciler = [
      { Sid = "ReadDbSecret", Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = [aws_secretsmanager_secret.db_app.arn] },
    ]
    traffic = [
      { Sid = "SendOrders", Effect = "Allow", Action = ["sqs:SendMessage"], Resource = [aws_sqs_queue.main["orders"].arn] },
    ]
    ops = []
  }
}

resource "aws_iam_role" "lambda" {
  for_each             = local.lambdas
  name                 = "${local.name}-${each.key}" # the harness default names it after the function
  permissions_boundary = local.permissions_boundary
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda" {
  for_each   = local.lambdas
  role       = aws_iam_role.lambda[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/${each.value.in_vpc ? "AWSLambdaVPCAccessExecutionRole" : "AWSLambdaBasicExecutionRole"}"
}

resource "aws_iam_role_policy" "lambda" {
  for_each = { for k, v in local.lambda_statements : k => v if length(v) > 0 }
  name     = "${local.name}-${each.key}"
  role     = aws_iam_role.lambda[each.key].id
  policy   = jsonencode({ Version = "2012-10-17", Statement = each.value })
}

resource "aws_cloudwatch_log_group" "lambda" {
  for_each          = local.lambdas
  name              = "/aws/lambda/${local.name}-${each.key}"
  retention_in_days = 3
}

resource "aws_lambda_function" "fn" {
  for_each         = local.lambdas
  function_name    = "${local.name}-${each.key}"
  role             = aws_iam_role.lambda[each.key].arn
  runtime          = "python3.12"
  handler          = "app.handler"
  filename         = data.archive_file.placeholder.output_path
  source_code_hash = data.archive_file.placeholder.output_base64sha256
  timeout          = each.value.timeout
  memory_size      = each.value.memory
  publish          = each.key == "checkout" # only checkout has an alias

  dynamic "environment" {
    for_each = length(each.value.env) > 0 ? [1] : []
    content {
      variables = each.value.env
    }
  }

  dynamic "vpc_config" {
    for_each = each.value.in_vpc ? [1] : []
    content {
      subnet_ids         = aws_subnet.private[*].id
      security_group_ids = [aws_security_group.lambda.id]
    }
  }

  lifecycle {
    # The APPS pipeline owns the code. Terraform owns configuration.
    ignore_changes = [filename, source_code_hash, s3_bucket, s3_key, s3_object_version, image_uri, publish]
  }

  depends_on = [aws_iam_role_policy_attachment.lambda, aws_cloudwatch_log_group.lambda]
}

resource "aws_lambda_alias" "checkout_live" {
  name             = "live"
  function_name    = aws_lambda_function.fn["checkout"].function_name
  function_version = aws_lambda_function.fn["checkout"].version
  lifecycle {
    ignore_changes = [function_version] # moved by the apps pipeline (and by fs-01)
  }
}

# --------------------------------------------------------------------------- SQS triggers

resource "aws_lambda_event_source_mapping" "orders" {
  event_source_arn        = aws_sqs_queue.main["orders"].arn
  function_name           = aws_lambda_function.fn["order-processor"].arn
  batch_size              = 5
  function_response_types = ["ReportBatchItemFailures"]  # one poison message fails alone
  depends_on              = [aws_iam_role_policy.lambda] # CreateEventSourceMapping checks the role
}

resource "aws_lambda_event_source_mapping" "notifications" {
  event_source_arn = aws_sqs_queue.main["notifications"].arn
  function_name    = aws_lambda_function.fn["notifier"].arn
  batch_size       = 10
  depends_on       = [aws_iam_role_policy.lambda]
}

# --------------------------------------------------------------------------- EventBridge schedules

locals {
  schedules = {
    reconcile-5m = { fn = "reconciler", rate = "rate(5 minutes)" }
    traffic-1m   = { fn = "traffic", rate = "rate(1 minute)" }
  }
}

resource "aws_cloudwatch_event_rule" "schedule" {
  for_each            = local.schedules
  name                = "${local.name}-${each.key}"
  schedule_expression = each.value.rate
}

resource "aws_cloudwatch_event_target" "schedule" {
  for_each = local.schedules
  rule     = aws_cloudwatch_event_rule.schedule[each.key].name
  arn      = aws_lambda_function.fn[each.value.fn].arn
}

resource "aws_lambda_permission" "schedule" {
  for_each      = local.schedules
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fn[each.value.fn].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule[each.key].arn
}

# --------------------------------------------------------------------------- API Gateway (HTTP API)

resource "aws_apigatewayv2_api" "api" {
  name          = "${local.name}-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "checkout" {
  api_id                 = aws_apigatewayv2_api.api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_alias.checkout_live.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 29000
}

resource "aws_apigatewayv2_route" "checkout" {
  for_each  = toset(["POST /checkout", "GET /health"])
  api_id    = aws_apigatewayv2_api.api.id
  route_key = each.key
  target    = "integrations/${aws_apigatewayv2_integration.checkout.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.api.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_burst_limit = 50
    throttling_rate_limit  = 20 # the public URL cannot run up a bill
  }
}

resource "aws_lambda_permission" "api" {
  statement_id  = "AllowApiGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fn["checkout"].function_name
  qualifier     = aws_lambda_alias.checkout_live.name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.api.execution_arn}/*/*"
}
