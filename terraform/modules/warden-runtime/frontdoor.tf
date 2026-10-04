# How alarms, Alertmanager and approvers reach WARDEN with the laptop off (G6), all from the one runtime image:
# - CloudWatch alarm state changes of the watched environments' alarms -> EventBridge -> the `alarm` Lambda (retried,
#   then kept in a dead-letter queue that pages);
# - Alertmanager -> POST /alertmanager -> the `alertmanager` Lambda (bearer secret, size caps; register S5);
# - an approver's browser -> /a/... -> the `approval` Lambda (passkeys; registers H6, R28, R58);
# - every session of a watched environment's actor role -> CloudTrail -> EventBridge -> the `actor-use` Lambda
#   (witness.tf).
# The HTTP API throttles every route (register N10) and writes JSON access logs.
locals {
  lambda_env = {
    WARDEN_ENV                 = var.environment
    WARDEN_AUDIT_KMS_KEY_ID    = aws_kms_alias.audit_signer.name
    WARDEN_AUDIT_ANCHOR_BUCKET = aws_s3_bucket.anchors.bucket
    WARDEN_APPROVAL_RP_ID      = var.approval_domain
  }
  front_doors = {
    alarm        = { handler = "warden.lambdas.alarm", timeout = 60 }
    alertmanager = { handler = "warden.lambdas.alertmanager", timeout = 60 }
    approval     = { handler = "warden.lambdas.approval", timeout = 30 }
    actor-use    = { handler = "warden.lambdas.actor_use", timeout = 60 }
  }
}

resource "aws_cloudwatch_log_group" "front_door" {
  for_each          = local.front_doors
  name              = "/aws/lambda/warden-${var.environment}-${each.key}"
  retention_in_days = 90
  tags              = { Project = "warden", Environment = var.environment }
}

resource "aws_lambda_function" "front_door" {
  for_each      = local.front_doors
  function_name = "warden-${var.environment}-${each.key}"
  role          = aws_iam_role.lambda.arn
  package_type  = "Image"
  image_uri     = var.runtime_image
  timeout       = each.value.timeout
  memory_size   = 512
  image_config {
    entry_point = ["/opt/warden/bin/python", "-m", "awslambdaric"]
    command     = [each.value.handler]
  }
  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.runtime.id]
  }
  environment {
    variables = local.lambda_env
  }
  tags       = { Project = "warden", Environment = var.environment }
  depends_on = [aws_cloudwatch_log_group.front_door]
}

# --------------------------------------------------------------------------- alarms -> intake

resource "aws_cloudwatch_event_rule" "alarms" {
  name        = "warden-${var.environment}-alarm-changes"
  description = "WARDEN ${var.environment}: the watched environments' alarm state changes, to intake"
  event_pattern = jsonencode({
    source        = ["aws.cloudwatch"]
    "detail-type" = ["CloudWatch Alarm State Change"]
    detail        = { alarmName = [for e in var.watched_environments : { prefix = "warden-${e}-" }] }
  })
  tags = { Project = "warden", Environment = var.environment }
}

resource "aws_sqs_queue" "alarm_dlq" {
  name                      = "warden-${var.environment}-alarm-dlq"
  message_retention_seconds = 1209600 # 14 days: a lost alarm is read by a person
  sqs_managed_sse_enabled   = true
  tags                      = { Project = "warden", Environment = var.environment }
}

resource "aws_sqs_queue_policy" "alarm_dlq" {
  queue_url = aws_sqs_queue.alarm_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OnlyTheseRulesUndeliveredEvents"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.alarm_dlq.arn
      Condition = { ArnEquals = { "aws:SourceArn" = [aws_cloudwatch_event_rule.alarms.arn, aws_cloudwatch_event_rule.actor_use.arn] } }
    }]
  })
}

resource "aws_cloudwatch_event_target" "alarms" {
  rule = aws_cloudwatch_event_rule.alarms.name
  arn  = aws_lambda_function.front_door["alarm"].arn
  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }
  dead_letter_config {
    arn = aws_sqs_queue.alarm_dlq.arn
  }
}

resource "aws_lambda_permission" "alarms" {
  statement_id  = "EventBridgeAlarmChanges"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.front_door["alarm"].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.alarms.arn
}

# An alarm that never reached intake pages a person: the dead-letter queue is never silently full.
resource "aws_cloudwatch_metric_alarm" "alarm_dlq" {
  alarm_name          = "warden-${var.environment}-alarm-dlq"
  alarm_description   = "An alarm change or an actor session did not reach WARDEN after every retry. Read the queue and handle it by hand: docs/RUNBOOK-WARDEN-INCIDENT.md."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.alarm_dlq.name }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.page_topic_arn]
  tags                = { Project = "warden", Environment = var.environment }
}

# --------------------------------------------------------------------------- the HTTP API

resource "aws_apigatewayv2_api" "front" {
  name          = "warden-${var.environment}-front"
  protocol_type = "HTTP"
  tags          = { Project = "warden", Environment = var.environment }
}

resource "aws_cloudwatch_log_group" "api_access" {
  name              = "/aws/vendedlogs/warden-${var.environment}-front-access"
  retention_in_days = 90
  tags              = { Project = "warden", Environment = var.environment }
}

resource "aws_apigatewayv2_stage" "front" {
  api_id      = aws_apigatewayv2_api.front.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_rate_limit  = var.api_rate_limit
    throttling_burst_limit = var.api_burst_limit
  }
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access.arn
    format = jsonencode({
      requestId = "$context.requestId", ip = "$context.identity.sourceIp", time = "$context.requestTime",
      method    = "$context.httpMethod", route = "$context.routeKey", status = "$context.status",
      length    = "$context.responseLength", latency = "$context.integrationLatency"
    })
  }
  tags = { Project = "warden", Environment = var.environment }
}

resource "aws_apigatewayv2_integration" "front" {
  for_each               = toset(["alertmanager", "approval"])
  api_id                 = aws_apigatewayv2_api.front.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.front_door[each.key].invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "alertmanager" {
  api_id    = aws_apigatewayv2_api.front.id
  route_key = "POST /alertmanager"
  target    = "integrations/${aws_apigatewayv2_integration.front["alertmanager"].id}"
}

resource "aws_apigatewayv2_route" "approval" {
  for_each  = toset(["GET /a/{token}", "POST /a/{token}/{step}"])
  api_id    = aws_apigatewayv2_api.front.id
  route_key = each.key
  target    = "integrations/${aws_apigatewayv2_integration.front["approval"].id}"
}

resource "aws_lambda_permission" "api" {
  for_each      = toset(["alertmanager", "approval"])
  statement_id  = "HttpApiFrontDoor"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.front_door[each.key].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.front.execution_arn}/*/*"
}

# The approval page on its own domain (decision D17, register R58): the passkeys' relying party. The DNS record (a
# DNS-only CNAME at the domain's provider) is a person's step, shown record by record before it is made.
resource "aws_apigatewayv2_domain_name" "approval" {
  count       = var.approval_domain == "" ? 0 : 1
  domain_name = var.approval_domain
  domain_name_configuration {
    certificate_arn = var.approval_certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }
  tags = { Project = "warden", Environment = var.environment }
}

resource "aws_apigatewayv2_api_mapping" "approval" {
  count       = var.approval_domain == "" ? 0 : 1
  api_id      = aws_apigatewayv2_api.front.id
  domain_name = aws_apigatewayv2_domain_name.approval[0].id
  stage       = aws_apigatewayv2_stage.front.id
}
