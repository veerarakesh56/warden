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
    WARDEN_AUDIT_DSN           = local.audit_dsn
    WARDEN_AUDIT_IAM_AUTH      = "1"
  }
  # `approval` is the one a person waits for. Lambda gives CPU in proportion to memory, a whole vCPU at 1,769 MB
  # (AWS's Lambda guide, "Configure Lambda function memory", read 2026-10-12); at 512 MB its cold start - Python
  # imports, five AWS clients, the audit's connection, all CPU work - had about a third of one and took 5.6 s to
  # 9.5 s. Billed by the millisecond, a few requests a day: the shorter run costs no more.
  front_doors = {
    alarm        = { handler = "warden.lambdas.alarm", timeout = 60, memory = 512 }
    alertmanager = { handler = "warden.lambdas.alertmanager", timeout = 60, memory = 512 }
    approval     = { handler = "warden.lambdas.approval", timeout = 30, memory = 1769 }
    actor-use    = { handler = "warden.lambdas.actor_use", timeout = 60, memory = 512 }
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
  role          = aws_iam_role.front_door[each.key].arn
  package_type  = "Image"
  image_uri     = var.runtime_image
  timeout       = each.value.timeout
  memory_size   = each.value.memory
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
  state       = var.paused ? "DISABLED" : "ENABLED" # paused: no alarm starts an incident nobody would serve
  description = "WARDEN ${var.environment}: the watched environments' alarm state changes, to intake"
  event_pattern = jsonencode({
    source        = ["aws.cloudwatch"]
    "detail-type" = ["CloudWatch Alarm State Change"]
    detail        = { alarmName = [for e in var.watched_environments : { prefix = "warden-${e}-" }] }
  })
  tags = { Project = "warden", Environment = var.environment }
}

# What a service says about itself with no alarm on it (lambdas.service_event, register G10-40): an ECS service's
# WARN and ERROR events, an RDS instance's or cluster's failure, failover and low-storage events - of the watched
# environments' resources only, by their names.
locals {
  service_events = {
    ecs = jsonencode({
      source        = ["aws.ecs"]
      "detail-type" = ["ECS Service Action", "ECS Deployment State Change"]
      detail        = { eventType = ["WARN", "ERROR"] }
      resources     = [for e in var.watched_environments : { prefix = "arn:aws:ecs:${local.region}:${local.account}:service/warden-${e}-" }]
    })
    # AWS Health: an open issue scoped to this account (lambdas.health_event picks the watched resources by name).
    health = jsonencode({
      source        = ["aws.health"]
      "detail-type" = ["AWS Health Event"]
      detail        = { eventTypeCategory = ["issue"], eventScopeCode = ["ACCOUNT_SPECIFIC"], statusCode = ["open"] }
    })
    # Security findings (security_findings.py): GuardDuty's at Medium and above, Security Hub CSPM's active, open,
    # Medium and above. Each goes to a person on the rules alone, never to a fix. A rule on a service that is not
    # turned on receives nothing and costs nothing; turning GuardDuty or Security Hub on is the owner's choice.
    guardduty = jsonencode({
      source        = ["aws.guardduty"]
      "detail-type" = ["GuardDuty Finding"]
      detail        = { severity = [{ numeric = [">=", 4] }] }
    })
    securityhub = jsonencode({
      source        = ["aws.securityhub"]
      "detail-type" = ["Security Hub Findings - Imported"]
      detail = { findings = {
        Severity    = { Label = ["MEDIUM", "HIGH", "CRITICAL"] }
        RecordState = ["ACTIVE"]
        Workflow    = { Status = ["NEW", "NOTIFIED"] }
      } }
    })
    rds = jsonencode({
      source        = ["aws.rds"]
      "detail-type" = ["RDS DB Instance Event", "RDS DB Cluster Event"]
      detail        = { EventCategories = ["failure", "failover", "low storage"] }
      resources = flatten([for e in var.watched_environments : [
        { prefix = "arn:aws:rds:${local.region}:${local.account}:db:warden-${e}-" },
      { prefix = "arn:aws:rds:${local.region}:${local.account}:cluster:warden-${e}-" }]])
    })
    # AWS Health's scheduled changes (maintenance, planned lifecycle events such as a Lambda runtime's end of support),
    # upcoming or open: never an incident - the alarm Lambda records each for the AWS updates watch's daily digest
    # (awswatch.health_notice), which alarms one that names WARDEN's resources. AWS's own events: no charge on the
    # default bus.
    healthchanges = jsonencode({
      source        = ["aws.health"]
      "detail-type" = ["AWS Health Event"]
      detail        = { eventTypeCategory = ["scheduledChange"], statusCode = ["upcoming", "open"] }
    })
  }
}

resource "aws_cloudwatch_event_rule" "service_events" {
  for_each      = local.service_events
  name          = "warden-${var.environment}-${each.key}-events"
  state         = var.paused ? "DISABLED" : "ENABLED"
  description   = "WARDEN ${var.environment}: the watched environments' own ${each.key} events that something is wrong, to intake"
  event_pattern = each.value
  tags          = { Project = "warden", Environment = var.environment }
}

resource "aws_cloudwatch_event_target" "service_events" {
  for_each = local.service_events
  rule     = aws_cloudwatch_event_rule.service_events[each.key].name
  arn      = aws_lambda_function.front_door["alarm"].arn
  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }
  dead_letter_config {
    arn = aws_sqs_queue.alarm_dlq.arn
  }
}

resource "aws_lambda_permission" "service_events" {
  for_each      = local.service_events
  statement_id  = "EventBridge${title(each.key)}Events"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.front_door["alarm"].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.service_events[each.key].arn
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
      Condition = { ArnEquals = { "aws:SourceArn" = concat([aws_cloudwatch_event_rule.alarms.arn, aws_cloudwatch_event_rule.actor_use.arn],
      [for r in aws_cloudwatch_event_rule.service_events : r.arn]) } }
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

# A Datadog monitor's webhook (webhooks.receive_datadog): the same function, its own bearer secret (register G10-53).
resource "aws_apigatewayv2_route" "datadog" {
  api_id    = aws_apigatewayv2_api.front.id
  route_key = "POST /datadog"
  target    = "integrations/${aws_apigatewayv2_integration.front["alertmanager"].id}"
}

resource "aws_apigatewayv2_route" "approval" {
  # /a/: approving a plan. /e/: enrolling a passkey, /k/: resetting the kill switch, /x/: turning it on - each on a link the approver's
  # own key signed. /s/interact: Slack's note of a button click, answered by the function below. /r: WARDEN's records
  # (records.py), for a reader Slack names who is on the approver or viewer list; /s/r starts that sign-in.
  for_each = toset(["GET /a/{token}", "POST /a/{token}/{step}", "GET /e/{token}", "POST /e/{token}/{step}",
    "GET /k/{token}", "POST /k/{token}/{step}", "GET /x/{token}", "POST /x/{token}/{step}",
    "GET /s/callback", "GET /s/{kind}/{token}", "POST /s/interact",
  "GET /r", "GET /r/{incident}", "GET /s/r"])
  api_id    = aws_apigatewayv2_api.front.id
  route_key = each.key
  target = "integrations/${each.key == "POST /s/interact" ? aws_apigatewayv2_integration.ack.id :
  aws_apigatewayv2_integration.front["approval"].id}"
}

# Slack shows "Operation timed out" beside a button unless its note of the click is answered within three seconds.
# The approval function, started cold, took 2.7 s to answer even with nothing loaded (measured 2026-10-12): a
# container image, in the VPC. So the answer is its own function - a few lines of Python, no image, no VPC, no
# permission at all (its role has no policy), nothing read and nothing decided (ack/ack.py).
resource "aws_iam_role" "ack" {
  name                 = "warden-${var.environment}-ack"
  permissions_boundary = var.permissions_boundary_arn
  description          = "WARDEN ${var.environment}: answers Slack's note of a button click - no permission, nothing read"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
  tags                 = { Project = "warden", Environment = var.environment }
}

resource "aws_lambda_function" "ack" {
  function_name    = "warden-${var.environment}-ack"
  role             = aws_iam_role.ack.arn
  runtime          = "python3.13"
  handler          = "ack.handler"
  filename         = "${path.module}/ack.zip"
  source_code_hash = filebase64sha256("${path.module}/ack.zip")
  timeout          = 3
  memory_size      = 128
  tags             = { Project = "warden", Environment = var.environment }
}

resource "aws_apigatewayv2_integration" "ack" {
  api_id                 = aws_apigatewayv2_api.front.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.ack.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_lambda_permission" "ack" {
  statement_id  = "HttpApiSlackNote"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ack.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.front.execution_arn}/*/POST/s/interact"
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
