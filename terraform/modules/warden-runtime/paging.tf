# Pages that repeat until a person acknowledges them (owner, 2026-10-16), and keep repeating with WARDEN down.
#
# CloudWatch sends an alarm's action once, when it goes into ALARM, never again while it stays there; AWS's own paging
# with acknowledgement (Systems Manager Incident Manager) takes no new customers since 2025-11-07 (read 2026-10-16).
# So: every self-alarm below, going into ALARM, reaches the `pager` (EventBridge), as does a worker task that stopped
# on its own; an EventBridge schedule runs it every five minutes, and it says each open page again - Slack and email -
# once every `page_repeat_minutes` until an approver acknowledges it on the approval page (`/p`, passkey-signed, on
# WARDEN's record). The pager is a zip of its own (pager/pager.py): no image, no VPC, no Temporal, no audit database -
# a dead worker, database or image does not silence it. Its state is in the anchors bucket (anchors.tf): `pages/` the
# pager's, `acks/` the approval function's - TLS only, Object Lock, every version kept; no second bucket to secure. Email goes through `page_repeat`, set to ALARM with the page's words as its reason:
# CloudWatch already publishes to the page topic, so nothing here needs an SNS permission.
# Within the environment's boundary and deploy role as they are (S3, Lambda, EventBridge, CloudWatch, Secrets
# Manager, SSM reads): EventBridge Scheduler and DynamoDB are not in them, and the boundary lets only the anchors and
# witness buckets have a bucket policy - so a scheduled rule, and the anchors bucket's own TLS-only policy.
locals {
  ack_url = var.approval_domain == "" ? "" : "https://${var.approval_domain}/p"
  # The self-alarms that page and repeat. Paused, the workers are off on purpose: their silence pages nobody.
  self_alarms = concat(var.paused ? [] : [aws_cloudwatch_metric_alarm.heartbeat.alarm_name,
    aws_cloudwatch_metric_alarm.synthetic.alarm_name, aws_cloudwatch_metric_alarm.worker_errors.alarm_name], [
    aws_cloudwatch_metric_alarm.killswitch.alarm_name,
    aws_cloudwatch_metric_alarm.model["provider_unavailable"].alarm_name,
    aws_cloudwatch_metric_alarm.model["daily_cap"].alarm_name,
    aws_cloudwatch_metric_alarm.model["budget"].alarm_name,
    aws_cloudwatch_metric_alarm.alarm_dlq.alarm_name,
    aws_cloudwatch_metric_alarm.unapproved_actor.alarm_name,
    aws_cloudwatch_metric_alarm.approvers_changed.alarm_name,
    aws_cloudwatch_metric_alarm.lambda_errors.alarm_name,
    aws_cloudwatch_metric_alarm.lambda_throttles.alarm_name,
    aws_cloudwatch_metric_alarm.audit_db_cpu.alarm_name,
    aws_cloudwatch_metric_alarm.audit_db_connections.alarm_name,
    aws_cloudwatch_metric_alarm.audit_db_storage.alarm_name,
  ])
  # Every function a person's page or WARDEN's intake depends on: the front doors, Slack's answer, the pager itself.
  paged_functions = merge({ for k, f in aws_lambda_function.front_door : k => f.function_name },
  { ack = aws_lambda_function.ack.function_name, pager = aws_lambda_function.pager.function_name })
  audit_db_dimensions = var.aws_free_plan ? { DBInstanceIdentifier = "warden-${var.environment}-audit" } : {
  DBClusterIdentifier = "warden-${var.environment}-audit" }
  key_expiry_param = "/warden/${var.environment}/env/WARDEN_TEMPORAL_KEY_EXPIRES"
}

# --------------------------------------------------------------------------- the pager

resource "aws_iam_role" "pager" {
  name                 = "warden-${var.environment}-pager"
  permissions_boundary = var.permissions_boundary_arn
  description          = "WARDEN ${var.environment}: repeats WARDEN's own pages until acknowledged - its pages, Slack's webhook, one alarm"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
  tags                 = { Project = "warden", Environment = var.environment }
}

resource "aws_iam_role_policy" "pager" {
  name = "warden-${var.environment}-pager"
  role = aws_iam_role.pager.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    # ListBucket on the bucket: without it S3 answers a missing acknowledgement 403, not NoSuchKey.
    { Sid = "ListPages", Effect = "Allow", Action = ["s3:ListBucket"], Resource = aws_s3_bucket.anchors.arn },
    { Sid = "ItsPages", Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = "${aws_s3_bucket.anchors.arn}/pages/*" },
    { Sid = "ReadAcknowledgements", Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.anchors.arn}/acks/*" },
    {
      Sid      = "EmailThroughTheRepeatAlarm"
      Effect   = "Allow"
      Action   = ["cloudwatch:SetAlarmState"]
      Resource = "arn:aws:cloudwatch:${local.region}:${local.account}:alarm:${local.page_repeat_alarm}"
    },
    {
      Sid      = "ReadItsAlarmsState"
      Effect   = "Allow"
      Action   = ["cloudwatch:DescribeAlarms"]
      Resource = "arn:aws:cloudwatch:${local.region}:${local.account}:alarm:warden-${var.environment}-*"
    },
    { Sid = "SlacksWebhook", Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = "${local.secret_arn}/slack-webhook-??????" },
    {
      Sid      = "TheTemporalKeysEnd"
      Effect   = "Allow"
      Action   = ["ssm:GetParameter"]
      Resource = "arn:aws:ssm:${local.region}:${local.account}:parameter${local.key_expiry_param}"
    },
    {
      Sid      = "ItsOwnLogs"
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.pager.arn}:*"
    },
  ] })
}

resource "aws_cloudwatch_log_group" "pager" {
  name              = "/aws/lambda/warden-${var.environment}-pager"
  retention_in_days = 90
  tags              = { Project = "warden", Environment = var.environment }
}

resource "aws_lambda_function" "pager" {
  function_name    = "warden-${var.environment}-pager"
  role             = aws_iam_role.pager.arn
  runtime          = "python3.13"
  handler          = "pager.handler"
  filename         = "${path.module}/pager.zip"
  source_code_hash = filebase64sha256("${path.module}/pager.zip")
  timeout          = 60
  memory_size      = 128
  environment {
    variables = {
      WARDEN_ENV       = var.environment
      PAGES_BUCKET     = aws_s3_bucket.anchors.bucket
      REPEAT_MINUTES   = tostring(var.page_repeat_minutes)
      REPEAT_ALARM     = local.page_repeat_alarm
      SLACK_SECRET_ID  = "warden/${var.environment}/slack-webhook"
      ACK_URL          = local.ack_url
      CLUSTER_ARN      = aws_ecs_cluster.runtime.arn
      KEY_EXPIRY_PARAM = local.key_expiry_param
      KEY_WARN_DAYS    = tostring(var.temporal_key_warn_days)
    }
  }
  tags       = { Project = "warden", Environment = var.environment }
  depends_on = [aws_cloudwatch_log_group.pager]
}

# A self-alarm going into ALARM opens a page; its own action has already emailed it.
resource "aws_cloudwatch_event_rule" "pages" {
  name        = "warden-${var.environment}-pages"
  description = "WARDEN ${var.environment}: its own alarms going into ALARM, and worker tasks that stopped on their own, to the pager"
  event_pattern = jsonencode({
    source        = ["aws.cloudwatch"]
    "detail-type" = ["CloudWatch Alarm State Change"]
    detail        = { alarmName = local.self_alarms, state = { value = ["ALARM"] } }
  })
  tags = { Project = "warden", Environment = var.environment }
}

# A worker task that stopped on its own - the container exited, or the task never started - opens a page. A deploy's
# or a pause's stop (ServiceSchedulerInitiated) does not.
resource "aws_cloudwatch_event_rule" "worker_stopped" {
  name        = "warden-${var.environment}-worker-stopped"
  description = "WARDEN ${var.environment}: a worker task that stopped on its own, to the pager"
  event_pattern = jsonencode({
    source        = ["aws.ecs"]
    "detail-type" = ["ECS Task State Change"]
    detail = { clusterArn = [aws_ecs_cluster.runtime.arn], lastStatus = ["STOPPED"],
    stopCode = ["EssentialContainerExited", "TaskFailedToStart"] }
  })
  tags = { Project = "warden", Environment = var.environment }
}

resource "aws_cloudwatch_event_rule" "page_tick" {
  name                = "warden-${var.environment}-page-tick"
  description         = "WARDEN ${var.environment}: the pager says each open page again until it is acknowledged"
  schedule_expression = "rate(5 minutes)"
  tags                = { Project = "warden", Environment = var.environment }
}

resource "aws_cloudwatch_event_target" "pager" {
  for_each = { pages = aws_cloudwatch_event_rule.pages.name, worker_stopped = aws_cloudwatch_event_rule.worker_stopped.name,
  page_tick = aws_cloudwatch_event_rule.page_tick.name }
  rule = each.value
  arn  = aws_lambda_function.pager.arn
  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }
}

resource "aws_lambda_permission" "pager" {
  for_each = { pages = aws_cloudwatch_event_rule.pages.arn, worker_stopped = aws_cloudwatch_event_rule.worker_stopped.arn,
  page_tick = aws_cloudwatch_event_rule.page_tick.arn }
  statement_id  = "EventBridge${replace(title(replace(each.key, "_", " ")), " ", "")}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pager.function_name
  principal     = "events.amazonaws.com"
  source_arn    = each.value
}

# The email of a repeat: the pager sets this to ALARM with the page's words as the reason. No data is ever published
# to its metric, so it returns to OK by itself a minute later; OK sends nothing.
locals {
  page_repeat_alarm = "warden-${var.environment}-page-repeat"
}

resource "aws_cloudwatch_metric_alarm" "page_repeat" {
  alarm_name          = local.page_repeat_alarm
  alarm_description   = "A WARDEN page is still not acknowledged. The reason below says which, since when and why; acknowledge it with your passkey on the approval page (/p)."
  namespace           = "WARDEN/${var.environment}"
  metric_name         = "PageRepeat"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.page_topic_arn]
  tags                = { Project = "warden", Environment = var.environment }
}

# --------------------------------------------------------------------------- the self-alarms the audit found missing

# The kill switch went on - by a person, or by WARDEN itself (bounds.trip counts each trip: paging.killswitch_tripped).
resource "aws_cloudwatch_metric_alarm" "killswitch" {
  alarm_name          = "warden-${var.environment}-killswitch-on"
  alarm_description   = "WARDEN's kill switch went on, by a person or by WARDEN itself: every automatic fix is stopped. `warden killswitch link` opens the page that says why and resets it."
  namespace           = "WARDEN/${var.environment}"
  metric_name         = "KillSwitchTripped"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.page_topic_arn]
  tags                = { Project = "warden", Environment = var.environment }
}

# The model could not be used (item 7c, paging.model_condition): its provider unavailable, the daily cap reached (the
# incidents' daily cap or Eldane's daily call ceiling), or an incident's budget spent. The worker counts each condition
# once per UTC day, whatever the number of calls it stops, so each pages at most once a day; the page says only the
# fixed words below - never an error's text, a number from the evidence or a secret. Paged to the page topic, as
# every alarm here: no address of its own.
locals {
  model_pages = {
    provider_unavailable = {
      metric = "ModelProviderUnavailable"
      says   = "WARDEN's model provider is unavailable (down, out of capacity or not answering in time): incidents are escalated to a person on the rules alone. Check the provider's status page and the llm zone's log."
    }
    daily_cap = {
      metric = "ModelDailyCapReached"
      says   = "WARDEN's daily model cap is reached: until the 24-hour window moves on, incidents are escalated to a person on the rules alone and Eldane reviews nothing. The day's spend is in the audit's incident.llm_spend rows."
    }
    budget = {
      metric = "ModelBudgetReached"
      says   = "An incident spent its model budget (WARDEN_MAX_USD or WARDEN_MAX_CALLS): that incident is escalated to a person on the rules alone. Its incident.llm_spend rows say what was spent."
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "model" {
  for_each            = local.model_pages
  alarm_name          = "warden-${var.environment}-model-${replace(each.key, "_", "-")}"
  alarm_description   = each.value.says
  namespace           = "WARDEN/${var.environment}"
  metric_name         = each.value.metric
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.page_topic_arn]
  tags                = { Project = "warden", Environment = var.environment }
}

# A worker wrote an ERROR or CRITICAL line (observability.install_log_gate's format: "<time> <LEVEL> <logger>: ...").
# An activity's failure is a WARNING there, and pages nobody.
resource "aws_cloudwatch_log_metric_filter" "worker_errors" {
  name           = "warden-${var.environment}-worker-errors"
  log_group_name = aws_cloudwatch_log_group.worker.name
  pattern        = "?\" ERROR \" ?\" CRITICAL \""
  metric_transformation {
    name          = "WorkerErrors"
    namespace     = "WARDEN/${var.environment}"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "worker_errors" {
  alarm_name          = "warden-${var.environment}-worker-errors"
  actions_enabled     = !var.paused
  alarm_description   = "A WARDEN worker logged an error. Read /warden/${var.environment}/worker around this time: docs/RUNBOOK-WARDEN-INCIDENT.md."
  namespace           = "WARDEN/${var.environment}"
  metric_name         = "WorkerErrors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.page_topic_arn]
  tags                = { Project = "warden", Environment = var.environment }
}

# The front doors, Slack's answer and the pager: an error or a throttle in any of them, summed.
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "warden-${var.environment}-lambda-errors"
  alarm_description   = "A WARDEN function failed (an alarm's intake, Alertmanager's or Datadog's webhook, the approval page, the actor check, the pager). Read its log in /aws/lambda/warden-${var.environment}-*."
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.page_topic_arn]
  metric_query {
    id          = "total"
    expression  = "SUM([${join(",", [for k in sort(keys(local.paged_functions)) : "e_${replace(k, "-", "_")}"])}])"
    label       = "Errors"
    return_data = true
  }
  dynamic "metric_query" {
    for_each = local.paged_functions
    content {
      id = "e_${replace(metric_query.key, "-", "_")}"
      metric {
        namespace   = "AWS/Lambda"
        metric_name = "Errors"
        dimensions  = { FunctionName = metric_query.value }
        period      = 300
        stat        = "Sum"
      }
    }
  }
  tags = { Project = "warden", Environment = var.environment }
}

resource "aws_cloudwatch_metric_alarm" "lambda_throttles" {
  alarm_name          = "warden-${var.environment}-lambda-throttles"
  alarm_description   = "A WARDEN function was throttled: an alarm, a webhook or an approval may have been turned away. Check the account's Lambda concurrency."
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.page_topic_arn]
  metric_query {
    id          = "total"
    expression  = "SUM([${join(",", [for k in sort(keys(local.paged_functions)) : "t_${replace(k, "-", "_")}"])}])"
    label       = "Throttles"
    return_data = true
  }
  dynamic "metric_query" {
    for_each = local.paged_functions
    content {
      id = "t_${replace(metric_query.key, "-", "_")}"
      metric {
        namespace   = "AWS/Lambda"
        metric_name = "Throttles"
        dimensions  = { FunctionName = metric_query.value }
        period      = 300
        stat        = "Sum"
      }
    }
  }
  tags = { Project = "warden", Environment = var.environment }
}

# The audit database. Paused to 0 capacity it reports nothing, and missing data pages nobody.
resource "aws_cloudwatch_metric_alarm" "audit_db_cpu" {
  alarm_name          = "warden-${var.environment}-audit-db-cpu"
  alarm_description   = "WARDEN's audit database has been above 80% CPU for 15 minutes: every record and approval waits on it."
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  dimensions          = local.audit_db_dimensions
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.page_topic_arn]
  tags                = { Project = "warden", Environment = var.environment }
}

resource "aws_cloudwatch_metric_alarm" "audit_db_connections" {
  alarm_name          = "warden-${var.environment}-audit-db-connections"
  alarm_description   = "WARDEN's audit database holds more connections than it should for 10 minutes: a leak, or a flood of work."
  namespace           = "AWS/RDS"
  metric_name         = "DatabaseConnections"
  dimensions          = local.audit_db_dimensions
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 2
  threshold           = var.audit_db_max_connections
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.page_topic_arn]
  tags                = { Project = "warden", Environment = var.environment }
}

# Storage: the Free plan's instance has 20 GiB and pages under 2 left; Aurora grows by itself, and pages when the
# audit passes `audit_db_max_gib` - far more than a year of incidents, so a runaway writer, and its bill.
resource "aws_cloudwatch_metric_alarm" "audit_db_storage" {
  alarm_name          = "warden-${var.environment}-audit-db-storage"
  alarm_description   = var.aws_free_plan ? "WARDEN's audit database has under 2 GiB of storage left: the audit stops when it is full." : "WARDEN's audit database holds more than ${var.audit_db_max_gib} GiB: something writes far more than incidents do."
  namespace           = "AWS/RDS"
  metric_name         = var.aws_free_plan ? "FreeStorageSpace" : "VolumeBytesUsed"
  dimensions          = local.audit_db_dimensions
  statistic           = var.aws_free_plan ? "Minimum" : "Maximum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = var.aws_free_plan ? 2 * 1073741824 : var.audit_db_max_gib * 1073741824
  comparison_operator = var.aws_free_plan ? "LessThanThreshold" : "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.page_topic_arn]
  tags                = { Project = "warden", Environment = var.environment }
}

# The month's spend before credits (credits pay the bill, they do not shrink what is used): 80% spent and 100%
# forecast email the page topic. Off unless SSM tf/monthly_budget_usd is set - the deploy role and the boundary need
# budgets:* and the topic's policy must let budgets.amazonaws.com publish, both a person's steps (docs/SETUP.md).
resource "aws_budgets_budget" "monthly" {
  count        = var.monthly_budget_usd > 0 ? 1 : 0
  name         = "warden-${var.environment}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  cost_types {
    include_credit = false
    include_refund = false
  }
  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 80
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [var.page_topic_arn]
  }
  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "FORECASTED"
    subscriber_sns_topic_arns = [var.page_topic_arn]
  }
  tags = { Project = "warden", Environment = var.environment }
}
