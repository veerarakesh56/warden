# Register C13: WARDEN can fail together with the incident it should help with, and nobody notices. Each worker
# publishes a beat (WARDEN/<env> Heartbeat, by task queue) only when a whole round trip through Temporal works
# (src/warden/runtime.py `heartbeat`). This alarm pages a person when the beats stop: missing data is BREACHING,
# so a dead worker, a dead Temporal connection and a dead clock all page - silence is the failure.
resource "aws_cloudwatch_metric_alarm" "heartbeat" {
  alarm_name          = "warden-${var.environment}-heartbeat-missing"
  alarm_description   = "WARDEN's workers have not completed a round trip through Temporal. WARDEN may be down: follow docs/RUNBOOK-WARDEN-INCIDENT.md."
  namespace           = "WARDEN/${var.environment}"
  metric_name         = "Heartbeat"
  dimensions          = { TaskQueue = "warden" }
  statistic           = "Sum"
  period              = var.heartbeat_period_seconds
  evaluation_periods  = var.missed_beats_to_page
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [var.page_topic_arn]
  ok_actions          = [var.page_topic_arn]
  tags                = { Project = "warden", Environment = var.environment }
}

# Register C13: once a day a worker runs a bundled recorded incident through the whole diagnosis path in shadow (the
# model, the gate, the report; src/warden/runtime.py `synthetic`) and publishes WARDEN/<env> Synthetic only when the
# model answered and the report passed the gate. 25 hourly periods without one - the model gone, a key expired, the
# pipeline broken - page a person; missing data is BREACHING.
resource "aws_cloudwatch_metric_alarm" "synthetic" {
  alarm_name          = "warden-${var.environment}-synthetic-missing"
  alarm_description   = "WARDEN's daily synthetic incident has not passed for a day: the model or the diagnosis pipeline may be broken. Follow docs/RUNBOOK-WARDEN-INCIDENT.md."
  namespace           = "WARDEN/${var.environment}"
  metric_name         = "Synthetic"
  dimensions          = { TaskQueue = "warden" }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 25
  datapoints_to_alarm = 25
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [var.page_topic_arn]
  ok_actions          = [var.page_topic_arn]
  tags                = { Project = "warden", Environment = var.environment }
}
