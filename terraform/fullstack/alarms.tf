# The alert source. One alarm per signal the faults in docs/WAVE4-FULLSTACK.md section 7 trip.
#
# ⛔ Descriptions name the SYMPTOM a user or an on-call engineer would see, never the cause. The
# alarm text reaches WARDEN verbatim; a description that said what was broken would hand it the
# answer. tests/test_fullstack_infra.py fails on cause words.
#
# No alarm actions: the harness polls alarm state and turns an ALARM into WARDEN's alert.

locals {
  fn = { for k, v in aws_lambda_function.fn : k => v.function_name }
  alb_dims = {
    LoadBalancer = aws_lb.orders.arn_suffix
    TargetGroup  = aws_lb_target_group.orders.arn_suffix
  }
  shop_dims = { ClusterName = aws_eks_cluster.this.name, Namespace = "shop" }

  # name suffix => metric. Names match scenarios/catalog/wave4-fullstack.yaml (the harness polls them).
  # op: GreaterThanOrEqualToThreshold unless stated.
  alarms = {
    api-5xx = {
      ns   = "AWS/ApiGateway", metric = "5xx", stat = "Sum", threshold = 1,
      dims = { ApiId = aws_apigatewayv2_api.api.id, Stage = "$default" },
      desc = "Checkout API is returning 5xx responses to clients."
    }
    checkout-errors = {
      ns   = "AWS/Lambda", metric = "Errors", stat = "Sum", threshold = 1,
      dims = { FunctionName = local.fn["checkout"] },
      desc = "Checkout function invocations are ending in errors."
    }
    checkout-throttles = {
      ns   = "AWS/Lambda", metric = "Throttles", stat = "Sum", threshold = 1,
      dims = { FunctionName = local.fn["checkout"] },
      desc = "Checkout function invocations are being refused before they run."
    }
    processor-errors = {
      ns   = "AWS/Lambda", metric = "Errors", stat = "Sum", threshold = 1,
      dims = { FunctionName = local.fn["order-processor"] },
      desc = "Order processing invocations are ending in errors."
    }
    processor-duration = {
      ns   = "AWS/Lambda", metric = "Duration", stat = "Maximum", threshold = 10000,
      dims = { FunctionName = local.fn["order-processor"] },
      desc = "Order processing is taking longer than normal."
    }
    reconciler-errors = {
      ns   = "AWS/Lambda", metric = "Errors", stat = "Sum", threshold = 1,
      dims = { FunctionName = local.fn["reconciler"] },
      desc = "Scheduled reconciliation is ending in errors."
    }
    reconciler-invocations-low = {
      ns     = "AWS/Lambda", metric = "Invocations", stat = "Sum", threshold = 1, op = "LessThanThreshold",
      period = 600, periods = 1, missing = "breaching",
      dims   = { FunctionName = local.fn["reconciler"] },
      desc   = "Scheduled reconciliation has not run in the last 10 minutes."
    }
    reconciler-duration = {
      ns   = "AWS/Lambda", metric = "Duration", stat = "Maximum", threshold = 10000,
      dims = { FunctionName = local.fn["reconciler"] },
      desc = "Scheduled reconciliation is taking longer than normal."
    }
    orders-age = {
      ns   = "AWS/SQS", metric = "ApproximateAgeOfOldestMessage", stat = "Maximum", threshold = 300, periods = 3,
      dims = { QueueName = aws_sqs_queue.main["orders"].name },
      desc = "Orders are waiting in the queue longer than normal."
    }
    orders-dlq-visible = {
      ns   = "AWS/SQS", metric = "ApproximateNumberOfMessagesVisible", stat = "Maximum", threshold = 1,
      dims = { QueueName = aws_sqs_queue.dlq["orders"].name },
      desc = "Orders are arriving in the dead-letter queue."
    }
    sns-failed = {
      ns   = "AWS/SNS", metric = "NumberOfNotificationsFailed", stat = "Sum", threshold = 1,
      dims = { TopicName = aws_sns_topic.order_events.name },
      desc = "Order event notifications are failing to deliver."
    }
    carts-throttles = {
      ns   = "AWS/DynamoDB", metric = "WriteThrottleEvents", stat = "Sum", threshold = 1,
      dims = { TableName = aws_dynamodb_table.carts.name },
      desc = "Cart writes are being rejected by the table."
    }
    redis-memory = {
      ns   = "AWS/ElastiCache", metric = "DatabaseMemoryUsagePercentage", stat = "Maximum", threshold = 80,
      dims = { CacheClusterId = "${aws_elasticache_replication_group.redis.id}-001" },
      desc = "Cache memory usage is above 80 percent."
    }
    aurora-connections = {
      ns   = "AWS/RDS", metric = "DatabaseConnections", stat = "Maximum", threshold = 50,
      dims = { DBClusterIdentifier = local.aurora_cluster }, # created by aurora_express.py
      desc = "Database connection count is above normal."
    }
    # The writer's per-minute AVERAGE. Measured on the idle express cluster (2026-09-26): the per-minute
    # Maximum spikes to 100 from Aurora's own processes while the average sits near 22, and the
    # Maximum-based alarm went to ALARM twice with no fault injected - a red herring in WARDEN's evidence.
    aurora-cpu = {
      ns   = "AWS/RDS", metric = "CPUUtilization", stat = "Average", threshold = 70, periods = 3,
      dims = { DBClusterIdentifier = local.aurora_cluster, Role = "WRITER" }, # created by aurora_express.py
      desc = "Database CPU usage is above normal."
    }
    alb-5xx = {
      ns   = "AWS/ApplicationELB", metric = "HTTPCode_Target_5XX_Count", stat = "Sum", threshold = 1,
      dims = local.alb_dims,
      desc = "Orders API is returning 5xx responses."
    }
    alb-elb-5xx = {
      ns   = "AWS/ApplicationELB", metric = "HTTPCode_ELB_5XX_Count", stat = "Sum", threshold = 1,
      dims = { LoadBalancer = aws_lb.orders.arn_suffix },
      desc = "Orders API load balancer is returning 5xx responses."
    }
    alb-unhealthy = {
      ns   = "AWS/ApplicationELB", metric = "UnHealthyHostCount", stat = "Maximum", threshold = 1, periods = 2,
      dims = local.alb_dims,
      desc = "Orders API has unhealthy targets."
    }
    alb-healthy-low = {
      ns      = "AWS/ApplicationELB", metric = "HealthyHostCount", stat = "Minimum", threshold = 2, op = "LessThanThreshold",
      periods = 3, missing = "breaching",
      dims    = local.alb_dims,
      desc    = "Orders API has fewer healthy targets than desired."
    }
    # ContainerInsights (amazon-cloudwatch-observability add-on). PodName is the workload name.
    # Verified on the live cluster (2026-09-26, `aws cloudwatch list-metrics --namespace ContainerInsights`):
    # both metrics exist with {ClusterName, Namespace, PodName} and arrive every minute, so treating
    # missing data as breaching does not flap while the pods run.
    catalog-errors = {
      ns      = "ContainerInsights", metric = "pod_status_ready", stat = "Sum", threshold = 2, op = "LessThanThreshold",
      periods = 3, missing = "breaching",
      dims    = merge(local.shop_dims, { PodName = "catalog-api" }),
      desc    = "catalog-api has fewer ready pods than desired."
    }
    cart-worker-stalled = {
      ns      = "ContainerInsights", metric = "pod_status_running", stat = "Sum", threshold = 1, op = "LessThanThreshold",
      periods = 3, missing = "breaching",
      dims    = merge(local.shop_dims, { PodName = "cart-worker" }),
      desc    = "cart-worker has no running pod."
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "this" {
  for_each            = local.alarms
  alarm_name          = "${local.name}-${each.key}"
  alarm_description   = each.value.desc
  namespace           = each.value.ns
  metric_name         = each.value.metric
  dimensions          = each.value.dims
  statistic           = each.value.stat
  threshold           = each.value.threshold
  comparison_operator = lookup(each.value, "op", "GreaterThanOrEqualToThreshold")
  period              = lookup(each.value, "period", 60)
  evaluation_periods  = lookup(each.value, "periods", 1)
  treat_missing_data  = lookup(each.value, "missing", "notBreaching")
}
