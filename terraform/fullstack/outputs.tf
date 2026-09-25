# The infra pipeline's product. `terraform output -json` with the sensitive entries stripped is
# stack.json (README), which the apps pipeline and the harness read instead of calling terraform.
#
# No account_id output: stack.json is copied around (CI uploads it to the state bucket). The ARNs
# below carry the account id where one is unavoidable, so stack.json itself is never published.

output "region" {
  value = var.region
}

output "project_tag" {
  description = "The tag every fault injector checks before it acts."
  value       = local.tags.Project
}

# --------------------------------------------------------------------------- entry points

output "api_url" {
  value = aws_apigatewayv2_api.api.api_endpoint
}

output "api_id" {
  value = aws_apigatewayv2_api.api.id
}

output "api_name" {
  value = aws_apigatewayv2_api.api.name
}

output "alb_dns" {
  value = aws_lb.orders.dns_name
}

output "alb_url" {
  value = "http://${aws_lb.orders.dns_name}"
}

output "alb_target_group_name" {
  value = aws_lb_target_group.orders.name
}

output "alb_target_group_arn" {
  value = aws_lb_target_group.orders.arn
}

# --------------------------------------------------------------------------- data

output "aurora_cluster" {
  value = aws_rds_cluster.aurora.cluster_identifier
}

output "aurora_writer_endpoint" {
  value = aws_rds_cluster.aurora.endpoint
}

output "aurora_reader_endpoint" {
  value = aws_rds_cluster.aurora.reader_endpoint
}

output "aurora_instance_endpoints" {
  description = "Instance endpoints (fs-15 pins the processor to the writer instance, then fails over)."
  value = {
    (aws_rds_cluster_instance.aurora_1.identifier) = aws_rds_cluster_instance.aurora_1.endpoint
    (aws_rds_cluster_instance.aurora_2.identifier) = aws_rds_cluster_instance.aurora_2.endpoint
  }
}

output "aurora_security_group_id" {
  value = aws_security_group.aurora.id
}

output "db_name" {
  value = aws_rds_cluster.aurora.database_name
}

output "db_master_username" {
  value = aws_rds_cluster.aurora.master_username
}

output "db_app_secret_name" {
  value = aws_secretsmanager_secret.db_app.name
}

output "db_app_secret_arn" {
  value = aws_secretsmanager_secret.db_app.arn
}

output "db_catalog_secret_name" {
  value = aws_secretsmanager_secret.db_catalog.name
}

output "db_warden_ro_secret_name" {
  value = aws_secretsmanager_secret.db_warden_ro.name
}

output "db_app_password" {
  description = "Also in the db-app secret. Sensitive: stripped from stack.json."
  value       = random_password.app.result
  sensitive   = true
}

output "db_warden_ro_password" {
  description = "Also in the db-warden-ro secret. Sensitive: stripped from stack.json."
  value       = random_password.warden_ro.result
  sensitive   = true
}

output "redis_replication_group" {
  value = aws_elasticache_replication_group.redis.id
}

output "redis_primary_endpoint" {
  value = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "redis_security_group_id" {
  value = aws_security_group.redis.id
}

output "redis_app_ingress_rule_ids" {
  description = "The rules fs-10 revokes, by application security group."
  value       = { for k, v in aws_vpc_security_group_ingress_rule.redis_apps : k => v.security_group_rule_id }
}

output "app_security_group_ids" {
  value = local.app_security_groups
}

output "dynamodb_table" {
  value = aws_dynamodb_table.carts.name
}

# --------------------------------------------------------------------------- messaging

output "queue_urls" {
  value = merge(
    { for k, v in aws_sqs_queue.main : k => v.id },
    { for k, v in aws_sqs_queue.dlq : "${k}-dlq" => v.id },
  )
}

output "orders_queue_url" {
  value = aws_sqs_queue.main["orders"].id
}

output "notifications_queue_url" {
  value = aws_sqs_queue.main["notifications"].id
}

output "sns_topic_arn" {
  value = aws_sns_topic.order_events.arn
}

output "eventbridge_rules" {
  value = { for k, v in aws_cloudwatch_event_rule.schedule : k => v.name }
}

# --------------------------------------------------------------------------- compute

output "lambda_functions" {
  description = "short name => function name"
  value       = { for k, v in aws_lambda_function.fn : k => v.function_name }
}

output "lambda_role_names" {
  value = { for k, v in aws_iam_role.lambda : k => v.name }
}

output "checkout_alias" {
  value = aws_lambda_alias.checkout_live.name
}

output "ecr_repository_url" {
  value = aws_ecr_repository.app.repository_url
}

output "ecs_cluster" {
  value = aws_ecs_cluster.this.name
}

output "ecs_service" {
  value = aws_ecs_service.orders_api.name
}

output "ecs_task_family" {
  value = aws_ecs_task_definition.orders_api.family
}

output "ecs_execution_role_arn" {
  value = aws_iam_role.ecs_execution.arn
}

output "ecs_execution_role_name" {
  value = aws_iam_role.ecs_execution.name
}

output "ecs_log_group" {
  value = aws_cloudwatch_log_group.orders_api.name
}

output "eks_cluster_name" {
  value = aws_eks_cluster.this.name
}

# --------------------------------------------------------------------------- how WARDEN runs

output "reader_role_arn" {
  description = "The role the harness assumes before running WARDEN (reader.tf)."
  value       = aws_iam_role.fs_reader.arn
}

output "alarm_names" {
  value = [for a in aws_cloudwatch_metric_alarm.this : a.alarm_name]
}

output "teardown_check" {
  description = "Run after terraform destroy. An empty list is the only acceptable answer."
  value       = "aws resourcegroupstaggingapi get-resources --region ${var.region} --tag-filters Key=Project,Values=${local.tags.Project} --query 'ResourceTagMappingList[].ResourceARN'"
}
