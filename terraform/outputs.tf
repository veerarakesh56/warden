output "task_definition_arn" {
  description = "ARN of the WARDEN task definition. Run it with `aws ecs run-task` or wire it to an EventBridge rule on your alerting pipeline."
  value       = aws_ecs_task_definition.warden.arn
}

output "task_role_arn" {
  description = "The role WARDEN runs as. Read-only by design - it can inspect infrastructure but not change it."
  value       = aws_iam_role.task.arn
}

output "security_group_id" {
  description = "Egress-only security group for the task."
  value       = aws_security_group.warden.id
}

output "log_group_name" {
  description = "CloudWatch log group carrying the run audit trail."
  value       = aws_cloudwatch_log_group.warden.name
}
