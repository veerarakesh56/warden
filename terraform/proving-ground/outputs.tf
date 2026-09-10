# Everything the benchmark harness needs, and nothing it does not.
#
# ⛔ `db_dsn` is marked sensitive so it is never echoed into a terminal or a CI log by accident.
# Read it deliberately with `terraform output -raw db_dsn`.

output "region" {
  value = var.region
}

output "account_id" {
  description = "Used only to prove in the evidence bundle that this ran against a real account. Redacted before anything is published."
  value       = data.aws_caller_identity.current.account_id
}

# --------------------------------------------------------------------------- ecs

output "ecs_cluster" {
  value = aws_ecs_cluster.this.name
}

output "ecs_service" {
  value = aws_ecs_service.checkout.name
}

output "log_group" {
  value = aws_cloudwatch_log_group.service.name
}

output "baseline_task_definition" {
  description = "⭐ Revision 2, NOT revision 1. This is what every scenario reverts to, and it must be a revision that HAS a predecessor - on revision 1 there is nothing to compare against, so WARDEN would report its first rollout as a deploy and the restart tests could distinguish nothing."
  value       = aws_ecs_task_definition.healthy_reregistered.arn
}

output "task_definition_healthy_v1" {
  description = "Revision 1. The predecessor that makes the image comparison in `deploys()` meaningful. Nothing points at it."
  value       = aws_ecs_task_definition.healthy.arn
}

output "task_definition_bad" {
  description = "Revision 3, registered but not deployed. The harness switches to it to stage a real bad deploy."
  value       = aws_ecs_task_definition.bad.arn
}

# --------------------------------------------------------------------------- what the harness breaks
#
# The fault injector refuses to touch anything it was not handed here, and cross-checks each one
# against the Project=warden-proving-ground tag before acting.

output "service_security_group_id" {
  description = "The task security group. Scenario ecs-12 revokes its egress and restores it verbatim."
  value       = aws_security_group.service.id
}

output "route_table_id" {
  description = "The public route table. Scenario ecs-13 deletes its default route and restores it."
  value       = aws_route_table.public.id
}

# --------------------------------------------------------------------------- how WARDEN runs

output "warden_reader_role_arn" {
  description = "⭐ The role the harness ASSUMES before running WARDEN. Four read actions, nothing else - so 'WARDEN is read-only' is enforced by IAM during the benchmark rather than asserted about its source. Scenario ecs-11 removes one of the four from this role."
  value       = aws_iam_role.reader.arn
}

output "warden_reader_role_name" {
  value = aws_iam_role.reader.name
}

# --------------------------------------------------------------------------- optional services

output "db_endpoint" {
  description = "Empty unless enable_rds = true."
  value       = var.enable_rds ? aws_db_instance.this[0].address : ""
}

output "db_dsn" {
  description = "WARDEN_DB_DSN for the RDS instance. Empty unless enable_rds = true."
  value       = var.enable_rds ? "postgresql://${aws_db_instance.this[0].username}:${var.db_password}@${aws_db_instance.this[0].address}:${aws_db_instance.this[0].port}/${aws_db_instance.this[0].db_name}" : ""
  sensitive   = true
}

output "eks_cluster" {
  description = "Empty unless enable_eks = true."
  value       = var.enable_eks ? aws_eks_cluster.this[0].name : ""
}

# --------------------------------------------------------------------------- cleanup

output "teardown_check" {
  description = "Run this after `terraform destroy`. An empty list is the only acceptable answer."
  value       = "aws resourcegroupstaggingapi get-resources --region ${var.region} --tag-filters Key=Project,Values=warden-proving-ground --query 'ResourceTagMappingList[].ResourceARN'"
}

output "estimated_hourly_usd" {
  description = "What this configuration costs per hour while it is up. Computed from the switches actually set, so it cannot drift from a number written in a README."
  value = format(
    "%.4f",
    # Fargate Spot, 2 tasks x (0.25 vCPU + 0.5 GB) at ap-south-1 spot rates, plus the optional bits.
    # NOTE: ap-south-2 (Hyderabad) prices differ slightly from ap-south-1. This is an ESTIMATE for
    # sanity-checking the bill, never a quote - the $5 budget alarm is the real guard.
    0.0086 + (var.enable_rds ? 0.0210 : 0) + (var.enable_eks ? 0.1096 : 0)
  )
}
