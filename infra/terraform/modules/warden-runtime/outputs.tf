output "audit_signer_key_id" {
  description = "WARDEN_AUDIT_KMS_KEY_ID: the alias of the key that signs audit checkpoints."
  value       = aws_kms_alias.audit_signer.name
}

output "anchor_bucket" {
  description = "WARDEN_AUDIT_ANCHOR_BUCKET: where every checkpoint is anchored under Object Lock."
  value       = aws_s3_bucket.anchors.bucket
}

output "audit_db_endpoint" {
  description = "The audit database's writer endpoint: WARDEN_AUDIT_DSN points here (a Secrets Manager secret)."
  value       = local.audit_db.host
}

output "runtime_security_group_id" {
  description = "The security group of WARDEN's workers and Lambdas."
  value       = aws_security_group.runtime.id
}

output "front_door_url" {
  description = "The HTTP API's own address: Alertmanager posts to <this>/alertmanager."
  value       = aws_apigatewayv2_api.front.api_endpoint
}

output "approval_dns_target" {
  description = "Where the approval domain's DNS-only CNAME points (empty without an approval domain)."
  value       = var.approval_domain == "" ? "" : aws_apigatewayv2_domain_name.approval[0].domain_name_configuration[0].target_domain_name
}

output "migrate_function" {
  description = "The Lambda that creates the audit's schema and writer login; runtime.yml invokes it after each apply."
  value       = aws_lambda_function.migrate.function_name
}
