# The runtime's own security group: workers and Lambdas. Only it may reach the audit database.
resource "aws_security_group" "runtime" {
  name_prefix = "warden-${var.environment}-runtime-"
  description = "WARDEN ${var.environment}: workers and Lambdas"
  vpc_id      = var.vpc_id
  egress {
    description = "HTTPS out: Temporal Cloud, AWS APIs, chat"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Project = "warden", Environment = var.environment }
}

resource "aws_security_group" "audit_db" {
  name_prefix = "warden-${var.environment}-audit-db-"
  description = "WARDEN ${var.environment}: the audit database, reached by the runtime only"
  vpc_id      = var.vpc_id
  tags        = { Project = "warden", Environment = var.environment }
}

resource "aws_vpc_security_group_ingress_rule" "audit_db_from_runtime" {
  security_group_id            = aws_security_group.audit_db.id
  referenced_security_group_id = aws_security_group.runtime.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "PostgreSQL from the WARDEN runtime only"
}

resource "aws_vpc_security_group_egress_rule" "runtime_to_audit_db" {
  security_group_id            = aws_security_group.runtime.id
  referenced_security_group_id = aws_security_group.audit_db.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "PostgreSQL to the audit database"
}
