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
  # Temporal Cloud's endpoints listen on 7233 only: with 443 alone every worker timed out connecting (2026-10-09).
  egress {
    description = "Temporal Cloud gRPC"
    from_port   = 7233
    to_port     = 7233
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # Every egress rule is here, in the group's own blocks: Terraform treats them as the whole list, so a separate
  # egress rule resource was deleted by the group's next in-place update (the audit became unreachable, 2026-10-09).
  egress {
    description     = "PostgreSQL to the audit database"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.audit_db.id]
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
