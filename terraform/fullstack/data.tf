# The data layer: ElastiCache Redis, DynamoDB, and the application's connection metadata.
#
# ⛔ AURORA IS NOT HERE (changed 2026-09-26, docs/WAVE4-FULLSTACK.md "Free-plan constraints"). The
# account is on the AWS Free plan, which only creates Aurora clusters in EXPRESS configuration, and
# the AWS provider cannot create one. `aurora_express.py create` (this directory, the INFRA
# pipeline) creates cluster warden-pg-fs-aurora after `terraform apply`; `destroy` removes it
# before `terraform destroy`. Express clusters take IAM database authentication only: there are no
# database passwords anywhere in this stack.
#
# ⛔ The schema and the roles app / catalog / warden_ro are NOT created here: they are SQL, applied
# by `scripts/deploy_fullstack_apps.py bootstrap-db` from scenarios/fullstack/sql/bootstrap.sql.

locals {
  aurora_cluster = "${local.name}-aurora" # created by aurora_express.py, not by terraform
  # rds-db:connect is scoped by DATABASE USER. The cluster's resource id (the middle of the ARN) is
  # only known after aurora_express.py runs, so it is `*`: the user name is the scope.
  dbuser_arn = { for u in ["app", "catalog"] :
    u => "arn:aws:rds-db:${var.region}:${data.aws_caller_identity.current.account_id}:dbuser:*/${u}"
  }
}

# --------------------------------------------------------------------------- secrets
#
# recovery_window_in_days = 0: a destroyed stack must be re-creatable at once under the same name.
#
# ONE secret, and it holds connection METADATA, not a credential (IAM tokens replace passwords).
# Kept because (a) the in-VPC Lambdas fall back to its host/reader when DB_HOST is empty - terraform
# cannot know the endpoints - and (b) orders-api's task definition injects a value from it, so the
# execution role still resolves a secret at task start and fs-18 stays the fault it was designed as.
# The catalog and warden_ro secrets were removed: with no password there was nothing in them that
# stack.json and the ConfigMap do not already carry.

resource "aws_secretsmanager_secret" "db_app" {
  name                    = "${local.name}-db-app"
  description             = "Aurora connection metadata for user app (no password: IAM authentication)."
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "db_app" {
  secret_id = aws_secretsmanager_secret.db_app.id
  secret_string = jsonencode({
    username = "app"
    dbname   = "shop"
    port     = 5432
    host     = "" # filled by aurora_express.py create (the cluster endpoint)
    reader   = "" # and the reader endpoint
  })
  # aurora_express.py writes the endpoints; a re-apply must not blank them.
  lifecycle {
    ignore_changes = [secret_string]
  }
}

# --------------------------------------------------------------------------- ElastiCache Redis

resource "aws_elasticache_subnet_group" "redis" {
  name       = "${local.name}-redis"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_security_group" "redis" {
  name        = "${local.name}-redis"
  description = "Redis. 6379 from the application security groups only."
  vpc_id      = aws_vpc.this.id
}

# fs-10 revokes exactly these rules and restores them.
resource "aws_vpc_security_group_ingress_rule" "redis_apps" {
  for_each                     = local.app_security_groups
  security_group_id            = aws_security_group.redis.id
  description                  = "Redis from ${each.key}"
  referenced_security_group_id = each.value
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "${local.name}-redis"
  description                = "Wave 4 application cache"
  engine                     = "redis"
  engine_version             = "7.1"
  node_type                  = "cache.t4g.micro"
  num_cache_clusters         = 2 # primary + 1 replica
  automatic_failover_enabled = true
  parameter_group_name       = "default.redis7" # volatile-lru: filler keys carry a TTL so they evict
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.redis.name
  security_group_ids         = [aws_security_group.redis.id]
  at_rest_encryption_enabled = true
  transit_encryption_enabled = false # VPC-only; the apps connect with plain redis-py
  snapshot_retention_limit   = 0
  apply_immediately          = true
}

# --------------------------------------------------------------------------- DynamoDB

resource "aws_dynamodb_table" "carts" {
  name           = "${local.name}-carts"
  billing_mode   = "PROVISIONED" # no autoscaling: a capacity fault must stay a capacity fault
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "cart_id"
  range_key      = "order_id"

  attribute {
    name = "cart_id"
    type = "S"
  }
  attribute {
    name = "order_id"
    type = "S"
  }

  deletion_protection_enabled = false
}
