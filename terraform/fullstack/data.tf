# The data layer: Aurora PostgreSQL, ElastiCache Redis, DynamoDB, and the application's secrets.
#
# ⛔ The schema, the app user and warden_ro are NOT created here: they are SQL, applied by
# `scripts/deploy_fullstack_apps.py bootstrap-db` from scenarios/fullstack/sql/bootstrap.sql.

# --------------------------------------------------------------------------- Aurora

resource "aws_db_subnet_group" "aurora" {
  name       = "${local.name}-aurora"
  subnet_ids = aws_subnet.public[*].id # publicly accessible: no NAT and no bastion, bounded by the SG
}

resource "aws_security_group" "aurora" {
  name        = "${local.name}-aurora"
  description = "Aurora. PostgreSQL from the operator address and the application security groups."
  vpc_id      = aws_vpc.this.id
}

resource "aws_vpc_security_group_ingress_rule" "aurora_operator" {
  security_group_id = aws_security_group.aurora.id
  description       = "PostgreSQL from the operator address"
  cidr_ipv4         = var.my_ip_cidr
  ip_protocol       = "tcp"
  from_port         = 5432
  to_port           = 5432
}

resource "aws_vpc_security_group_ingress_rule" "aurora_apps" {
  for_each                     = local.app_security_groups
  security_group_id            = aws_security_group.aurora.id
  description                  = "PostgreSQL from ${each.key}"
  referenced_security_group_id = each.value
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_rds_cluster" "aurora" {
  cluster_identifier     = "${local.name}-aurora"
  engine                 = "aurora-postgresql"
  engine_mode            = "provisioned"
  engine_version         = var.aurora_engine_version
  database_name          = "shop"
  master_username        = "warden_admin"
  master_password        = var.db_master_password
  db_subnet_group_name   = aws_db_subnet_group.aurora.name
  vpc_security_group_ids = [aws_security_group.aurora.id]
  storage_encrypted      = true

  serverlessv2_scaling_configuration {
    min_capacity = 0.5
    max_capacity = 2
  }

  backup_retention_period = 1    # Aurora's minimum
  skip_final_snapshot     = true # ⛔ without it a destroy FAILS and the bill keeps running
  deletion_protection     = false
  apply_immediately       = true
}

# Instance 1 is created first and so becomes the writer; instance 2 joins as the reader.
resource "aws_rds_cluster_instance" "aurora_1" {
  identifier                   = "${local.name}-aurora-1"
  cluster_identifier           = aws_rds_cluster.aurora.id
  instance_class               = "db.serverless"
  engine                       = aws_rds_cluster.aurora.engine
  engine_version               = aws_rds_cluster.aurora.engine_version
  publicly_accessible          = true
  promotion_tier               = 0
  performance_insights_enabled = false
  apply_immediately            = true
}

resource "aws_rds_cluster_instance" "aurora_2" {
  identifier                   = "${local.name}-aurora-2"
  cluster_identifier           = aws_rds_cluster.aurora.id
  instance_class               = "db.serverless"
  engine                       = aws_rds_cluster.aurora.engine
  engine_version               = aws_rds_cluster.aurora.engine_version
  publicly_accessible          = true
  promotion_tier               = 1
  performance_insights_enabled = false
  apply_immediately            = true
  depends_on                   = [aws_rds_cluster_instance.aurora_1]
}

# --------------------------------------------------------------------------- secrets
#
# recovery_window_in_days = 0: a destroyed stack must be re-creatable at once under the same name.

resource "random_password" "app" {
  length  = 32
  special = false # the value ends up in DSNs; no URL escaping to get wrong
}

resource "random_password" "catalog" {
  length  = 32
  special = false
}

resource "random_password" "warden_ro" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "db_app" {
  name                    = "${local.name}-db-app"
  description             = "Application Aurora credentials (user app)."
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "db_app" {
  secret_id = aws_secretsmanager_secret.db_app.id
  secret_string = jsonencode({
    username = "app"
    password = random_password.app.result
    host     = aws_rds_cluster.aurora.endpoint
    port     = 5432
    dbname   = aws_rds_cluster.aurora.database_name
  })
  # fs-21 rotates the value outside terraform; the harness restores it. A re-apply must not fight.
  lifecycle {
    ignore_changes = [secret_string]
  }
}

# ⛔ catalog-api has its OWN database user. It used to share `app` with orders-api, so fs-21 (rotate
# the app password, leave orders-api on the old one) also broke catalog-api through its static copy
# in a Kubernetes Secret - a second, unplanned victim the fault's verifier never looked at. One user
# per service is also what least privilege asks for: catalog-api only ever reads.
resource "aws_secretsmanager_secret" "db_catalog" {
  name                    = "${local.name}-db-catalog"
  description             = "catalog-api's read-only application credentials (user catalog)."
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "db_catalog" {
  secret_id = aws_secretsmanager_secret.db_catalog.id
  secret_string = jsonencode({
    username = "catalog"
    password = random_password.catalog.result
    host     = aws_rds_cluster.aurora.reader_endpoint
    port     = 5432
    dbname   = aws_rds_cluster.aurora.database_name
  })
}

# warden_ro's credentials: read by the harness (to build WARDEN's DSNs) and by bootstrap-db. WARDEN
# itself never reads any secret value.
resource "aws_secretsmanager_secret" "db_warden_ro" {
  name                    = "${local.name}-db-warden-ro"
  description             = "Read-only monitoring credentials (user warden_ro, pg_monitor only)."
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "db_warden_ro" {
  secret_id = aws_secretsmanager_secret.db_warden_ro.id
  secret_string = jsonencode({
    username = "warden_ro"
    password = random_password.warden_ro.result
    host     = aws_rds_cluster.aurora.endpoint
    reader   = aws_rds_cluster.aurora.reader_endpoint
    port     = 5432
    dbname   = aws_rds_cluster.aurora.database_name
  })
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
