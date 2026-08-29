# Redis for the grant revocation cache, rate limiting, and idempotency
# reservations. A cache miss is never authoritative (Postgres remains the
# source of truth for grants), so a single non-replicated node is an
# acceptable v1 footprint. Private subnets only, reachable solely from the
# broker service security group.

resource "aws_elasticache_subnet_group" "redis" {
  name       = "${local.name_prefix}-redis"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "${local.name_prefix}-redis"
  }
}

resource "aws_security_group" "redis" {
  name        = "${local.name_prefix}-redis"
  description = "ElastiCache Redis: ingress only from the broker service"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Redis from broker tasks"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.broker_service.id]
  }

  tags = {
    Name = "${local.name_prefix}-redis"
  }
}

resource "aws_elasticache_cluster" "redis" {
  cluster_id           = "${local.name_prefix}-redis"
  engine               = "redis"
  engine_version       = var.redis_engine_version
  node_type            = var.redis_node_type
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  port                 = 6379

  subnet_group_name  = aws_elasticache_subnet_group.redis.name
  security_group_ids = [aws_security_group.redis.id]

  tags = {
    Name = "${local.name_prefix}-redis"
  }
}
