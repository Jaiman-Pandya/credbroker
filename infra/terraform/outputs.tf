# Stack outputs: endpoints for operators and values CI needs (ECR repository,
# cluster/service names for `aws ecs update-service` deploys).

output "http_endpoint" {
  description = "Public base URL (OAuth flow, /healthz; /metrics is blocked at the ALB)."
  value       = var.public_base_url != "" ? var.public_base_url : "http://${aws_lb.http.dns_name}"
}

output "grpc_endpoint" {
  description = "Internal gRPC endpoint for in-VPC agents (host:port)."
  value       = "${aws_lb.grpc.dns_name}:50051"
}

output "ecr_repository_url" {
  description = "ECR repository for broker images (CI pushes here)."
  value       = aws_ecr_repository.broker.repository_url
}

output "ecs_cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  description = "ECS service name (target for CI deploys and one-off migration tasks)."
  value       = aws_ecs_service.broker.name
}

output "kms_key_arn" {
  description = "KMS key used for envelope encryption of stored credentials (set as CREDBROKER_KMS_KEY_ID)."
  value       = aws_kms_key.credentials.arn
}

output "rds_address" {
  description = "RDS Postgres endpoint address (private)."
  value       = aws_db_instance.postgres.address
}

output "redis_address" {
  description = "ElastiCache Redis endpoint address (private)."
  value       = aws_elasticache_cluster.redis.cache_nodes[0].address
}

output "jwt_signing_secret_arn" {
  description = "Secrets Manager secret holding the grant-token signing keypair (populate out of band)."
  value       = aws_secretsmanager_secret.jwt_signing.arn
}

output "google_oauth_secret_arn" {
  description = "Secrets Manager secret holding the Google OAuth client (populate out of band)."
  value       = aws_secretsmanager_secret.google_oauth.arn
}

output "database_secret_arn" {
  description = "Secrets Manager secret holding RDS credentials and the SQLAlchemy URL."
  value       = aws_secretsmanager_secret.database.arn
}
