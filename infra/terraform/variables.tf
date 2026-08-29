# Input variables (and shared naming locals) for the CredBroker stack.

variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Project slug used in resource names and tags."
  type        = string
  default     = "credbroker"
}

variable "environment" {
  description = "Deployment environment slug (prod, staging, ...)."
  type        = string
  default     = "prod"
}

# --- Networking -------------------------------------------------------------

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.42.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for the two public subnets (ALB, NAT gateway)."
  type        = list(string)
  default     = ["10.42.0.0/24", "10.42.1.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for the two private subnets (ECS tasks, RDS, ElastiCache, gRPC NLB)."
  type        = list(string)
  default     = ["10.42.10.0/24", "10.42.11.0/24"]
}

# --- Broker service ---------------------------------------------------------

variable "container_image_tag" {
  description = "Image tag in the ECR repository to deploy (CI pushes the git SHA)."
  type        = string
  default     = "latest"
}

variable "broker_cpu" {
  description = "Fargate task CPU units (256 = 0.25 vCPU)."
  type        = number
  default     = 512
}

variable "broker_memory" {
  description = "Fargate task memory in MiB."
  type        = number
  default     = 1024
}

variable "broker_desired_count" {
  description = "Initial number of broker tasks (autoscaling adjusts it afterwards)."
  type        = number
  default     = 2
}

variable "broker_min_count" {
  description = "Autoscaling floor for broker tasks."
  type        = number
  default     = 2
}

variable "broker_max_count" {
  description = "Autoscaling ceiling for broker tasks."
  type        = number
  default     = 6
}

variable "autoscale_requests_per_target" {
  description = "Target ALB requests per task per minute for request-count autoscaling."
  type        = number
  default     = 500
}

variable "autoscale_cpu_target_percent" {
  description = "Target average CPU percent for the fallback CPU autoscaling policy (covers gRPC traffic, which the ALB request count cannot see)."
  type        = number
  default     = 60
}

variable "alb_certificate_arn" {
  description = "ACM certificate ARN for the public ALB. When set, an HTTPS :443 listener terminates TLS and the :80 listener redirects to it; when empty the ALB serves plain HTTP (dev only)."
  type        = string
  default     = ""
}

variable "public_base_url" {
  description = "Externally reachable base URL for OAuth redirects, e.g. https://broker.example.com (no trailing slash). When empty the plain-HTTP ALB DNS name is used."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "CloudWatch log retention for broker task logs."
  type        = number
  default     = 30
}

# --- Data stores ------------------------------------------------------------

variable "db_engine_version" {
  description = "PostgreSQL engine version for RDS."
  type        = string
  default     = "16.6"
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage_gb" {
  description = "RDS allocated storage in GiB."
  type        = number
  default     = 20
}

variable "db_deletion_protection" {
  description = "Enable RDS deletion protection (turn on once the environment carries real credentials)."
  type        = bool
  default     = false
}

variable "redis_engine_version" {
  description = "Redis engine version for ElastiCache."
  type        = string
  default     = "7.1"
}

variable "redis_node_type" {
  description = "ElastiCache node type."
  type        = string
  default     = "cache.t4g.micro"
}

# --- Shared naming ----------------------------------------------------------

locals {
  # Prefix for every named resource, e.g. "credbroker-prod".
  name_prefix = "${var.project}-${var.environment}"
}
