# ECS Fargate service for the broker, fronted by two load balancers:
#
#   * A public APPLICATION load balancer -> container :8000 for the HTTP
#     surface (OAuth redirect dance needs to be browser-reachable, plus
#     /healthz). With var.alb_certificate_arn set, :443 terminates TLS and
#     :80 redirects to it; when unset, :80 serves plain HTTP (dev only —
#     OAuth needs HTTPS in production). /metrics is never forwarded: a
#     listener rule returns a fixed 403 because Prometheus scrapes
#     in-network, not through the ALB.
#   * An INTERNAL network load balancer on :50051 -> container :50051 for the
#     agent-facing gRPC API. Agents are in-VPC workloads; keeping the gRPC
#     endpoint off the public internet means a leaked grant token alone is not
#     enough to invoke tools from outside. NLB TCP passthrough avoids the
#     ALB gRPC requirement for an HTTPS listener/certificate.
#
# Autoscaling tracks ALB request count per target, with an average-CPU policy
# as the fallback signal (gRPC traffic through the NLB never appears in ALB
# request metrics, but it does show up as CPU).
#
# Database migrations are NOT run at container startup in AWS; run
# `python -m alembic upgrade head` as a one-off ECS task (same task
# definition, overridden command) before rolling a deploy.

resource "aws_ecs_cluster" "main" {
  name = local.name_prefix

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_cloudwatch_log_group" "broker" {
  name              = "/ecs/${local.name_prefix}"
  retention_in_days = var.log_retention_days
}

# --- Security groups --------------------------------------------------------

resource "aws_security_group" "alb" {
  name        = "${local.name_prefix}-alb"
  description = "Public ALB for the broker HTTP surface"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP from anywhere (OAuth callbacks arrive from user browsers)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  dynamic "ingress" {
    for_each = var.alb_certificate_arn != "" ? [1] : []
    content {
      description = "HTTPS from anywhere (TLS terminated at the ALB)"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  egress {
    description = "To broker tasks"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-alb"
  }
}

resource "aws_security_group" "broker_service" {
  name        = "${local.name_prefix}-broker"
  description = "Broker Fargate tasks"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "HTTP from the ALB only"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # The internal NLB is TCP passthrough and preserves the client source IP,
  # so gRPC ingress is scoped to the VPC CIDR (in-VPC agents + NLB health
  # checks) rather than to a load balancer security group.
  ingress {
    description = "gRPC from inside the VPC via the internal NLB"
    from_port   = 50051
    to_port     = 50051
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Outbound to RDS, Redis, KMS, Secrets Manager, and provider APIs via NAT"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-broker"
  }
}

# --- Public ALB (:80/:443 -> container :8000) -------------------------------

resource "aws_lb" "http" {
  name               = "${local.name_prefix}-alb"
  load_balancer_type = "application"
  internal           = false
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  tags = {
    Name = "${local.name_prefix}-alb"
  }
}

resource "aws_lb_target_group" "http" {
  name        = "${local.name_prefix}-http"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  deregistration_delay = 30

  health_check {
    path                = "/healthz"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = {
    Name = "${local.name_prefix}-http"
  }
}

# Exactly one of the two dynamic blocks renders, so the listener always has a
# single default_action: plain-HTTP forward without a certificate (dev),
# redirect-to-HTTPS once var.alb_certificate_arn is set.
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.http.arn
  port              = 80
  protocol          = "HTTP"

  dynamic "default_action" {
    for_each = var.alb_certificate_arn == "" ? [1] : []
    content {
      type             = "forward"
      target_group_arn = aws_lb_target_group.http.arn
    }
  }

  dynamic "default_action" {
    for_each = var.alb_certificate_arn != "" ? [1] : []
    content {
      type = "redirect"

      redirect {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }
}

resource "aws_lb_listener" "https" {
  count = var.alb_certificate_arn != "" ? 1 : 0

  load_balancer_arn = aws_lb.http.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.alb_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.http.arn
  }
}

# Prometheus scrapes /metrics in-network, never through the public ALB, so the
# forwarding listener (HTTPS when a certificate exists, HTTP otherwise) answers
# 403 for it ahead of the default forward.
resource "aws_lb_listener_rule" "block_metrics" {
  listener_arn = var.alb_certificate_arn != "" ? aws_lb_listener.https[0].arn : aws_lb_listener.http.arn
  priority     = 1

  action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "Forbidden"
      status_code  = "403"
    }
  }

  condition {
    path_pattern {
      values = ["/metrics*"]
    }
  }
}

# --- Internal NLB (gRPC :50051) ---------------------------------------------

resource "aws_lb" "grpc" {
  name               = "${local.name_prefix}-grpc"
  load_balancer_type = "network"
  internal           = true
  subnets            = aws_subnet.private[*].id

  tags = {
    Name = "${local.name_prefix}-grpc"
  }
}

resource "aws_lb_target_group" "grpc" {
  name        = "${local.name_prefix}-grpc"
  port        = 50051
  protocol    = "TCP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  deregistration_delay = 30

  health_check {
    protocol            = "TCP"
    interval            = 15
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }

  tags = {
    Name = "${local.name_prefix}-grpc"
  }
}

resource "aws_lb_listener" "grpc" {
  load_balancer_arn = aws_lb.grpc.arn
  port              = 50051
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.grpc.arn
  }
}

# --- Task definition --------------------------------------------------------

resource "aws_ecs_task_definition" "broker" {
  family                   = "${local.name_prefix}-broker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.broker_cpu)
  memory                   = tostring(var.broker_memory)
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = "broker"
      image     = "${aws_ecr_repository.broker.repository_url}:${var.container_image_tag}"
      essential = true

      portMappings = [
        { containerPort = 8000, protocol = "tcp" },
        { containerPort = 50051, protocol = "tcp" },
      ]

      # Non-secret configuration only. Everything sensitive is injected below
      # via `secrets` so raw values never appear in the task definition.
      environment = [
        {
          name  = "CREDBROKER_REDIS_URL"
          value = "redis://${aws_elasticache_cluster.redis.cache_nodes[0].address}:${aws_elasticache_cluster.redis.cache_nodes[0].port}/0"
        },
        {
          name  = "CREDBROKER_AWS_REGION"
          value = var.aws_region
        },
        {
          # Non-empty KMS key id switches the broker to real envelope
          # encryption via AWS KMS (credbroker/crypto/kms.py).
          name  = "CREDBROKER_KMS_KEY_ID"
          value = aws_kms_key.credentials.arn
        },
        {
          # OAuth redirect URIs are built from this base; set
          # var.public_base_url (alongside var.alb_certificate_arn) once a
          # real domain + TLS exist, and update the Google OAuth app to match.
          name  = "CREDBROKER_PUBLIC_BASE_URL"
          value = var.public_base_url != "" ? var.public_base_url : "http://${aws_lb.http.dns_name}"
        },
      ]

      secrets = [
        {
          name      = "CREDBROKER_DATABASE_URL"
          valueFrom = "${aws_secretsmanager_secret.database.arn}:url::"
        },
        {
          name      = "CREDBROKER_JWT_PRIVATE_KEY_PEM"
          valueFrom = "${aws_secretsmanager_secret.jwt_signing.arn}:private_key_pem::"
        },
        {
          name      = "CREDBROKER_JWT_PUBLIC_KEY_PEM"
          valueFrom = "${aws_secretsmanager_secret.jwt_signing.arn}:public_key_pem::"
        },
        {
          name      = "CREDBROKER_GOOGLE_CLIENT_ID"
          valueFrom = "${aws_secretsmanager_secret.google_oauth.arn}:client_id::"
        },
        {
          name      = "CREDBROKER_GOOGLE_CLIENT_SECRET"
          valueFrom = "${aws_secretsmanager_secret.google_oauth.arn}:client_secret::"
        },
        {
          name      = "CREDBROKER_OAUTH_STATE_SECRET"
          valueFrom = "${aws_secretsmanager_secret.google_oauth.arn}:oauth_state_secret::"
        },
      ]

      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)\""]
        interval    = 15
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.broker.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "broker"
        }
      }
    }
  ])
}

# --- Service ----------------------------------------------------------------

resource "aws_ecs_service" "broker" {
  name            = "${local.name_prefix}-broker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.broker.arn
  desired_count   = var.broker_desired_count
  launch_type     = "FARGATE"

  health_check_grace_period_seconds = 120

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.broker_service.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.http.arn
    container_name   = "broker"
    container_port   = 8000
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.grpc.arn
    container_name   = "broker"
    container_port   = 50051
  }

  # Autoscaling owns the live task count after creation.
  lifecycle {
    ignore_changes = [desired_count]
  }

  depends_on = [
    aws_lb_listener.http,
    aws_lb_listener.https,
    aws_lb_listener.grpc,
  ]
}

# --- Autoscaling ------------------------------------------------------------

resource "aws_appautoscaling_target" "broker" {
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.broker.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = var.broker_min_count
  max_capacity       = var.broker_max_count
}

# Primary signal: HTTP request rate per task, measured at the ALB.
resource "aws_appautoscaling_policy" "broker_requests" {
  name               = "${local.name_prefix}-broker-requests"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.broker.service_namespace
  resource_id        = aws_appautoscaling_target.broker.resource_id
  scalable_dimension = aws_appautoscaling_target.broker.scalable_dimension

  target_tracking_scaling_policy_configuration {
    target_value = var.autoscale_requests_per_target

    predefined_metric_specification {
      predefined_metric_type = "ALBRequestCountPerTarget"
      resource_label         = "${aws_lb.http.arn_suffix}/${aws_lb_target_group.http.arn_suffix}"
    }

    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

# Fallback signal: average CPU, which also reflects gRPC load the ALB metric
# cannot observe. Application Auto Scaling scales out on whichever policy
# demands more capacity.
resource "aws_appautoscaling_policy" "broker_cpu" {
  name               = "${local.name_prefix}-broker-cpu"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.broker.service_namespace
  resource_id        = aws_appautoscaling_target.broker.resource_id
  scalable_dimension = aws_appautoscaling_target.broker.scalable_dimension

  target_tracking_scaling_policy_configuration {
    target_value = var.autoscale_cpu_target_percent

    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }

    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
