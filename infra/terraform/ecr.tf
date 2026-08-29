# Container registry for the broker image. CI builds and pushes here; the
# ECS task definition references ${repository_url}:${var.container_image_tag}.

resource "aws_ecr_repository" "broker" {
  name                 = local.name_prefix
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "${local.name_prefix}-ecr"
  }
}

# Keep the registry bounded: retain the 20 most recent images, expire
# anything older.
resource "aws_ecr_lifecycle_policy" "broker" {
  repository = aws_ecr_repository.broker.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Retain only the 20 most recent images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 20
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}
