resource "aws_ecr_repository" "openrun" {
  name                 = var.ecr_repo_name
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = local.tags
}

resource "aws_ecr_repository_creation_template" "apps" {
  prefix      = "openrun-apps"
  description = "Auto-create repos on push for openrun-apps/*"

  applied_for = ["CREATE_ON_PUSH"]

  image_tag_mutability = "MUTABLE"
}

resource "aws_ecr_lifecycle_policy" "openrun" {
  repository = aws_ecr_repository.openrun.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last ${var.ecr_lifecycle_keep_last_n} images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = var.ecr_lifecycle_keep_last_n
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

output "ecr_repository_url" {
  description = "ECR repository URL for OpenRun images."
  value       = aws_ecr_repository.openrun.repository_url
}
