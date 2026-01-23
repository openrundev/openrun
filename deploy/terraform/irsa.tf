locals {
  irsa_oidc_host = replace(module.eks.cluster_oidc_issuer_url, "https://", "")
}

data "aws_iam_policy_document" "openrun_assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [module.eks.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.irsa_oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.irsa_oidc_host}:sub"
      values   = ["system:serviceaccount:${var.openrun_namespace}:${var.openrun_service_account_name}"]
    }
  }
}

resource "aws_iam_role" "openrun_irsa" {
  name               = "${var.name_prefix}-irsa"
  assume_role_policy = data.aws_iam_policy_document.openrun_assume_role.json
  tags               = local.tags
}

resource "aws_iam_policy" "openrun_ecr" {
  name_prefix = "${var.name_prefix}-ecr-"
  description = "Allow OpenRun to push/pull images from ECR"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["ecr:GetAuthorizationToken"],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:DescribeRepositories",
          "ecr:ListImages"
        ],
        Resource = aws_ecr_repository.openrun.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "openrun_ecr" {
  role       = aws_iam_role.openrun_irsa.name
  policy_arn = aws_iam_policy.openrun_ecr.arn
}
