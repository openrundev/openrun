locals {
  cluster_name = "${var.name_prefix}-eks"
  tags = merge(
    {
      Project = var.name_prefix
    },
    var.tags
  )

  aws_cli_profile_args = var.aws_profile != "" ? ["--profile", var.aws_profile] : []
  aws_cli_profile_arg  = var.aws_profile != "" ? "--profile ${var.aws_profile}" : ""
}
