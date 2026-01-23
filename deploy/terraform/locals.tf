locals {
  cluster_name = "${var.name_prefix}-eks"
  tags = merge(
    {
      Project = var.name_prefix
    },
    var.tags
  )
}
