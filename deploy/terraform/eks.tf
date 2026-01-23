module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 21.0"

  name               = local.cluster_name
  kubernetes_version = var.eks_version

  vpc_id                   = module.network.vpc_id
  subnet_ids               = module.network.private_subnets
  control_plane_subnet_ids = module.network.private_subnets

  endpoint_public_access       = true
  endpoint_public_access_cidrs = var.eks_public_access_cidrs
  endpoint_private_access      = true

  enable_cluster_creator_admin_permissions = var.eks_enable_cluster_creator_admin_permissions

  enable_irsa = true

  eks_managed_node_groups = {
    default = {
      create         = true
      name           = "${local.cluster_name}-ng"
      instance_types = var.node_instance_types
      min_size       = var.node_min_size
      max_size       = var.node_max_size
      desired_size   = var.node_desired_size
      subnet_ids     = module.network.private_subnets
    }
  }

  tags = local.tags
}
