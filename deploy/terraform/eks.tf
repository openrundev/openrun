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

  security_group_additional_rules = {
    egress_nodes_all = {
      description                = "Allow control plane to reach worker nodes"
      protocol                   = "-1"
      from_port                  = 0
      to_port                    = 0
      type                       = "egress"
      source_node_security_group = true
    }
  }

  node_security_group_additional_rules = {
    openrun_nlb_http = {
      description = "Allow NLB to reach OpenRun HTTP"
      protocol    = "tcp"
      from_port   = 80
      to_port     = 80
      type        = "ingress"
      cidr_blocks = local.vpc_public_subnets
    }
    openrun_nlb_https = {
      description = "Allow NLB to reach OpenRun HTTPS"
      protocol    = "tcp"
      from_port   = 443
      to_port     = 443
      type        = "ingress"
      cidr_blocks = local.vpc_public_subnets
    }
  }

  enable_cluster_creator_admin_permissions = var.eks_enable_cluster_creator_admin_permissions

  enable_irsa                        = true
  create_primary_security_group_tags = false

  eks_managed_node_groups = {
    default = {
      create                                = true
      name                                  = "${local.cluster_name}-ng"
      instance_types                        = var.node_instance_types
      min_size                              = var.node_min_size
      max_size                              = var.node_max_size
      desired_size                          = var.node_desired_size
      subnet_ids                            = module.network.private_subnets
      enable_bootstrap_user_data            = true
      # Avoid multiple kubernetes.io/cluster/* tagged SGs on node ENIs (breaks LB controller).
      attach_cluster_primary_security_group = false
      cloudinit_pre_nodeadm = [
        {
          content      = <<-EOT
            #!/bin/bash
            # noop: ensure MIME multipart user data so EKS can append nodeadm config
          EOT
          content_type = "text/x-shellscript"
        }
      ]
    }
  }

  tags = local.tags
}
