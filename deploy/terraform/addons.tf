locals {
  addons_oidc_host = replace(module.eks.cluster_oidc_issuer_url, "https://", "")
}

data "aws_iam_policy_document" "lb_assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [module.eks.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.addons_oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.addons_oidc_host}:sub"
      values   = ["system:serviceaccount:kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "aws_iam_role" "lb_controller" {
  name               = "${module.eks.cluster_name}-aws-lb-controller"
  assume_role_policy = data.aws_iam_policy_document.lb_assume_role.json
  tags               = local.tags
}

resource "aws_iam_policy" "lb_controller" {
  name        = "${module.eks.cluster_name}-aws-lb-controller"
  description = "IAM policy for AWS Load Balancer Controller"

  # Upstream policy for controller v3.6.2; update alongside the chart version.
  policy = file("${path.module}/aws-load-balancer-controller-iam-policy.json")
}

resource "aws_iam_role_policy_attachment" "lb_controller" {
  role       = aws_iam_role.lb_controller.name
  policy_arn = aws_iam_policy.lb_controller.arn
}

resource "kubernetes_service_account_v1" "lb_controller" {
  metadata {
    name      = "aws-load-balancer-controller"
    namespace = "kube-system"
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.lb_controller.arn
    }
  }
}

resource "helm_release" "lb_controller" {
  name       = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  namespace  = "kube-system"

  version = var.aws_load_balancer_controller_chart_version != "" ? var.aws_load_balancer_controller_chart_version : null

  set = [
    {
      name  = "clusterName"
      value = module.eks.cluster_name
    },
    {
      name  = "region"
      value = var.aws_region
    },
    {
      name  = "vpcId"
      value = module.network.vpc_id
    },
    {
      name  = "serviceAccount.create"
      value = "false"
    },
    {
      name  = "serviceAccount.name"
      value = kubernetes_service_account_v1.lb_controller.metadata[0].name
    }
  ]

  depends_on = [kubernetes_service_account_v1.lb_controller, aws_iam_role_policy_attachment.lb_controller]
}

# Select the newest AWS-managed add-on release compatible with the cluster.
data "aws_eks_addon_version" "current" {
  for_each = toset(["aws-ebs-csi-driver", "vpc-cni", "coredns", "kube-proxy"])

  addon_name         = each.key
  kubernetes_version = var.eks_version
  most_recent        = true
}

# EBS CSI driver IRSA role and addon

data "aws_iam_policy_document" "ebs_assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [module.eks.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.addons_oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.addons_oidc_host}:sub"
      values   = ["system:serviceaccount:kube-system:ebs-csi-controller-sa"]
    }
  }
}

resource "aws_iam_role" "ebs_csi" {
  name               = "${module.eks.cluster_name}-ebs-csi"
  assume_role_policy = data.aws_iam_policy_document.ebs_assume_role.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "ebs_csi" {
  role       = aws_iam_role.ebs_csi.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

resource "aws_eks_addon" "ebs_csi" {
  cluster_name             = module.eks.cluster_name
  addon_name               = "aws-ebs-csi-driver"
  addon_version            = data.aws_eks_addon_version.current["aws-ebs-csi-driver"].version
  service_account_role_arn = aws_iam_role.ebs_csi.arn

  depends_on = [aws_iam_role_policy_attachment.ebs_csi]
}

resource "aws_eks_addon" "vpc_cni" {
  cluster_name  = module.eks.cluster_name
  addon_name    = "vpc-cni"
  addon_version = data.aws_eks_addon_version.current["vpc-cni"].version
}

resource "aws_eks_addon" "coredns" {
  cluster_name  = module.eks.cluster_name
  addon_name    = "coredns"
  addon_version = data.aws_eks_addon_version.current["coredns"].version
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name  = module.eks.cluster_name
  addon_name    = "kube-proxy"
  addon_version = data.aws_eks_addon_version.current["kube-proxy"].version
}
