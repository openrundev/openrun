locals {
  vpc_azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  vpc_public_subnets = [
    for index in range(var.az_count) : cidrsubnet(var.vpc_cidr, 8, index)
  ]

  vpc_private_subnets = [
    for index in range(var.az_count) : cidrsubnet(var.vpc_cidr, 8, index + var.az_count)
  ]

  vpc_interface_endpoints = {
    "ecr.api" = "com.amazonaws.${var.aws_region}.ecr.api"
    "ecr.dkr" = "com.amazonaws.${var.aws_region}.ecr.dkr"
    "sts"     = "com.amazonaws.${var.aws_region}.sts"
  }
}

module "network" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${var.name_prefix}-vpc"
  cidr = var.vpc_cidr

  azs             = local.vpc_azs
  public_subnets  = local.vpc_public_subnets
  private_subnets = local.vpc_private_subnets

  enable_nat_gateway     = true
  one_nat_gateway_per_az = true
  single_nat_gateway     = false

  enable_dns_hostnames = true
  enable_dns_support   = true

  public_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                      = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = "1"
  }

  tags = local.tags
}

resource "aws_security_group" "vpc_endpoints" {
  count = var.enable_vpc_endpoints ? 1 : 0

  name        = "${var.name_prefix}-vpce"
  description = "Security group for VPC interface endpoints."
  vpc_id      = module.network.vpc_id

  ingress {
    description = "VPC endpoint HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

resource "aws_vpc_endpoint" "interface" {
  for_each = var.enable_vpc_endpoints ? local.vpc_interface_endpoints : {}

  vpc_id              = module.network.vpc_id
  service_name        = each.value
  vpc_endpoint_type   = "Interface"
  subnet_ids          = module.network.private_subnets
  security_group_ids  = [aws_security_group.vpc_endpoints[0].id]
  private_dns_enabled = true

  tags = local.tags
}
