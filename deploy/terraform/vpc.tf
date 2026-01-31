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

resource "null_resource" "vpc_cleanup" {
  triggers = {
    vpc_id  = module.network.vpc_id
    region  = var.aws_region
    profile = var.aws_profile
  }

  # Comprehensive VPC cleanup: delete orphaned ENIs, NLBs, target groups, and security groups
  provisioner "local-exec" {
    when        = destroy
    interpreter = ["bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      vpc_id="${self.triggers.vpc_id}"
      region="${self.triggers.region}"
      profile="${self.triggers.profile}"

      profile_args=()
      if [ -n "$${profile}" ]; then
        profile_args=(--profile "$${profile}")
      fi

      echo "Cleaning up VPC $vpc_id..."

      if ! aws sts get-caller-identity --region "$${region}" "$${profile_args[@]}" >/dev/null 2>&1; then
        if [ -n "$${profile}" ]; then
          echo "AWS CLI credentials not available for profile '$${profile}'. Run: aws sso login --profile '$${profile}' (if using SSO) then re-run terraform destroy." >&2
        else
          echo "AWS CLI credentials not available. Export AWS_PROFILE (and run aws sso login if needed) then re-run terraform destroy." >&2
        fi
        exit 1
      fi

      # 0. Delete VPC endpoints (interface endpoints create ENIs that block deletion)
      echo "Deleting VPC endpoints..."
      vpce_ids=$(aws ec2 describe-vpc-endpoints --region "$${region}" "$${profile_args[@]}" \
        --filters Name=vpc-id,Values="$${vpc_id}" --query 'VpcEndpoints[].VpcEndpointId' --output text 2>/dev/null || true)
      for vpce in $vpce_ids; do
        [ -z "$${vpce}" ] && continue
        aws ec2 delete-vpc-endpoints --region "$${region}" --vpc-endpoint-ids "$${vpce}" "$${profile_args[@]}" >/dev/null 2>&1 || true
      done

      # 1. Delete any orphaned NLBs in this VPC (left behind by LB controller)
      echo "Checking for orphaned load balancers..."
      lb_arns=$(aws elbv2 describe-load-balancers --region "$region" "$${profile_args[@]}" \
        --query "LoadBalancers[?VpcId=='$vpc_id'].LoadBalancerArn" --output text 2>/dev/null || true)
      for arn in $lb_arns; do
        [ -z "$arn" ] && continue
        echo "Deleting orphaned LB: $arn"
        aws elbv2 delete-load-balancer --region "$region" --load-balancer-arn "$arn" "$${profile_args[@]}" 2>/dev/null || true
      done
      # Wait for LB deletion
      if [ -n "$lb_arns" ]; then
        for arn in $lb_arns; do
          [ -z "$arn" ] && continue
          end=$((SECONDS+600))
          while [ $SECONDS -lt $end ]; do
            aws elbv2 wait load-balancers-deleted --region "$region" --load-balancer-arns "$arn" "$${profile_args[@]}" >/dev/null 2>&1 && break || true
            sleep 5
          done
        done
      fi

      # 2. Delete orphaned target groups
      echo "Checking for orphaned target groups..."
      tg_arns=$(aws elbv2 describe-target-groups --region "$region" "$${profile_args[@]}" \
        --query "TargetGroups[?VpcId=='$vpc_id'].TargetGroupArn" --output text 2>/dev/null || true)
      for arn in $tg_arns; do
        [ -z "$arn" ] && continue
        echo "Deleting orphaned target group: $arn"
        aws elbv2 delete-target-group --region "$region" --target-group-arn "$arn" "$${profile_args[@]}" 2>/dev/null || true
      done

      # 3. Delete orphaned ENIs (network interfaces) - main VPC deletion blocker
      echo "Deleting orphaned ENIs..."
      enis=$(aws ec2 describe-network-interfaces --region "$region" "$${profile_args[@]}" \
        --filters Name=vpc-id,Values="$vpc_id" \
        --query 'NetworkInterfaces[?Status!=`in-use` || Attachment.DeleteOnTermination==`false`].NetworkInterfaceId' \
        --output text 2>/dev/null || true)
      for eni in $enis; do
        [ -z "$eni" ] && continue
        # Detach if attached
        att_id=$(aws ec2 describe-network-interfaces --region "$region" "$${profile_args[@]}" \
          --network-interface-ids "$eni" --query 'NetworkInterfaces[0].Attachment.AttachmentId' --output text 2>/dev/null || true)
        if [ -n "$att_id" ] && [ "$att_id" != "None" ]; then
          aws ec2 detach-network-interface --region "$region" --attachment-id "$att_id" --force "$${profile_args[@]}" 2>/dev/null || true
          sleep 2
        fi
        aws ec2 delete-network-interface --region "$region" --network-interface-id "$eni" "$${profile_args[@]}" 2>/dev/null || true
      done

      # 4. Delete internet gateways
      echo "Deleting internet gateways..."
      igws=$(aws ec2 describe-internet-gateways --region "$region" "$${profile_args[@]}" \
        --filters Name=attachment.vpc-id,Values="$vpc_id" --query 'InternetGateways[].InternetGatewayId' --output text 2>/dev/null || true)
      for igw in $igws; do
        [ -z "$igw" ] && continue
        aws ec2 detach-internet-gateway --region "$region" --internet-gateway-id "$igw" --vpc-id "$vpc_id" "$${profile_args[@]}" 2>/dev/null || true
        aws ec2 delete-internet-gateway --region "$region" --internet-gateway-id "$igw" "$${profile_args[@]}" 2>/dev/null || true
      done

      # 5. Delete subnets
      echo "Deleting subnets..."
      subnets=$(aws ec2 describe-subnets --region "$region" "$${profile_args[@]}" \
        --filters Name=vpc-id,Values="$vpc_id" --query 'Subnets[].SubnetId' --output text 2>/dev/null || true)
      for subnet in $subnets; do
        [ -z "$subnet" ] && continue
        aws ec2 delete-subnet --region "$region" --subnet-id "$subnet" "$${profile_args[@]}" 2>/dev/null || true
      done

      # 6. Delete non-main route tables
      echo "Deleting non-main route tables..."
      route_tables=$(aws ec2 describe-route-tables --region "$region" "$${profile_args[@]}" \
        --filters Name=vpc-id,Values="$vpc_id" \
        --query 'RouteTables[?Associations[?Main==`false`]].RouteTableId' --output text 2>/dev/null || true)
      for rt in $route_tables; do
        [ -z "$rt" ] && continue
        assoc_ids=$(aws ec2 describe-route-tables --region "$region" "$${profile_args[@]}" \
          --route-table-ids "$rt" --query 'RouteTables[0].Associations[?Main==`false`].RouteTableAssociationId' --output text 2>/dev/null || true)
        for assoc in $assoc_ids; do
          [ -z "$assoc" ] && continue
          aws ec2 disassociate-route-table --region "$region" --association-id "$assoc" "$${profile_args[@]}" 2>/dev/null || true
        done
        aws ec2 delete-route-table --region "$region" --route-table-id "$rt" "$${profile_args[@]}" 2>/dev/null || true
      done

      # 7. Delete non-default network ACLs
      echo "Deleting non-default network ACLs..."
      acls=$(aws ec2 describe-network-acls --region "$region" "$${profile_args[@]}" \
        --filters Name=vpc-id,Values="$vpc_id" --query 'NetworkAcls[?IsDefault==`false`].NetworkAclId' --output text 2>/dev/null || true)
      for acl in $acls; do
        [ -z "$acl" ] && continue
        aws ec2 delete-network-acl --region "$region" --network-acl-id "$acl" "$${profile_args[@]}" 2>/dev/null || true
      done

      # 8. Delete non-default security groups (retry loop - may need ENIs gone first)
      echo "Deleting security groups..."
      for attempt in 1 2 3 4 5; do
        sgs=$(aws ec2 describe-security-groups --region "$region" "$${profile_args[@]}" \
          --filters Name=vpc-id,Values="$vpc_id" \
          --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text 2>/dev/null || true)
        [ -z "$sgs" ] && break
        for sg in $sgs; do
          # Remove all ingress/egress rules first (may reference other SGs)
          aws ec2 revoke-security-group-ingress --region "$region" --group-id "$sg" \
            --ip-permissions "$(aws ec2 describe-security-groups --region "$region" --group-ids "$sg" \
            --query 'SecurityGroups[0].IpPermissions' --output json "$${profile_args[@]}" 2>/dev/null)" \
            "$${profile_args[@]}" 2>/dev/null || true
          aws ec2 revoke-security-group-egress --region "$region" --group-id "$sg" \
            --ip-permissions "$(aws ec2 describe-security-groups --region "$region" --group-ids "$sg" \
            --query 'SecurityGroups[0].IpPermissionsEgress' --output json "$${profile_args[@]}" 2>/dev/null)" \
            "$${profile_args[@]}" 2>/dev/null || true
          aws ec2 delete-security-group --region "$region" --group-id "$sg" "$${profile_args[@]}" 2>/dev/null || true
        done
        sleep 3
      done

      echo "VPC cleanup complete."
    EOT
  }

  depends_on = [module.network]
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
