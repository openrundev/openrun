resource "random_password" "openrun_admin" {
  length  = 24
  special = true
}

resource "aws_eip" "openrun_nlb" {
  count  = var.openrun_enable_nlb && var.openrun_enable_nlb_eips ? length(module.network.public_subnets) : 0
  domain = "vpc"

  tags = local.tags
}

locals {
  openrun_db_creds     = jsondecode(aws_secretsmanager_secret_version.rds.secret_string)
  openrun_auth_enabled = var.openrun_auth_mode != "none"
  openrun_callback_url = "https://${var.openrun_default_domain}"
  openrun_eip_ids      = var.openrun_enable_nlb && var.openrun_enable_nlb_eips ? [for eip in aws_eip.openrun_nlb : eip.allocation_id] : []

  openrun_service_annotations = merge(
    {
      "service.beta.kubernetes.io/aws-load-balancer-scheme"                            = "internet-facing"
      "service.beta.kubernetes.io/aws-load-balancer-nlb-target-type"                   = "ip"
      "service.beta.kubernetes.io/aws-load-balancer-type"                              = "external"
      "service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled" = "true"
      "service.beta.kubernetes.io/aws-load-balancer-subnets"                           = join(",", module.network.public_subnets)
      "service.beta.kubernetes.io/aws-load-balancer-healthcheck-protocol"              = "HTTPS"
      "service.beta.kubernetes.io/aws-load-balancer-healthcheck-path"                  = "/_openrun/health"
      "service.beta.kubernetes.io/aws-load-balancer-healthcheck-port"                  = "443"
    },
    var.openrun_enable_nlb_eips ? {
      "service.beta.kubernetes.io/aws-load-balancer-eip-allocations" = join(",", local.openrun_eip_ids)
    } : {}
  )

  openrun_oidc_values = var.openrun_auth_mode == "oidc" ? {
    (var.openrun_oidc_name) = {
      key          = var.openrun_oidc_client_id
      secret       = var.openrun_oidc_client_secret
      discoveryUrl = var.openrun_oidc_discovery_url
      scopes       = var.openrun_oidc_scopes
    }
  } : {}

  openrun_saml_values = var.openrun_auth_mode == "saml" ? {
    (var.openrun_saml_name) = {
      metadataUrl = var.openrun_saml_metadata_url
      groupsAttr  = var.openrun_saml_groups_attr
    }
  } : {}

  openrun_registry_url = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com"

  openrun_helm_values = {
    fullnameOverride = var.openrun_release_name
    serviceAccount = {
      create = false
      name   = var.openrun_service_account_name
    }
    service = {
      type = "ClusterIP"
    }
    postgres = {
      enabled = false
    }
    registry = {
      enabled = false
    }
    externalDatabase = {
      enabled            = true
      host               = aws_db_instance.rds.address
      port               = aws_db_instance.rds.port
      database           = var.rds_db_name
      existingSecretName = "openrun-postgres"
      usernameKey        = "username"
      passwordKey        = "password"
      sslMode            = var.rds_force_ssl ? "require" : "disable"
    }
    config = {
      system = {
        defaultDomain = var.openrun_default_domain
      }
      kubernetes = {
        namespace = var.openrun_namespace
      }
      http = {
        redirectToHttps = false
      }
      https = {
        enabled      = true
        serviceEmail = var.openrun_lets_encrypt_email
        useStaging   = var.openrun_lets_encrypt_use_staging
      }
      security = {
        adminPassword = random_password.openrun_admin.result
        callbackUrl   = local.openrun_auth_enabled ? local.openrun_callback_url : ""
      }
      registry = {
        url       = local.openrun_registry_url
        project   = var.ecr_repo_name
        insecure  = false
        type      = "ecr"
        awsRegion = var.aws_region
      }
      metadata = {
        sslMode = var.rds_force_ssl ? "require" : "disable"
      }
    }
    auth = local.openrun_oidc_values
    saml = local.openrun_saml_values
  }
}

resource "kubernetes_namespace_v1" "openrun" {
  metadata {
    name = var.openrun_namespace
  }

  timeouts {
    delete = "5m"
  }

  # Fast namespace cleanup for destroy - cluster is being deleted so we just need to:
  # 1. Clear all finalizers immediately (no waiting for controllers)
  # 2. Force-remove namespace finalizer so Terraform proceeds
  provisioner "local-exec" {
    when        = destroy
    interpreter = ["bash", "-c"]
    command     = <<-EOT
      set -euo pipefail

      ns="${self.metadata[0].name}"

      # Build AWS profile args
      profile="$${AWS_PROFILE:-$${AWS_DEFAULT_PROFILE:-}}"
      if [ -z "$${profile}" ] && [ -f terraform.tfvars ]; then
        profile=$(awk -F'"' '/^[[:space:]]*aws_profile[[:space:]]*=/ {print $2; exit}' terraform.tfvars 2>/dev/null || true)
      fi
      profile_args=($${profile:+--profile "$${profile}"})

      # Build region/cluster from env or tfvars
      region="$${AWS_REGION:-$${AWS_DEFAULT_REGION:-}}"
      if [ -z "$${region}" ] && [ -f terraform.tfvars ]; then
        region=$(awk -F'"' '/^[[:space:]]*aws_region[[:space:]]*=/ {print $2; exit}' terraform.tfvars 2>/dev/null || true)
      fi
      cluster="$${EKS_CLUSTER_NAME:-}"
      if [ -z "$${cluster}" ] && [ -f terraform.tfvars ]; then
        name_prefix=$(awk -F'"' '/^[[:space:]]*name_prefix[[:space:]]*=/ {print $2; exit}' terraform.tfvars 2>/dev/null || true)
        [ -n "$${name_prefix}" ] && cluster="$${name_prefix}-eks"
      fi

      if [ -z "$${region}" ] || [ -z "$${cluster}" ]; then
        echo "Cannot determine EKS region/cluster. Set AWS_REGION and EKS_CLUSTER_NAME or use terraform.tfvars." >&2
        exit 1
      fi

      # Get kubeconfig
      KCFG="$(mktemp)"; trap 'rm -f "$KCFG"' EXIT
      if ! aws eks update-kubeconfig --region "$${region}" --name "$${cluster}" "$${profile_args[@]}" --kubeconfig "$KCFG" >/dev/null 2>&1; then
        echo "Failed to get kubeconfig. Run: aws sso login" >&2
        exit 1
      fi
      K="kubectl --kubeconfig $KCFG"

      # Skip if namespace already gone
      $K get ns "$${ns}" >/dev/null 2>&1 || exit 0

      echo "Fast cleanup of namespace $${ns} (cluster being destroyed)..."

      # Clear finalizers from all resources in parallel (don't wait for anything)
      for type in targetgroupbindings.elbv2.k8s.aws services pods deployments.apps replicasets.apps statefulsets.apps persistentvolumeclaims secrets configmaps serviceaccounts; do
        for r in $($K get "$${type}" -n "$${ns}" -o name 2>/dev/null || true); do
          $K patch "$${r}" -n "$${ns}" -p '{"metadata":{"finalizers":[]}}' --type=merge >/dev/null 2>&1 &
        done
      done
      wait

      # Delete all resources without waiting
      $K delete all -n "$${ns}" --all --force --grace-period=0 --wait=false >/dev/null 2>&1 || true

      # Force-remove namespace finalizer so Terraform sees it as deleted
      $K get ns "$${ns}" -o json 2>/dev/null | \
        jq '.spec.finalizers = []' | \
        $K replace --raw "/api/v1/namespaces/$${ns}/finalize" -f - >/dev/null 2>&1 || true

      echo "Namespace $${ns} cleanup complete."
    EOT
  }

  depends_on = [helm_release.lb_controller]
}

resource "kubernetes_namespace_v1" "openrun_apps" {
  metadata {
    name = var.openrun_apps_namespace
    labels = {
      "app.kubernetes.io/managed-by" = "Helm"
      "app.kubernetes.io/component"  = "apps"
    }
    annotations = {
      "meta.helm.sh/release-name"      = var.openrun_release_name
      "meta.helm.sh/release-namespace" = var.openrun_namespace
      "openrun.io/description"         = "Namespace for OpenRun managed applications"
    }
  }

  timeouts {
    delete = "5m"
  }

  lifecycle {
    ignore_changes = [metadata[0].labels, metadata[0].annotations]
  }

  # Fast namespace cleanup for destroy - same as openrun namespace
  provisioner "local-exec" {
    when        = destroy
    interpreter = ["bash", "-c"]
    command     = <<-EOT
      set -euo pipefail

      ns="${self.metadata[0].name}"

      profile="$${AWS_PROFILE:-$${AWS_DEFAULT_PROFILE:-}}"
      if [ -z "$${profile}" ] && [ -f terraform.tfvars ]; then
        profile=$(awk -F'"' '/^[[:space:]]*aws_profile[[:space:]]*=/ {print $2; exit}' terraform.tfvars 2>/dev/null || true)
      fi
      profile_args=($${profile:+--profile "$${profile}"})

      region="$${AWS_REGION:-$${AWS_DEFAULT_REGION:-}}"
      if [ -z "$${region}" ] && [ -f terraform.tfvars ]; then
        region=$(awk -F'"' '/^[[:space:]]*aws_region[[:space:]]*=/ {print $2; exit}' terraform.tfvars 2>/dev/null || true)
      fi
      cluster="$${EKS_CLUSTER_NAME:-}"
      if [ -z "$${cluster}" ] && [ -f terraform.tfvars ]; then
        name_prefix=$(awk -F'"' '/^[[:space:]]*name_prefix[[:space:]]*=/ {print $2; exit}' terraform.tfvars 2>/dev/null || true)
        [ -n "$${name_prefix}" ] && cluster="$${name_prefix}-eks"
      fi

      if [ -z "$${region}" ] || [ -z "$${cluster}" ]; then
        echo "Cannot determine EKS region/cluster. Set AWS_REGION and EKS_CLUSTER_NAME or use terraform.tfvars." >&2
        exit 1
      fi

      KCFG="$(mktemp)"; trap 'rm -f "$KCFG"' EXIT
      if ! aws eks update-kubeconfig --region "$${region}" --name "$${cluster}" "$${profile_args[@]}" --kubeconfig "$KCFG" >/dev/null 2>&1; then
        echo "Failed to get kubeconfig. Run: aws sso login" >&2
        exit 1
      fi
      K="kubectl --kubeconfig $KCFG"

      $K get ns "$${ns}" >/dev/null 2>&1 || exit 0

      echo "Fast cleanup of namespace $${ns} (cluster being destroyed)..."

      for type in targetgroupbindings.elbv2.k8s.aws services pods deployments.apps replicasets.apps statefulsets.apps persistentvolumeclaims secrets configmaps serviceaccounts; do
        for r in $($K get "$${type}" -n "$${ns}" -o name 2>/dev/null || true); do
          $K patch "$${r}" -n "$${ns}" -p '{"metadata":{"finalizers":[]}}' --type=merge >/dev/null 2>&1 &
        done
      done
      wait

      $K delete all -n "$${ns}" --all --force --grace-period=0 --wait=false >/dev/null 2>&1 || true

      $K get ns "$${ns}" -o json 2>/dev/null | \
        jq '.spec.finalizers = []' | \
        $K replace --raw "/api/v1/namespaces/$${ns}/finalize" -f - >/dev/null 2>&1 || true

      echo "Namespace $${ns} cleanup complete."
    EOT
  }

  depends_on = [helm_release.lb_controller]
}

resource "null_resource" "openrun_default_sa_annotation" {
  triggers = {
    namespace = var.openrun_namespace
    role_arn  = aws_iam_role.openrun_irsa.arn
    cluster   = module.eks.cluster_name
    region    = var.aws_region
    profile   = local.aws_cli_profile_arg
  }

  provisioner "local-exec" {
    command = <<-EOT
      set -euo pipefail
      KCFG="$(mktemp)"
      trap 'rm -f "$KCFG"' EXIT
      aws eks update-kubeconfig --region ${self.triggers.region} --name ${self.triggers.cluster} ${self.triggers.profile} --kubeconfig "$KCFG" >/dev/null
      kubectl --kubeconfig "$KCFG" annotate sa default -n ${self.triggers.namespace} eks.amazonaws.com/role-arn=${self.triggers.role_arn} --overwrite
    EOT
  }

  depends_on = [kubernetes_namespace_v1.openrun]
}

resource "kubernetes_service_account_v1" "openrun" {
  metadata {
    name      = var.openrun_service_account_name
    namespace = var.openrun_namespace
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.openrun_irsa.arn
    }
  }

  depends_on = [kubernetes_namespace_v1.openrun, kubernetes_namespace_v1.openrun_apps]
}

resource "kubernetes_role_v1" "openrun_apps_scale" {
  metadata {
    name      = "${var.openrun_release_name}-apps-scale"
    namespace = var.openrun_apps_namespace
  }

  rule {
    api_groups = ["apps"]
    resources  = ["deployments/scale"]
    verbs      = ["get", "patch", "update"]
  }

  depends_on = [kubernetes_namespace_v1.openrun_apps]
}

resource "kubernetes_role_binding_v1" "openrun_apps_scale" {
  metadata {
    name      = "${var.openrun_release_name}-apps-scale"
    namespace = var.openrun_apps_namespace
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role_v1.openrun_apps_scale.metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = var.openrun_service_account_name
    namespace = var.openrun_namespace
  }

  depends_on = [kubernetes_service_account_v1.openrun, kubernetes_role_v1.openrun_apps_scale]
}

resource "kubernetes_secret_v1" "openrun_postgres" {
  metadata {
    name      = "openrun-postgres"
    namespace = var.openrun_namespace
  }

  data = {
    username = local.openrun_db_creds.username
    password = local.openrun_db_creds.password
  }

  type = "Opaque"

  depends_on = [kubernetes_namespace_v1.openrun]
}

resource "helm_release" "openrun" {
  name       = var.openrun_release_name
  repository = var.openrun_chart_repo
  chart      = var.openrun_chart_name
  namespace  = var.openrun_namespace

  version = var.openrun_chart_version != "" ? var.openrun_chart_version : null
  timeout = 1800

  values = [yamlencode(local.openrun_helm_values)]

  # Keep the AWS LB controller alive until this release is fully removed to avoid finalizer hangs.
  depends_on = [helm_release.lb_controller, kubernetes_service_account_v1.openrun, kubernetes_secret_v1.openrun_postgres]
}

resource "kubernetes_service_v1" "openrun_external" {
  count = var.openrun_enable_nlb ? 1 : 0

  metadata {
    name        = "${var.openrun_release_name}-external"
    namespace   = var.openrun_namespace
    annotations = local.openrun_service_annotations
    labels = {
      "app.kubernetes.io/name"     = var.openrun_chart_name
      "app.kubernetes.io/instance" = var.openrun_release_name
    }
  }

  spec {
    type = "LoadBalancer"
    selector = {
      "app.kubernetes.io/name"     = var.openrun_chart_name
      "app.kubernetes.io/instance" = var.openrun_release_name
    }

    port {
      name        = "http"
      port        = 80
      target_port = "http"
      protocol    = "TCP"
    }

    port {
      name        = "https"
      port        = 443
      target_port = "https"
      protocol    = "TCP"
    }
  }

  depends_on = [helm_release.openrun]

  # Delete NLB via AWS API and clear finalizers - cluster is being destroyed
  provisioner "local-exec" {
    when        = destroy
    interpreter = ["bash", "-c"]
    command     = <<-EOT
      set -euo pipefail

      name="${self.metadata[0].name}"
      namespace="${self.metadata[0].namespace}"
      eip_ids="${lookup(self.metadata[0].annotations, "service.beta.kubernetes.io/aws-load-balancer-eip-allocations", "")}"

      # Build AWS profile/region args
      profile="$${AWS_PROFILE:-$${AWS_DEFAULT_PROFILE:-}}"
      if [ -z "$${profile}" ] && [ -f terraform.tfvars ]; then
        profile=$(awk -F'"' '/^[[:space:]]*aws_profile[[:space:]]*=/ {print $2; exit}' terraform.tfvars 2>/dev/null || true)
      fi
      profile_args=($${profile:+--profile "$${profile}"})

      region="$${AWS_REGION:-$${AWS_DEFAULT_REGION:-}}"
      if [ -z "$${region}" ] && [ -f terraform.tfvars ]; then
        region=$(awk -F'"' '/^[[:space:]]*aws_region[[:space:]]*=/ {print $2; exit}' terraform.tfvars 2>/dev/null || true)
      fi
      cluster=""
      if [ -f terraform.tfvars ]; then
        name_prefix=$(awk -F'"' '/^[[:space:]]*name_prefix[[:space:]]*=/ {print $2; exit}' terraform.tfvars 2>/dev/null || true)
        [ -n "$${name_prefix}" ] && cluster="$${name_prefix}-eks"
      fi

      # Get kubeconfig (optional - we still try to clear finalizers if possible)
      KCFG="$(mktemp)"; trap 'rm -f "$KCFG"' EXIT
      K=""
      if [ -n "$${region}" ] && [ -n "$${cluster}" ]; then
        if aws eks update-kubeconfig --region "$${region}" --name "$${cluster}" "$${profile_args[@]}" --kubeconfig "$KCFG" >/dev/null 2>&1; then
          K="kubectl --kubeconfig $KCFG"
        fi
      fi

      # Get LB hostname from service if kubectl works
      lb_host=""
      if [ -n "$K" ]; then
        lb_host=$($K get "svc/$${name}" -n "$${namespace}" -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || true)
      fi

      # Extract region from LB hostname if not set
      if [ -z "$${region}" ] && [ -n "$${lb_host}" ] && [[ "$${lb_host}" == *".elb."* ]]; then
        region="$${lb_host#*.elb.}"; region="$${region%%.*}"
      fi

      # Delete the NLB via AWS API (this is an AWS resource that must be cleaned up)
      if [ -n "$${lb_host}" ] && [ -n "$${region}" ]; then
        echo "Deleting NLB for service $${namespace}/$${name}..."
        arn=$(aws elbv2 describe-load-balancers --region "$${region}" "$${profile_args[@]}" \
          --query "LoadBalancers[?DNSName=='$${lb_host}'].LoadBalancerArn | [0]" --output text 2>/dev/null || true)

        if [ -n "$${arn}" ] && [ "$${arn}" != "None" ]; then
          aws elbv2 delete-load-balancer --region "$${region}" --load-balancer-arn "$${arn}" "$${profile_args[@]}" >/dev/null 2>&1 || true
          # Wait up to 2 minutes for NLB deletion (reduced from 15)
          timeout 120 aws elbv2 wait load-balancers-deleted --region "$${region}" --load-balancer-arns "$${arn}" "$${profile_args[@]}" >/dev/null 2>&1 || true
        fi
      fi

      # Clear service finalizers and delete (don't wait long)
      if [ -n "$K" ]; then
        $K patch "svc/$${name}" -n "$${namespace}" -p '{"metadata":{"finalizers":[]}}' --type=merge >/dev/null 2>&1 || true
        $K delete "svc/$${name}" -n "$${namespace}" --wait=false >/dev/null 2>&1 || true
      fi

      # Brief wait for EIPs to disassociate (reduced from 15 min to 2 min - Terraform will retry if needed)
      if [ -n "$${eip_ids}" ] && [ -n "$${region}" ]; then
        eip_args=$(echo "$${eip_ids}" | tr ',' ' ')
        for i in {1..12}; do
          out=$(aws ec2 describe-addresses --region "$${region}" --allocation-ids $${eip_args} --query 'Addresses[].AssociationId' --output text "$${profile_args[@]}" 2>/dev/null || true)
          [ -z "$(echo "$${out}" | tr -d 'None \n')" ] && break
          sleep 10
        done
      fi

      echo "Service cleanup complete."
    EOT
  }
}

data "kubernetes_service_v1" "openrun" {
  metadata {
    name      = var.openrun_release_name
    namespace = var.openrun_namespace
  }

  depends_on = [helm_release.openrun]
}

data "kubernetes_service_v1" "openrun_external" {
  count = var.openrun_enable_nlb ? 1 : 0

  metadata {
    name      = kubernetes_service_v1.openrun_external[0].metadata[0].name
    namespace = var.openrun_namespace
  }

  depends_on = [kubernetes_service_v1.openrun_external]
}

output "openrun_load_balancer_hostname" {
  description = "Hostname of the OpenRun service load balancer. Empty when openrun_enable_nlb is false."
  value       = var.openrun_enable_nlb ? try(data.kubernetes_service_v1.openrun_external[0].status[0].load_balancer[0].ingress[0].hostname, "") : ""
}

output "openrun_load_balancer_ips" {
  description = "Static Elastic IPs attached to the OpenRun NLB (use for DNS A records). Empty when openrun_enable_nlb is false."
  value       = [for eip in aws_eip.openrun_nlb : eip.public_ip]
}

output "openrun_dns_records" {
  description = "DNS records to create for OpenRun. Empty when openrun_enable_nlb is false."
  value = var.openrun_enable_nlb ? {
    root_a         = "${var.openrun_default_domain} -> ${join(", ", [for eip in aws_eip.openrun_nlb : eip.public_ip])}"
    wildcard_a     = "*.${var.openrun_default_domain} -> ${join(", ", [for eip in aws_eip.openrun_nlb : eip.public_ip])}"
    root_cname     = "${var.openrun_default_domain} -> ${try(data.kubernetes_service_v1.openrun_external[0].status[0].load_balancer[0].ingress[0].hostname, "")}"
    wildcard_cname = "*.${var.openrun_default_domain} -> ${try(data.kubernetes_service_v1.openrun_external[0].status[0].load_balancer[0].ingress[0].hostname, "")}"
  } : {}
}

output "openrun_oidc_callback_url" {
  description = "OIDC callback URL for OpenRun."
  value       = "https://${var.openrun_default_domain}/_openrun/auth/${var.openrun_oidc_name}/callback"
}

output "openrun_saml_acs_url" {
  description = "SAML ACS endpoint for OpenRun."
  value       = "https://${var.openrun_default_domain}/_openrun/sso/${var.openrun_saml_name}/acs"
}

output "openrun_saml_metadata_url" {
  description = "SAML metadata endpoint for OpenRun."
  value       = "https://${var.openrun_default_domain}/_openrun/sso/${var.openrun_saml_name}/metadata"
}

output "openrun_admin_password" {
  description = "OpenRun admin password generated by Terraform."
  value       = random_password.openrun_admin.result
  sensitive   = true
}
