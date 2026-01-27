resource "random_password" "openrun_admin" {
  length  = 24
  special = true
}

resource "aws_eip" "openrun_nlb" {
  count  = var.openrun_enable_nlb_eips ? length(module.network.public_subnets) : 0
  domain = "vpc"

  tags = local.tags
}

locals {
  openrun_db_creds     = jsondecode(aws_secretsmanager_secret_version.rds.secret_string)
  openrun_auth_enabled = var.openrun_auth_mode != "none"
  openrun_callback_url = "https://${var.openrun_default_domain}"
  openrun_eip_ids      = var.openrun_enable_nlb_eips ? [for eip in aws_eip.openrun_nlb : eip.allocation_id] : []

  openrun_service_annotations = merge(
    {
      "service.beta.kubernetes.io/aws-load-balancer-scheme"          = "internet-facing"
      "service.beta.kubernetes.io/aws-load-balancer-nlb-target-type" = "ip"
      "service.beta.kubernetes.io/aws-load-balancer-type"            = "external"
      "service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled" = "true"
      "service.beta.kubernetes.io/aws-load-balancer-subnets"         = join(",", module.network.public_subnets)
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
    delete = "30m"
  }

  # Ensure AWS LB controller stays until namespace cleanup is complete.
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
    delete = "30m"
  }

  lifecycle {
    ignore_changes = [metadata[0].labels, metadata[0].annotations]
  }

  # Ensure AWS LB controller stays until namespace cleanup is complete.
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

resource "null_resource" "openrun_lb_cleanup_wait" {
  triggers = {
    name      = "${var.openrun_release_name}-external"
    namespace = var.openrun_namespace
    eip_ids   = join(",", local.openrun_eip_ids)
    region    = var.aws_region
  }

  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      set -euo pipefail
      name="${lookup(self.triggers, "name", "")}"
      namespace="${lookup(self.triggers, "namespace", "")}"
      eip_ids="${lookup(self.triggers, "eip_ids", "")}"
      region="${lookup(self.triggers, "region", "")}"
      if [ -n "$name" ] && [ -n "$namespace" ] && kubectl get svc/$name -n $namespace >/dev/null 2>&1; then
        kubectl wait --for=delete svc/$name -n $namespace --timeout=15m
      fi
      if [ -n "$eip_ids" ] && [ -n "$region" ]; then
        end=$((SECONDS+900))
        while [ $SECONDS -lt $end ]; do
          assoc=$(aws ec2 describe-addresses --region $region --allocation-ids $eip_ids --query 'Addresses[].AssociationId' --output text | tr -s ' ' '\n' | grep -v -E '^(None)?$' || true)
          if [ -z "$assoc" ]; then
            exit 0
          fi
          sleep 10
        done
        echo "Timed out waiting for NLB EIPs to disassociate: $eip_ids" >&2
        exit 1
      fi
    EOT
  }

  # Ensure the LB controller is still present while we wait on service finalizers.
  depends_on = [helm_release.lb_controller]
}

resource "kubernetes_service_v1" "openrun_external" {
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

  depends_on = [helm_release.openrun, null_resource.openrun_lb_cleanup_wait]
}

data "kubernetes_service_v1" "openrun" {
  metadata {
    name      = var.openrun_release_name
    namespace = var.openrun_namespace
  }

  depends_on = [helm_release.openrun]
}

data "kubernetes_service_v1" "openrun_external" {
  metadata {
    name      = kubernetes_service_v1.openrun_external.metadata[0].name
    namespace = var.openrun_namespace
  }

  depends_on = [kubernetes_service_v1.openrun_external]
}

output "openrun_load_balancer_hostname" {
  description = "Hostname of the OpenRun service load balancer."
  value       = try(data.kubernetes_service_v1.openrun_external.status[0].load_balancer[0].ingress[0].hostname, "")
}

output "openrun_load_balancer_ips" {
  description = "Static Elastic IPs attached to the OpenRun NLB (use for DNS A records)."
  value       = [for eip in aws_eip.openrun_nlb : eip.public_ip]
}

output "openrun_dns_records" {
  description = "DNS records to create for OpenRun."
  value = {
    root_a         = "${var.openrun_default_domain} -> ${join(", ", [for eip in aws_eip.openrun_nlb : eip.public_ip])}"
    wildcard_a     = "*.${var.openrun_default_domain} -> ${join(", ", [for eip in aws_eip.openrun_nlb : eip.public_ip])}"
    root_cname     = "${var.openrun_default_domain} -> ${try(data.kubernetes_service_v1.openrun_external.status[0].load_balancer[0].ingress[0].hostname, "")}"
    wildcard_cname = "*.${var.openrun_default_domain} -> ${try(data.kubernetes_service_v1.openrun_external.status[0].load_balancer[0].ingress[0].hostname, "")}"
  }
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
