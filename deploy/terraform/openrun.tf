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
      type        = "LoadBalancer"
      annotations = local.openrun_service_annotations
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
        type      = "aws"
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

  lifecycle {
    ignore_changes = [metadata[0].labels, metadata[0].annotations]
  }

  # Ensure AWS LB controller stays until namespace cleanup is complete.
  depends_on = [helm_release.lb_controller]
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

data "kubernetes_service_v1" "openrun" {
  metadata {
    name      = var.openrun_release_name
    namespace = var.openrun_namespace
  }

  depends_on = [helm_release.openrun]
}

output "openrun_load_balancer_hostname" {
  description = "Hostname of the OpenRun service load balancer."
  value       = try(data.kubernetes_service_v1.openrun.status[0].load_balancer[0].ingress[0].hostname, "")
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
    root_cname     = "${var.openrun_default_domain} -> ${try(data.kubernetes_service_v1.openrun.status[0].load_balancer[0].ingress[0].hostname, "")}"
    wildcard_cname = "*.${var.openrun_default_domain} -> ${try(data.kubernetes_service_v1.openrun.status[0].load_balancer[0].ingress[0].hostname, "")}"
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
