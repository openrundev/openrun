variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
}

variable "name_prefix" {
  description = "Prefix used for naming AWS resources."
  type        = string
  default     = "openrun"
}

variable "tags" {
  description = "Additional tags to apply to all resources."
  type        = map(string)
  default     = {}
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "az_count" {
  description = "Number of AZs to use."
  type        = number
  default     = 2
  validation {
    condition     = var.az_count >= 1 && var.az_count <= 3
    error_message = "az_count must be between 1 and 3."
  }
}

variable "enable_vpc_endpoints" {
  description = "Whether to create VPC endpoints for ECR, STS, and S3."
  type        = bool
  default     = false
}

variable "eks_version" {
  description = "EKS Kubernetes version."
  type        = string
  default     = "1.34"
}

variable "eks_enable_cluster_creator_admin_permissions" {
  description = "Grant the Terraform execution identity admin access to the EKS cluster via access entry."
  type        = bool
  default     = true
}

variable "eks_public_access_cidrs" {
  description = "CIDR blocks allowed to access the EKS public API endpoint."
  type        = list(string)
  default     = []
  validation {
    condition     = length(var.eks_public_access_cidrs) > 0
    error_message = "eks_public_access_cidrs must include at least one CIDR so Terraform and Helm can reach the cluster endpoint."
  }
}

variable "aws_load_balancer_controller_chart_version" {
  description = "AWS Load Balancer Controller chart version (empty for latest)."
  type        = string
  default     = ""
}

variable "node_instance_types" {
  description = "EC2 instance types for the EKS managed node group."
  type        = list(string)
  default     = ["m6i.large"]
}

variable "node_desired_size" {
  description = "Desired node count for the EKS managed node group."
  type        = number
  default     = 2
}

variable "node_min_size" {
  description = "Minimum node count for the EKS managed node group."
  type        = number
  default     = 2
}

variable "node_max_size" {
  description = "Maximum node count for the EKS managed node group."
  type        = number
  default     = 4
}

variable "rds_db_name" {
  description = "Database name for OpenRun metadata."
  type        = string
  default     = "openrun"
}

variable "rds_username" {
  description = "Master username for the RDS instance."
  type        = string
  default     = "openrun"
}

variable "rds_engine_version" {
  description = "Postgres engine version for RDS (e.g., 17.6). Leave empty to use AWS default."
  type        = string
  default     = ""
}

variable "rds_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.m6g.large"
}

variable "rds_multi_az" {
  description = "Whether to enable multi-AZ for RDS."
  type        = bool
  default     = true
}

variable "rds_allocated_storage_gb" {
  description = "Allocated storage (GB) for RDS."
  type        = number
  default     = 100
}

variable "rds_max_allocated_storage_gb" {
  description = "Max storage autoscaling limit (GB) for RDS."
  type        = number
  default     = 500
}

variable "rds_backup_retention_days" {
  description = "Backup retention period in days."
  type        = number
  default     = 7
}

variable "rds_deletion_protection" {
  description = "Enable deletion protection on RDS."
  type        = bool
  default     = true
}

variable "rds_skip_final_snapshot" {
  description = "Skip final snapshot when destroying RDS."
  type        = bool
  default     = false
}

variable "rds_force_ssl" {
  description = "Force SSL connections to Postgres via parameter group."
  type        = bool
  default     = true
}

variable "ecr_repo_name" {
  description = "Name of the ECR repository that OpenRun will use."
  type        = string
  default     = "openrun-apps"
}

variable "ecr_lifecycle_keep_last_n" {
  description = "Number of images to keep in the ECR repo lifecycle policy."
  type        = number
  default     = 50
}

variable "openrun_namespace" {
  description = "Kubernetes namespace for OpenRun control plane."
  type        = string
  default     = "openrun"
}

variable "openrun_apps_namespace" {
  description = "Kubernetes namespace for OpenRun managed apps."
  type        = string
  default     = "openrun-apps"
}

variable "openrun_release_name" {
  description = "Helm release name for OpenRun."
  type        = string
  default     = "openrun"
}

variable "openrun_chart_repo" {
  description = "Helm repository URL for the OpenRun chart."
  type        = string
  default     = "https://openrundev.github.io/openrun-helm-charts/"
}

variable "openrun_chart_name" {
  description = "Helm chart name for OpenRun."
  type        = string
  default     = "openrun"
}

variable "openrun_chart_version" {
  description = "Helm chart version for OpenRun. Leave empty for the latest."
  type        = string
  default     = ""
}

variable "openrun_default_domain" {
  description = "Default domain for OpenRun apps (e.g. apps.example.com)."
  type        = string
}

variable "openrun_lets_encrypt_email" {
  description = "Email for Let's Encrypt registration."
  type        = string
}

variable "openrun_lets_encrypt_use_staging" {
  description = "Use Let's Encrypt staging environment."
  type        = bool
  default     = true
}

variable "openrun_service_account_name" {
  description = "Service account name for OpenRun (used for IRSA)."
  type        = string
  default     = "openrun"
}

variable "openrun_enable_nlb_eips" {
  description = "Allocate and attach static Elastic IPs to the OpenRun NLB for A records."
  type        = bool
  default     = true
}

variable "openrun_auth_mode" {
  description = "Authentication mode for OpenRun: none, oidc, or saml."
  type        = string
  default     = "none"
  validation {
    condition     = contains(["none", "oidc", "saml"], var.openrun_auth_mode)
    error_message = "openrun_auth_mode must be one of: none, oidc, saml."
  }
}

variable "openrun_oidc_name" {
  description = "OIDC provider name in OpenRun."
  type        = string
  default     = "oidc_main"
}

variable "openrun_oidc_client_id" {
  description = "OIDC client ID."
  type        = string
  default     = ""
  sensitive   = true
  validation {
    condition     = var.openrun_auth_mode != "oidc" || length(var.openrun_oidc_client_id) > 0
    error_message = "openrun_oidc_client_id is required when openrun_auth_mode is set to \"oidc\"."
  }
}

variable "openrun_oidc_client_secret" {
  description = "OIDC client secret."
  type        = string
  default     = ""
  sensitive   = true
  validation {
    condition     = var.openrun_auth_mode != "oidc" || length(var.openrun_oidc_client_secret) > 0
    error_message = "openrun_oidc_client_secret is required when openrun_auth_mode is set to \"oidc\"."
  }
}

variable "openrun_oidc_discovery_url" {
  description = "OIDC discovery URL."
  type        = string
  default     = ""
  validation {
    condition     = var.openrun_auth_mode != "oidc" || length(var.openrun_oidc_discovery_url) > 0
    error_message = "openrun_oidc_discovery_url is required when openrun_auth_mode is set to \"oidc\"."
  }
}

variable "openrun_oidc_scopes" {
  description = "OIDC scopes."
  type        = list(string)
  default     = ["openid", "profile", "email", "groups"]
}

variable "openrun_saml_name" {
  description = "SAML provider name in OpenRun."
  type        = string
  default     = "saml_main"
}

variable "openrun_saml_metadata_url" {
  description = "SAML metadata URL."
  type        = string
  default     = ""
  validation {
    condition     = var.openrun_auth_mode != "saml" || length(var.openrun_saml_metadata_url) > 0
    error_message = "openrun_saml_metadata_url is required when openrun_auth_mode is set to \"saml\"."
  }
}

variable "openrun_saml_groups_attr" {
  description = "SAML groups attribute name."
  type        = string
  default     = "groups"
}
