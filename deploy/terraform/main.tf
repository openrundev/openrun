module "network" {
  source = "./modules/network"

  name_prefix          = var.name_prefix
  vpc_cidr             = var.vpc_cidr
  az_count             = var.az_count
  cluster_name         = local.cluster_name
  enable_vpc_endpoints = var.enable_vpc_endpoints
  tags                 = local.tags
}

module "eks" {
  source = "./modules/eks"

  cluster_name                             = local.cluster_name
  eks_version                              = var.eks_version
  vpc_id                                   = module.network.vpc_id
  private_subnet_ids                       = module.network.private_subnet_ids
  enable_cluster_creator_admin_permissions = var.eks_enable_cluster_creator_admin_permissions
  eks_public_access_cidrs                  = var.eks_public_access_cidrs
  node_instance_types                      = var.node_instance_types
  node_desired_size                        = var.node_desired_size
  node_min_size                            = var.node_min_size
  node_max_size                            = var.node_max_size
  tags                                     = local.tags

  depends_on = [module.network]
}

module "ecr" {
  source = "./modules/ecr"

  name_prefix               = var.name_prefix
  ecr_repo_name             = var.ecr_repo_name
  ecr_lifecycle_keep_last_n = var.ecr_lifecycle_keep_last_n
  tags                      = local.tags
}

module "rds" {
  source = "./modules/rds"

  name_prefix                = var.name_prefix
  vpc_id                     = module.network.vpc_id
  private_subnet_ids         = module.network.private_subnet_ids
  eks_node_security_group_id = module.eks.node_security_group_id

  rds_db_name                  = var.rds_db_name
  rds_username                 = var.rds_username
  rds_engine_version           = var.rds_engine_version
  rds_instance_class           = var.rds_instance_class
  rds_multi_az                 = var.rds_multi_az
  rds_allocated_storage_gb     = var.rds_allocated_storage_gb
  rds_max_allocated_storage_gb = var.rds_max_allocated_storage_gb
  rds_backup_retention_days    = var.rds_backup_retention_days
  rds_deletion_protection      = var.rds_deletion_protection
  rds_skip_final_snapshot      = var.rds_skip_final_snapshot
  rds_force_ssl                = var.rds_force_ssl
  tags                         = local.tags

  depends_on = [module.network, module.eks]
}

module "irsa" {
  source = "./modules/irsa"

  name_prefix          = var.name_prefix
  oidc_provider_arn    = module.eks.oidc_provider_arn
  oidc_provider_url    = module.eks.oidc_provider_url
  namespace            = var.openrun_namespace
  service_account_name = var.openrun_service_account_name
  ecr_repo_arn         = module.ecr.repo_arn
  tags                 = local.tags

  depends_on = [module.eks, module.ecr]
}

module "addons" {
  source = "./modules/addons"

  cluster_name      = module.eks.cluster_name
  aws_region        = var.aws_region
  vpc_id            = module.network.vpc_id
  oidc_provider_arn = module.eks.oidc_provider_arn
  oidc_provider_url = module.eks.oidc_provider_url
  tags              = local.tags

  depends_on = [module.eks]

  providers = {
    aws        = aws
    kubernetes = kubernetes
    helm       = helm
  }
}

module "openrun" {
  source = "./modules/openrun"

  aws_region               = var.aws_region
  namespace                = var.openrun_namespace
  apps_namespace           = var.openrun_apps_namespace
  release_name             = var.openrun_release_name
  chart_repo               = var.openrun_chart_repo
  chart_name               = var.openrun_chart_name
  chart_version            = var.openrun_chart_version
  service_account_name     = var.openrun_service_account_name
  service_account_role_arn = module.irsa.role_arn
  public_subnet_ids        = module.network.public_subnet_ids
  enable_nlb_eips          = var.openrun_enable_nlb_eips

  openrun_default_domain           = var.openrun_default_domain
  openrun_lets_encrypt_email       = var.openrun_lets_encrypt_email
  openrun_lets_encrypt_use_staging = var.openrun_lets_encrypt_use_staging

  rds_endpoint   = module.rds.db_endpoint
  rds_port       = module.rds.db_port
  rds_db_name    = module.rds.db_name
  rds_secret_arn = module.rds.secret_arn
  rds_force_ssl  = var.rds_force_ssl

  ecr_repo_name    = module.ecr.repo_name
  ecr_registry_url = module.ecr.registry_url

  auth_mode          = var.openrun_auth_mode
  oidc_name          = var.openrun_oidc_name
  oidc_client_id     = var.openrun_oidc_client_id
  oidc_client_secret = var.openrun_oidc_client_secret
  oidc_discovery_url = var.openrun_oidc_discovery_url
  oidc_scopes        = var.openrun_oidc_scopes
  saml_name          = var.openrun_saml_name
  saml_metadata_url  = var.openrun_saml_metadata_url
  saml_groups_attr   = var.openrun_saml_groups_attr

  tags = local.tags

  depends_on = [module.addons, module.rds, module.ecr, module.irsa]

  providers = {
    aws        = aws
    kubernetes = kubernetes
    helm       = helm
  }
}
