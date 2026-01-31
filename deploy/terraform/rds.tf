data "aws_rds_engine_version" "postgres" {
  engine  = "postgres"
  version = var.rds_engine_version != "" ? var.rds_engine_version : null
}

resource "random_password" "rds" {
  length           = 24
  special          = true
  override_special = "_+=-!#%^*(){}[]<>:?"
}

resource "random_id" "rds_snapshot" {
  byte_length = 3
}

resource "aws_security_group" "rds" {
  name        = "${var.name_prefix}-db"
  description = "Security group for OpenRun RDS"
  vpc_id      = module.network.vpc_id

  ingress {
    description     = "Postgres from EKS nodes"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

resource "aws_db_subnet_group" "rds" {
  name       = "${var.name_prefix}-db-subnets"
  subnet_ids = module.network.private_subnets
  tags       = local.tags
}

resource "aws_db_parameter_group" "rds" {
  name_prefix = "${var.name_prefix}-pg-"
  family      = data.aws_rds_engine_version.postgres.parameter_group_family
  tags        = local.tags

  parameter {
    name         = "rds.force_ssl"
    value        = var.rds_force_ssl ? "1" : "0"
    apply_method = "immediate"
  }
}

resource "aws_db_instance" "rds" {
  identifier = "${var.name_prefix}-db"

  engine                = "postgres"
  engine_version        = data.aws_rds_engine_version.postgres.version
  instance_class        = var.rds_instance_class
  allocated_storage     = var.rds_allocated_storage_gb
  max_allocated_storage = var.rds_max_allocated_storage_gb
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = local.rds_db_name
  username = var.rds_username
  password = random_password.rds.result

  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.rds.name
  parameter_group_name   = aws_db_parameter_group.rds.name

  backup_retention_period    = var.rds_backup_retention_days
  deletion_protection        = var.rds_deletion_protection
  multi_az                   = var.rds_multi_az
  publicly_accessible        = false
  auto_minor_version_upgrade = true

  apply_immediately         = false
  skip_final_snapshot       = var.rds_skip_final_snapshot
  final_snapshot_identifier = var.rds_skip_final_snapshot ? null : "${var.name_prefix}-final-${random_id.rds_snapshot.hex}"

  copy_tags_to_snapshot = true

  tags = local.tags
}

resource "aws_secretsmanager_secret" "rds" {
  name                    = "${var.name_prefix}-postgres"
  description             = "OpenRun RDS credentials"
  recovery_window_in_days = var.rds_secret_recovery_window_days
  tags                    = local.tags
}

resource "aws_secretsmanager_secret_version" "rds" {
  secret_id = aws_secretsmanager_secret.rds.id

  secret_string = jsonencode({
    username = var.rds_username
    password = random_password.rds.result
    host     = aws_db_instance.rds.address
    port     = aws_db_instance.rds.port
    database = local.rds_db_name
  })
}

output "rds_endpoint" {
  description = "RDS endpoint for OpenRun."
  value       = aws_db_instance.rds.address
}
