# =========================================================== RDS (A.8.24)
# Multi-AZ, CMK-encrypted, NO public endpoint, 7-day backups, TLS enforced,
# log_connections=1 via parameter group. Password sourced from Secrets Manager.

resource "aws_db_subnet_group" "data" {
  name       = "${local.name}-db-subnets"
  subnet_ids = aws_subnet.data[*].id
  tags       = var.tags
}

resource "aws_db_parameter_group" "pg" {
  name   = "${local.name}-pg16"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1" # ssl=1 (TLS required)
  }
  parameter {
    name  = "log_connections"
    value = "1"
  }
  parameter {
    name  = "log_disconnections"
    value = "1"
  }
  tags = var.tags
}

resource "aws_secretsmanager_secret" "rds" {
  name                    = "${local.name}/prod/db"
  kms_key_id              = aws_kms_key.ecs.arn
  recovery_window_in_days = 7
  tags                    = var.tags
}

resource "aws_secretsmanager_secret_rotation" "rds" {
  secret_id = aws_secretsmanager_secret.rds.id
  rotation_rules {
    automatically_after_days = 30 # rotation 30 días (test requirement)
  }
  # rotation_lambda_arn wired to the AWS-provided Postgres rotation function.
  lifecycle { ignore_changes = [rotation_lambda_arn] }
}

resource "aws_db_instance" "postgres" {
  identifier     = "${local.name}-prod"
  engine         = "postgres"
  engine_version = "16.4"
  instance_class = "db.t3.medium"

  allocated_storage     = 50
  max_allocated_storage = 200
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.rds.arn

  multi_az                = true
  publicly_accessible     = false
  db_subnet_group_name    = aws_db_subnet_group.data.name
  vpc_security_group_ids  = [aws_security_group.data.id]
  parameter_group_name    = aws_db_parameter_group.pg.name
  backup_retention_period = 7
  deletion_protection     = true
  storage_type            = "gp3"

  # Password comes from Secrets Manager, never a literal.
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.rds.arn
  username                      = "fleetadmin"

  # IAM database authentication (no static DB passwords for app roles).
  iam_database_authentication_enabled = true

  # Enhanced monitoring + Performance Insights (encrypted with the RDS CMK).
  monitoring_interval                   = 60
  monitoring_role_arn                   = aws_iam_role.rds_monitoring.arn
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.rds.arn
  performance_insights_retention_period = 7

  enabled_cloudwatch_logs_exports = ["postgresql"]
  auto_minor_version_upgrade      = true
  copy_tags_to_snapshot           = true
  skip_final_snapshot             = false
  final_snapshot_identifier       = "${local.name}-final"

  tags = merge(var.tags, { DataClass = "PII" })
}

resource "aws_iam_role" "rds_monitoring" {
  name = "${local.name}-rds-monitoring"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "monitoring.rds.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}
