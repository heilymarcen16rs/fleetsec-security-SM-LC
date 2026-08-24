# =========================================================== IAM (A.5.15/A.8.2)
# Least-privilege ECS task role per service. NO AdministratorAccess, NO wildcards
# on actions in production. Strong password policy. (CIS 1.x)

resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}

# --- ECS task execution role (pull image, read secrets) ---------------------
resource "aws_iam_role" "ecs_execution" {
  name = "${local.name}-ecs-exec-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "ecs-tasks.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Scoped permission to read ONLY this app's secret and decrypt with the ECS CMK.
resource "aws_iam_role_policy" "ecs_secrets" {
  name = "${local.name}-ecs-read-secret"
  role = aws_iam_role.ecs_execution.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["secretsmanager:GetSecretValue"],
        Resource = [aws_secretsmanager_secret.rds.arn]
      },
      {
        Effect   = "Allow",
        Action   = ["kms:Decrypt"],
        Resource = [aws_kms_key.ecs.arn]
      }
    ]
  })
}

# --- ECS task (application) role: least privilege to S3 telemetry prefix -----
resource "aws_iam_role" "ecs_task" {
  name = "${local.name}-ecs-task-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "ecs-tasks.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "ecs_task_s3" {
  name = "${local.name}-ecs-task-s3"
  role = aws_iam_role.ecs_task.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = ["s3:GetObject", "s3:PutObject"],
      # Scoped to a single prefix — no s3:* and no bucket-wide wildcard.
      Resource = ["${aws_s3_bucket.telemetry.arn}/ingest/*"]
    }]
  })
}
