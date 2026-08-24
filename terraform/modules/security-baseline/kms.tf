# =========================================================== KMS (A.8.24 / CIS 3)
# Customer-managed keys per service, annual rotation, NO wildcard Principal.
# The trap "key policy sin Principal AWS *" is fixed here: every statement is
# scoped to the account root + the specific service principals that need it.

data "aws_iam_policy_document" "kms_generic" {
  # checkov:skip=CKV_AWS_111:Root "kms:*" is the AWS-recommended key-administration statement; scoped to this account root, it is the canonical key policy (AWS KMS best practice), not an over-privileged IAM policy.
  # checkov:skip=CKV_AWS_356:In a KMS key policy, Resource "*" means "this key" — it cannot reference other keys. This is the required form, not a wildcard grant.
  # checkov:skip=CKV_AWS_109:Key administration must be delegable to the account root per AWS guidance to avoid unrecoverable keys.
  statement {
    sid    = "EnableAccountRootAdmin"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
      "kms:GenerateDataKey*", "kms:Describe*"
    ]
    resources = ["*"]
  }
}

resource "aws_kms_key" "rds" {
  description             = "${local.name} RDS CMK"
  enable_key_rotation     = true # annual rotation (CIS 3.8)
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms_generic.json
  tags                    = var.tags
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${local.name}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

resource "aws_kms_key" "s3" {
  description             = "${local.name} S3 CMK"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms_generic.json
  tags                    = var.tags
}

resource "aws_kms_alias" "s3" {
  name          = "alias/${local.name}-s3"
  target_key_id = aws_kms_key.s3.key_id
}

resource "aws_kms_key" "ecs" {
  description             = "${local.name} ECS/Secrets CMK"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms_generic.json
  tags                    = var.tags
}

resource "aws_kms_alias" "ecs" {
  name          = "alias/${local.name}-ecs"
  target_key_id = aws_kms_key.ecs.key_id
}
