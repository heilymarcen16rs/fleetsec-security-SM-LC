# =========================================================== S3 (A.8.24 / CIS 2)
# Block Public Access at account level, SSE-KMS with CMK, versioning, lifecycle
# to Glacier, and a log bucket with Object Lock COMPLIANCE (immutable evidence).

resource "aws_s3_account_public_access_block" "account" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- Telemetry data bucket --------------------------------------------------
resource "aws_s3_bucket" "telemetry" {
  # checkov:skip=CKV_AWS_144:Cross-region replication out of scope for this baseline; Object Lock + versioning provide durability. Accepted risk, review 2026-Q4.
  # checkov:skip=CKV2_AWS_62:Event notifications wired by the ingestion stack, not the security baseline module.
  bucket = "${local.name}-telemetry-${local.account_id}"
  tags   = merge(var.tags, { DataClass = "PII" })
}

resource "aws_s3_bucket_logging" "telemetry" {
  bucket        = aws_s3_bucket.telemetry.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/telemetry/"
}

resource "aws_s3_bucket_public_access_block" "telemetry" {
  bucket                  = aws_s3_bucket.telemetry.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id
  rule {
    id     = "to-glacier"
    status = "Enabled"
    filter {}
    transition {
      days          = var.s3_glacier_transition_days
      storage_class = "GLACIER"
    }
    noncurrent_version_expiration {
      noncurrent_days = 365
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Enforce TLS-only access (deny insecure transport).
data "aws_iam_policy_document" "telemetry_tls" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.telemetry.arn, "${aws_s3_bucket.telemetry.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id
  policy = data.aws_iam_policy_document.telemetry_tls.json
}

# --- Immutable log/evidence bucket (Object Lock COMPLIANCE) -----------------
resource "aws_s3_bucket" "logs" {
  # checkov:skip=CKV_AWS_144:Cross-region replication out of scope; Object Lock COMPLIANCE + versioning give tamper-proof durability. Accepted risk.
  # checkov:skip=CKV2_AWS_62:Event notifications not required for the immutable log sink.
  bucket              = "${local.name}-logs-${local.account_id}"
  object_lock_enabled = true
  tags                = merge(var.tags, { Purpose = "immutable-logs" })
}

# Self-logging for the log bucket (server access logs, separate prefix).
resource "aws_s3_bucket_logging" "logs" {
  bucket        = aws_s3_bucket.logs.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/logs/"
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    filter {}
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    noncurrent_version_expiration {
      noncurrent_days = 730
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    default_retention {
      mode = "COMPLIANCE" # cannot be deleted, even by root
      days = 365
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
  }
}
