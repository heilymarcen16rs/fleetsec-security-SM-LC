# =========================================================== Monitoring & Compliance
# CloudTrail (multi-region, log file validation) -> immutable S3 + CloudWatch.
# Metric filters + alarms: root login, IAM changes, SG changes, DisableKeyRotation.
# AWS Config recorder + managed rules. GuardDuty. Security Hub (FSBP + CIS 1.4).

# --- SNS for HIGH+ security alerts ------------------------------------------
resource "aws_sns_topic" "security_alerts" {
  name              = "${local.name}-security-alerts"
  kms_master_key_id = aws_kms_key.s3.id
  tags              = var.tags
}

# Allow CloudTrail and EventBridge to publish to the alerts topic.
data "aws_iam_policy_document" "sns_publish" {
  statement {
    sid     = "AllowServicesPublish"
    effect  = "Allow"
    actions = ["SNS:Publish"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com", "events.amazonaws.com", "cloudwatch.amazonaws.com"]
    }
    resources = [aws_sns_topic.security_alerts.arn]
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = data.aws_iam_policy_document.sns_publish.json
}

# --- CloudTrail -------------------------------------------------------------
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/${local.name}/cloudtrail"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.s3.arn
  tags              = var.tags
}

resource "aws_iam_role" "cloudtrail_cw" {
  name = "${local.name}-cloudtrail-cw"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "cloudtrail.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "cloudtrail_cw" {
  name = "${local.name}-cloudtrail-cw"
  role = aws_iam_role.cloudtrail_cw.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"],
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

resource "aws_cloudtrail" "main" {
  name                          = "${local.name}-trail"
  s3_bucket_name                = aws_s3_bucket.logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true # tamper-evident digests
  kms_key_id                    = aws_kms_key.s3.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cw.arn
  sns_topic_name                = aws_sns_topic.security_alerts.name

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.telemetry.arn}/"]
    }
  }
  depends_on = [aws_s3_bucket_policy.trail]
  tags       = var.tags
}

# --- Metric filters + alarms ------------------------------------------------
locals {
  metric_filters = {
    root_login = {
      pattern = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
      desc    = "Root account usage (CIS 1.7 / 4.3)"
    }
    iam_changes = {
      pattern = "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = CreateUser) }"
      desc    = "IAM policy changes (CIS 4.4)"
    }
    sg_changes = {
      pattern = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = CreateSecurityGroup) }"
      desc    = "Security group changes (CIS 4.10)"
    }
    disable_key_rotation = {
      pattern = "{ ($.eventName = DisableKeyRotation) || ($.eventName = ScheduleKeyDeletion) }"
      desc    = "KMS key rotation disabled / key deletion (anti-forensics)"
    }
    delete_trail = {
      pattern = "{ ($.eventName = DeleteTrail) || ($.eventName = StopLogging) }"
      desc    = "CloudTrail tampering (CIS 4.5)"
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "filters" {
  for_each       = local.metric_filters
  name           = "${local.name}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = each.value.pattern
  metric_transformation {
    name      = "${local.name}-${each.key}"
    namespace = "FleetSec/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "alarms" {
  for_each            = local.metric_filters
  alarm_name          = "${local.name}-${each.key}"
  alarm_description   = each.value.desc
  namespace           = "FleetSec/Security"
  metric_name         = "${local.name}-${each.key}"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  tags                = var.tags
}

# --- AWS Config -------------------------------------------------------------
resource "aws_iam_role" "config" {
  name = "${local.name}-config-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "config.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  name     = "${local.name}-recorder"
  role_arn = aws_iam_role.config.arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${local.name}-delivery"
  s3_bucket_name = aws_s3_bucket.logs.id
  depends_on     = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

locals {
  config_rules = {
    cloudtrail-enabled          = "CLOUD_TRAIL_ENABLED"
    encrypted-volumes           = "ENCRYPTED_VOLUMES"
    guardduty-enabled-central   = "GUARDDUTY_ENABLED_CENTRALIZED"
    s3-public-read-prohibited   = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    iam-password-policy         = "IAM_PASSWORD_POLICY"
    root-account-mfa-enabled    = "ROOT_ACCOUNT_MFA_ENABLED"
    rds-encrypted               = "RDS_STORAGE_ENCRYPTED"
  }
}

resource "aws_config_config_rule" "managed" {
  for_each = local.config_rules
  name     = "${local.name}-${each.key}"
  source {
    owner             = "AWS"
    source_identifier = each.value
  }
  depends_on = [aws_config_configuration_recorder_status.main]
  tags       = var.tags
}

# --- GuardDuty --------------------------------------------------------------
resource "aws_guardduty_detector" "main" {
  # checkov:skip=CKV2_AWS_3:Single-account deployment; org-level delegated admin/auto-enable is configured at the AWS Organizations layer, out of this module's scope.
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  datasources {
    s3_logs { enable = true }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes { enable = true }
      }
    }
  }
  tags = var.tags
}

# Route HIGH+ GuardDuty findings to SNS via EventBridge.
resource "aws_cloudwatch_event_rule" "gd_high" {
  name        = "${local.name}-guardduty-high"
  description = "GuardDuty findings severity >= 7 (HIGH+)"
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail        = { severity = [{ numeric = [">=", 7] }] }
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "gd_high_sns" {
  rule      = aws_cloudwatch_event_rule.gd_high.name
  target_id = "sns"
  arn       = aws_sns_topic.security_alerts.arn
}

# --- Security Hub (FSBP + CIS AWS Foundations 1.4) --------------------------
resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}

resource "aws_securityhub_standards_subscription" "cis_14" {
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.main]
}
