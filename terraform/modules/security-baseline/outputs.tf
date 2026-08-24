output "vpc_id" {
  value       = aws_vpc.main.id
  description = "VPC id."
}

output "data_subnet_ids" {
  value       = aws_subnet.data[*].id
  description = "Isolated data subnet ids (no internet egress)."
}

output "telemetry_bucket" {
  value       = aws_s3_bucket.telemetry.bucket
  description = "SSE-KMS telemetry bucket."
}

output "logs_bucket" {
  value       = aws_s3_bucket.logs.bucket
  description = "Immutable (Object Lock COMPLIANCE) log/evidence bucket."
}

output "rds_endpoint" {
  value       = aws_db_instance.postgres.address
  description = "Private RDS endpoint."
  sensitive   = true
}

output "rds_secret_arn" {
  value       = aws_secretsmanager_secret.rds.arn
  description = "Secrets Manager ARN for the RDS credential (30-day rotation)."
}

output "waf_acl_arn" {
  value       = aws_wafv2_web_acl.alb.arn
  description = "WAFv2 web ACL ARN to associate with the ALB."
}

output "security_alerts_topic" {
  value       = aws_sns_topic.security_alerts.arn
  description = "SNS topic for HIGH+ security alerts."
}

output "guardduty_detector_id" {
  value       = aws_guardduty_detector.main.id
  description = "GuardDuty detector id."
}
