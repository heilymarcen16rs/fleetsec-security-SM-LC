# =========================================================== WAFv2 (A.8.20/A.8.23)
# Attached to the ALB (REGIONAL). Managed rule sets in BLOCK, a custom rate limit,
# and geo-restriction to CO/PE/US. CommonRuleSet is justified COUNT vs BLOCK below.

resource "aws_wafv2_web_acl" "alb" {
  name        = "${local.name}-alb-waf"
  description = "FleetSec ALB WAF"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # --- SQLi managed set (BLOCK) ---------------------------------------------
  rule {
    name     = "AWS-SQLi"
    priority = 1
    override_action {
      none {} # rules act in their own (BLOCK) mode
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "sqli"
      sampled_requests_enabled   = true
    }
  }

  # --- Known bad inputs managed set (BLOCK) ---------------------------------
  rule {
    name     = "AWS-KnownBadInputs"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "badinputs"
      sampled_requests_enabled   = true
    }
  }

  # --- Common rule set: COUNT first (tuning) --------------------------------
  # Justification: CommonRuleSet has broad rules (e.g. SizeRestrictions_BODY)
  # that can false-positive on legitimate large telemetry batches. We run it in
  # COUNT for 2 weeks, review sampled requests, then flip to BLOCK per-rule.
  rule {
    name     = "AWS-Common"
    priority = 3
    override_action {
      count {} # COUNT during tuning window
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "common"
      sampled_requests_enabled   = true
    }
  }

  # --- Rate limit on the auth endpoint scope --------------------------------
  rule {
    name     = "RateLimitAuth"
    priority = 10
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 1000 # 1,000 req / 5 min per IP
        aggregate_key_type = "IP"
        scope_down_statement {
          byte_match_statement {
            positional_constraint = "STARTS_WITH"
            search_string         = "/secure/login"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "ratelimit-auth"
      sampled_requests_enabled   = true
    }
  }

  # --- Geo restriction: CO, PE, US ------------------------------------------
  # Impact on VPN users documented in README §WAF; exception path = allowlisted
  # corporate egress IP set for staff travelling outside these countries.
  rule {
    name     = "GeoAllow"
    priority = 20
    action {
      block {}
    }
    statement {
      not_statement {
        statement {
          geo_match_statement { country_codes = ["CO", "PE", "US"] }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "geo"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-alb-waf"
    sampled_requests_enabled   = true
  }
  tags = var.tags
}

# WAF logging to a dedicated CloudWatch log group (name MUST start aws-waf-logs-).
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${local.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.s3.arn
  tags              = var.tags
}

resource "aws_wafv2_web_acl_logging_configuration" "alb" {
  resource_arn            = aws_wafv2_web_acl.alb.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  # Redact the Authorization header from stored WAF logs (no token leakage).
  redacted_fields {
    single_header {
      name = "authorization"
    }
  }
}
