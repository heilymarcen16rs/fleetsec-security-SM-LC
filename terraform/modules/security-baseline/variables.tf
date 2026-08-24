variable "project" {
  type        = string
  default     = "fleetsec"
  description = "Project/name prefix for all resources."
}

variable "region" {
  type        = string
  default     = "us-east-1"
  description = "Primary AWS region."
}

variable "vpc_cidr" {
  type        = string
  default     = "10.0.0.0/16"
  description = "VPC CIDR block."
}

variable "azs" {
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
  description = "At least two AZs for Multi-AZ."
}

variable "alb_ingress_cidrs" {
  type        = list(string)
  default     = ["0.0.0.0/0"]
  description = "CIDRs allowed to reach the ALB on 80/443 ONLY (no admin ports)."
}

variable "log_retention_days" {
  type        = number
  default     = 365
  description = "CloudWatch log retention."
}

variable "s3_glacier_transition_days" {
  type        = number
  default     = 180
  description = "Days before telemetry objects transition to Glacier."
}

variable "tags" {
  type = map(string)
  default = {
    Project    = "fleetsec"
    ManagedBy  = "terraform"
    Compliance = "ISO27001-CIS-Ley1581"
    DataClass  = "PII"
  }
  description = "Common tags."
}
