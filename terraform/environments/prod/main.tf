terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
  # Remote state should live in an encrypted, versioned bucket with a DynamoDB
  # lock table. Commented so `terraform init -backend=false` works in CI/offline.
  # backend "s3" {
  #   bucket         = "fleetsec-tfstate-<account_id>"
  #   key            = "prod/security-baseline.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "fleetsec-tf-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project    = "fleetsec"
      Env        = "prod"
      ManagedBy  = "terraform"
      Compliance = "ISO27001-CIS-Ley1581"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

module "security_baseline" {
  source = "../../modules/security-baseline"

  project = "fleetsec"
  region  = var.region
  azs     = ["us-east-1a", "us-east-1b"]
  vpc_cidr = "10.0.0.0/16"
}

# --- GuardDuty Threat Intel Set (Entregable 04) -----------------------------
# The IOC list (one IP per line) is uploaded to the immutable logs bucket and
# referenced here. See detection/threat-intel/ for the file and the CLI runbook.
resource "aws_s3_object" "threat_intel" {
  bucket = module.security_baseline.logs_bucket
  key    = "threat-intel/fleetsec-iocs.txt"
  source = "${path.module}/../../../detection/threat-intel/fleetsec-iocs.txt"
  etag   = filemd5("${path.module}/../../../detection/threat-intel/fleetsec-iocs.txt")
}

resource "aws_guardduty_threatintelset" "fleetsec" {
  detector_id = module.security_baseline.guardduty_detector_id
  name        = "fleetsec-iocs"
  format      = "TXT"
  location    = "https://s3.amazonaws.com/${module.security_baseline.logs_bucket}/threat-intel/fleetsec-iocs.txt"
  activate    = true
  depends_on  = [aws_s3_object.threat_intel]
}

output "telemetry_bucket" {
  value = module.security_baseline.telemetry_bucket
}

output "waf_acl_arn" {
  value = module.security_baseline.waf_acl_arn
}
