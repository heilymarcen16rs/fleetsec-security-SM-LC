terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name        = var.project
  account_id  = data.aws_caller_identity.current.account_id
  data_subnet = cidrsubnets(var.vpc_cidr, 4, 4, 4, 4, 4, 4)
}
