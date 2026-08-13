###############################################################################
# ⚠️  INTENTIONALLY VULNERABLE INFRASTRUCTURE — the "broken AWS account"
#
#  Teaching material for aiopsone.com. This is the artifact the IaC scanning
#  lessons (Checkov, trivy config, Snyk IaC) run against, and the account the
#  RUN chapter (Prowler, GuardDuty, Security Hub) scans once applied.
#
#  BEFORE YOU RUN THIS
#    1. Use a throwaway AWS account you are willing to delete.
#    2. Set a billing alarm. Do this first, not after.
#    3. Run `terraform destroy` when the exercise is finished.
#
#  There is deliberately NO default region and NO default profile. You must pass
#  both explicitly, so this cannot be applied to the wrong account by habit:
#
#    terraform apply -var="aws_region=ap-southeast-2" -var="aws_profile=range-throwaway"
#
#  Most lessons only need `terraform plan` plus a scanner. You do not have to
#  apply this at all to do the IaC chapter.
###############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "aws_region" {
  description = "Region for the throwaway account. No default, on purpose."
  type        = string
}

variable "aws_profile" {
  description = "Named profile for the throwaway account. No default, on purpose."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for every resource, so they are obvious and easy to delete."
  type        = string
  default     = "aiopsone-range"
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project   = "aiopsone-range"
      Purpose   = "INTENTIONALLY-VULNERABLE-TEACHING-LAB"
      DeleteMe  = "true"
      ManagedBy = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

output "account_id_reminder" {
  description = "Check this is the throwaway account before you apply."
  value       = "Applying to account ${data.aws_caller_identity.current.account_id} in ${var.aws_region}. If that is not your throwaway account, stop."
}
