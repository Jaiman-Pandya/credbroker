# Terraform and provider configuration for the CredBroker AWS deployment.
#
# State backend: uncomment and fill in the s3 block below BEFORE enabling the
# CI plan/apply jobs (the TERRAFORM_ENABLED repository variable read by
# .github/workflows/ci.yml). With the backend commented out every CI runner
# starts from fresh local state, so a second apply would try to recreate the
# whole stack. Local state is acceptable only for a first manual bootstrap.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # backend "s3" {
  #   bucket         = "<state-bucket>"
  #   key            = "credbroker/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "<lock-table>"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
