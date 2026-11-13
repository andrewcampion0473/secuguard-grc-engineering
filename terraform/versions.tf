terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    # Used only to generate the throwaway certificates in planted.tf.
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = var.aws_profile

  # Every resource Terraform creates gets these tags automatically.
  default_tags {
    tags = {
      Project   = "secuguard-grc"
      ManagedBy = "terraform"
      Purpose   = "grc-engineering-demo"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}
