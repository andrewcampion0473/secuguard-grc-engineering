variable "region" {
  description = "AWS region to build in."
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile to use. Leave null to use whatever credentials are active in your terminal."
  type        = string
  default     = null
}

variable "vpc_cidr" {
  description = "Address range for the SecuGuard VPC."
  type        = string
  default     = "10.20.0.0/16"
}

variable "evidence_retention_days" {
  description = "How many days each evidence file is locked against change or deletion. A real PCI environment would use at least 365. This demo uses 1 so it can be torn down the next day."
  type        = number
  default     = 1
}

variable "evidence_lock_mode" {
  description = <<-EOT
    COMPLIANCE means nobody can change or delete a locked file until its retention ends,
    including administrators and the root user. This is the mode a real evidence store
    should use, and it is the default here. The cost is that 'terraform destroy' cannot
    remove the bucket until the newest file's retention has ended.
    GOVERNANCE lets an administrator remove the lock early. The AWS Console does this
    automatically for administrators, so it protects against other users but not against
    the account's own admins.
  EOT
  type        = string
  default     = "COMPLIANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.evidence_lock_mode)
    error_message = "evidence_lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "github_repository" {
  description = "Your GitHub repository as owner/name. Leave empty until you want GitHub Actions to collect evidence on a schedule."
  type        = string
  default     = ""
}

variable "github_owner_id" {
  description = <<-EOT
    The numeric ID of the GitHub account that owns the repository. Repositories created
    after July 15, 2026 identify themselves to AWS with this number as well as the name,
    so that a deleted and re-registered name cannot inherit access. Leave empty only for
    a repository created before that date. MANUAL.md, Part 9, step 3 shows how to find it.
  EOT
  type        = string
  default     = ""
}

variable "github_repository_id" {
  description = "The numeric ID of the GitHub repository. See github_owner_id."
  type        = string
  default     = ""

  validation {
    condition     = (var.github_repository_id == "") == (var.github_owner_id == "")
    error_message = "Set both github_owner_id and github_repository_id, or neither."
  }
}

variable "planted_findings" {
  description = <<-EOT
    Create the deliberate weaknesses in planted.tf so the checks have real problems to
    find. Every one is built to be harmless: the users and role are blocked from doing
    anything, the bucket is empty, and nothing is reachable from the internet. Set to
    false to remove them all.
  EOT
  type        = bool
  default     = true
}

variable "planted_load_balancer" {
  description = "Create the load balancer with an outdated TLS policy. It costs about $17 a month while it exists. Ignored when planted_findings is false."
  type        = bool
  default     = true
}

variable "planted_vendor_account_id" {
  description = <<-EOT
    The outside AWS account that the planted vendor role trusts. AWS rejects account
    numbers that do not exist, so the default is an account AWS itself owns: the one
    its load balancing service uses in us-east-1, published in the AWS documentation.
    The role carries a deny-everything permissions boundary, so trusting it grants nothing.
    You can put a second account of your own here instead.
  EOT
  type        = string
  default     = "127311923021"

  validation {
    condition     = can(regex("^[0-9]{12}$", var.planted_vendor_account_id))
    error_message = "planted_vendor_account_id must be a 12-digit AWS account number."
  }
}
