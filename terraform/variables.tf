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
