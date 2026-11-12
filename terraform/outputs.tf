output "evidence_bucket" {
  description = "Name of the locked evidence bucket. Pass this to 'secuguard collect --upload --bucket'."
  value       = aws_s3_bucket.evidence.bucket
}

output "evidence_kms_key_arn" {
  description = "KMS key that encrypts evidence."
  value       = aws_kms_key.evidence.arn
}

output "vpc_id" {
  description = "The SecuGuard VPC."
  value       = aws_vpc.main.id
}

output "subnets_by_scope" {
  description = "Subnet IDs grouped by PCI scope."
  value = {
    for scope in distinct([for s in local.subnets : s.scope]) :
    scope => [for key, s in local.subnets : aws_subnet.tier[key].id if s.scope == scope]
  }
}

output "github_actions_role_arn" {
  description = "Role for GitHub Actions. Empty until github_repository is set."
  value       = local.github_enabled ? aws_iam_role.evidence_collector[0].arn : ""
}
