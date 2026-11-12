# Deliberate weaknesses, so the checks have real problems to find.
#
# A compliance tool that only ever reports "pass" proves nothing. These resources are
# the things a GRC team finds in real accounts: an old key nobody rotates, a user with
# no MFA, a certificate about to expire. Each comment names the check that catches it.
#
# Every one is built to be harmless:
#   - The users and the role carry a permissions boundary that denies every action, so
#     their credentials can do nothing even if they leaked.
#   - The bucket is empty and has no policy making it public.
#   - The network has no internet gateway, so nothing here is reachable from outside.
#
# Set planted_findings = false in terraform.tfvars to remove all of them.

locals {
  planted      = var.planted_findings ? 1 : 0
  planted_lb   = var.planted_findings && var.planted_load_balancer ? 1 : 0
  planted_tags = { "secuguard:planted" = "true" }
}

# ------------------------------------------------------------------ network

# NET-01: SSH open to the whole internet, on an office-zone group.
resource "aws_security_group" "planted_open_admin" {
  count = local.planted

  name        = "secuguard-planted-open-admin"
  description = "Planted finding: SSH open to the internet"
  vpc_id      = aws_vpc.main.id

  tags = merge(local.planted_tags, {
    Name              = "secuguard-planted-open-admin"
    (local.scope_tag) = "out-of-scope"
  })
}

resource "aws_vpc_security_group_ingress_rule" "planted_ssh_from_anywhere" {
  count = local.planted

  security_group_id = aws_security_group.planted_open_admin[0].id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  description       = "SSH from anywhere"
}

# ------------------------------------------------------------------ encryption

# CRY-01: an encryption key with automatic rotation switched off.
resource "aws_kms_key" "planted_no_rotation" {
  count = local.planted

  description             = "Planted finding: legacy key without rotation"
  enable_key_rotation     = false
  deletion_window_in_days = 7

  tags = merge(local.planted_tags, { Name = "secuguard-legacy-no-rotation" })
}

resource "aws_kms_alias" "planted_no_rotation" {
  count = local.planted

  name          = "alias/secuguard-legacy-no-rotation"
  target_key_id = aws_kms_key.planted_no_rotation[0].key_id
}

# CRY-02 and CRY-03: a bucket with no key of its own and its public access protections off.
# It holds nothing and has no policy or ACL that makes it public.
resource "aws_s3_bucket" "planted_legacy_exports" {
  count = local.planted

  bucket        = "secuguard-legacy-exports-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = merge(local.planted_tags, { Name = "secuguard-legacy-exports" })
}

resource "aws_s3_bucket_public_access_block" "planted_legacy_exports" {
  count = local.planted

  bucket = aws_s3_bucket.planted_legacy_exports[0].id

  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

# ------------------------------------------------------------------ certificates

# CRY-04 and CRY-05: a certificate with a 1024-bit key that expires 20 days after it is made.
resource "tls_private_key" "planted_weak" {
  count = local.planted

  algorithm = "RSA"
  rsa_bits  = 1024
}

resource "tls_self_signed_cert" "planted_weak" {
  count = local.planted

  private_key_pem       = tls_private_key.planted_weak[0].private_key_pem
  validity_period_hours = 480
  allowed_uses          = ["digital_signature", "key_encipherment", "server_auth"]

  subject {
    common_name  = "legacy-api.secuguard.example"
    organization = "SecuGuard (fictional)"
  }
}

resource "aws_acm_certificate" "planted_weak" {
  count = local.planted

  private_key      = tls_private_key.planted_weak[0].private_key_pem
  certificate_body = tls_self_signed_cert.planted_weak[0].cert_pem

  tags = merge(local.planted_tags, { Name = "legacy-api.secuguard.example" })

  lifecycle {
    create_before_destroy = true
  }
}

# A healthy certificate for comparison: 2048-bit key, valid for a year. The checks pass it.
resource "tls_private_key" "portal" {
  count = local.planted

  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "portal" {
  count = local.planted

  private_key_pem       = tls_private_key.portal[0].private_key_pem
  validity_period_hours = 8760
  allowed_uses          = ["digital_signature", "key_encipherment", "server_auth"]

  subject {
    common_name  = "portal.secuguard.example"
    organization = "SecuGuard (fictional)"
  }
}

resource "aws_acm_certificate" "portal" {
  count = local.planted

  private_key      = tls_private_key.portal[0].private_key_pem
  certificate_body = tls_self_signed_cert.portal[0].cert_pem

  tags = { Name = "portal.secuguard.example" }

  lifecycle {
    create_before_destroy = true
  }
}

# ------------------------------------------------------------------ load balancer

# CRY-06: an internal load balancer whose listener still allows TLS 1.0 and 1.1.
# ELBSecurityPolicy-2016-08 is what AWS applies when a listener is created outside the
# console and no policy is named, so this weakness is easy to end up with by accident.
# It sits in the shared zone, has nothing behind it, and answers every request with a 503.
resource "aws_lb" "planted_portal" {
  count = local.planted_lb

  name               = "secuguard-portal"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.tier["shared"].id]
  subnets            = [for key, subnet in local.subnets : aws_subnet.tier[key].id if subnet.tier == "shared"]

  tags = merge(local.planted_tags, { Name = "secuguard-portal" })
}

resource "aws_lb_listener" "planted_portal_https" {
  count = local.planted_lb

  load_balancer_arn = aws_lb.planted_portal[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.portal[0].arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "SecuGuard is a fictional company. Nothing is hosted here."
      status_code  = "503"
    }
  }
}

# ------------------------------------------------------------------ identity

# The safety net. Attached as a permissions boundary, this caps what an identity can do.
# Because it denies everything, the planted users and role are powerless whatever
# policies are attached to them.
resource "aws_iam_policy" "planted_deny_all" {
  count = local.planted

  name        = "secuguard-planted-deny-all"
  description = "Permissions boundary that makes the planted users and role harmless"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# IAM-04: a user who can sign in to the console with a password and has no MFA.
resource "aws_iam_user" "planted_alice" {
  count = local.planted

  name                 = "secuguard-dev-alice"
  permissions_boundary = aws_iam_policy.planted_deny_all[0].arn
  force_destroy        = true

  tags = local.planted_tags
}

resource "aws_iam_user_login_profile" "planted_alice" {
  count = local.planted

  user                    = aws_iam_user.planted_alice[0].name
  password_reset_required = true
}

# IAM-05 and IAM-06: a service account with administrator rights attached directly,
# and an active access key that has never been used.
resource "aws_iam_user" "planted_reports" {
  count = local.planted

  name                 = "secuguard-svc-reports"
  permissions_boundary = aws_iam_policy.planted_deny_all[0].arn
  force_destroy        = true

  tags = local.planted_tags
}

resource "aws_iam_user_policy_attachment" "planted_reports_admin" {
  count = local.planted

  user       = aws_iam_user.planted_reports[0].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_access_key" "planted_reports" {
  count = local.planted

  user = aws_iam_user.planted_reports[0].name
}

# A well-behaved user for comparison: no password, no keys, rights only through a group.
resource "aws_iam_group" "auditors" {
  count = local.planted

  name = "secuguard-auditors"
}

resource "aws_iam_group_policy_attachment" "auditors_read_only" {
  count = local.planted

  group      = aws_iam_group.auditors[0].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_user" "carol" {
  count = local.planted

  name                 = "secuguard-audit-carol"
  permissions_boundary = aws_iam_policy.planted_deny_all[0].arn
  force_destroy        = true
}

resource "aws_iam_user_group_membership" "carol" {
  count = local.planted

  user   = aws_iam_user.carol[0].name
  groups = [aws_iam_group.auditors[0].name]
}

# IAM-07: a role that an outside account may use, with no external ID required.
# AWS only accepts account numbers that exist, so this uses a real one that AWS owns
# and publishes in its documentation. It stands in for a vendor. See variables.tf.
resource "aws_iam_role" "planted_legacy_vendor" {
  count = local.planted

  name                 = "secuguard-legacy-vendor"
  description          = "Planted finding: trusts an outside account with no external ID"
  permissions_boundary = aws_iam_policy.planted_deny_all[0].arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.planted_vendor_account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.planted_tags
}
