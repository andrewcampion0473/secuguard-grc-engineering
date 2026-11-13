# Monitoring: the services that record what happens in the account and judge it continuously.
#
# Stage 2's checks reported that none of this existed. This file fixes those findings.
#   CloudTrail      records who did what. Fixes check LOG-01.
#   VPC flow logs   record network traffic in SecuGuard's network. Addresses check NET-04.
#   AWS Config      records every change to every resource. Satisfies check MON-01.
#   Security Hub    evaluates the account against a security standard every day. Satisfies MON-02.
#
# Each service can be switched off on its own in terraform.tfvars if AWS refuses it.

locals {
  monitoring   = var.monitoring ? 1 : 0
  cloudtrail   = var.monitoring && var.monitoring_cloudtrail ? 1 : 0
  flow_logs    = var.monitoring && var.monitoring_flow_logs ? 1 : 0
  config       = var.monitoring && var.monitoring_config ? 1 : 0
  security_hub = var.monitoring && var.monitoring_security_hub ? 1 : 0
  account_id   = data.aws_caller_identity.current.account_id
  log_services = ["cloudtrail.amazonaws.com", "config.amazonaws.com", "delivery.logs.amazonaws.com"]
}

# ------------------------------------------------------------------ where logs are kept

# A key for the logs, separate from the evidence key. The three AWS services that write
# logs are allowed to use it. Nothing else is, apart from this account's administrators.
data "aws_iam_policy_document" "logs_key" {
  count = local.monitoring

  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "LogServicesMayEncrypt"
    actions   = ["kms:GenerateDataKey*", "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = local.log_services
    }
  }
}

resource "aws_kms_key" "logs" {
  count = local.monitoring

  description             = "SecuGuard log encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.logs_key[0].json

  tags = { Name = "secuguard-logs" }
}

resource "aws_kms_alias" "logs" {
  count = local.monitoring

  name          = "alias/secuguard-logs"
  target_key_id = aws_kms_key.logs[0].key_id
}

resource "aws_s3_bucket" "logs" {
  count = local.monitoring

  bucket        = "secuguard-logs-${local.account_id}"
  force_destroy = true # so the demo can be torn down. Never set this on a real log bucket.

  tags = { Name = "secuguard-logs" }
}

resource "aws_s3_bucket_versioning" "logs" {
  count = local.monitoring

  bucket = aws_s3_bucket.logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  count = local.monitoring

  bucket = aws_s3_bucket.logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.logs[0].arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count = local.monitoring

  bucket = aws_s3_bucket.logs[0].id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Each AWS logging service may check the bucket and write under its own folder, and nowhere else.
data "aws_iam_policy_document" "logs_bucket" {
  count = local.monitoring

  statement {
    sid       = "LogServicesMayCheckTheBucket"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.logs[0].arn]

    principals {
      type        = "Service"
      identifiers = local.log_services
    }
  }

  statement {
    sid       = "CloudTrailMayWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs[0].arn}/cloudtrail/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid       = "ConfigMayWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs[0].arn}/config/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid       = "FlowLogsMayWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs[0].arn}/flow-logs/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.logs[0].arn,
      "${aws_s3_bucket.logs[0].arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  count = local.monitoring

  bucket = aws_s3_bucket.logs[0].id
  policy = data.aws_iam_policy_document.logs_bucket[0].json

  depends_on = [aws_s3_bucket_public_access_block.logs]
}

# ------------------------------------------------------------------ CloudTrail

# One trail for every region, with log file validation, so a deleted or edited log file
# can be detected. This is the record of who did what.
resource "aws_cloudtrail" "main" {
  count = local.cloudtrail

  name                          = "secuguard-trail"
  s3_bucket_name                = aws_s3_bucket.logs[0].id
  s3_key_prefix                 = "cloudtrail"
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  tags = { Name = "secuguard-trail" }

  depends_on = [aws_s3_bucket_policy.logs, aws_s3_bucket_server_side_encryption_configuration.logs]
}

# ------------------------------------------------------------------ network flow logs

resource "aws_flow_log" "main" {
  count = local.flow_logs

  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = "${aws_s3_bucket.logs[0].arn}/flow-logs/"

  tags = { Name = "secuguard-vpc-flow-logs" }

  depends_on = [aws_s3_bucket_policy.logs]
}

# ------------------------------------------------------------------ AWS Config

# The role AWS Config uses to read the account's resources.
resource "aws_iam_role" "config_recorder" {
  count = local.config

  name        = "secuguard-config-recorder"
  description = "Lets AWS Config read resource configuration"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_recorder" {
  count = local.config

  role       = aws_iam_role.config_recorder[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  count = local.config

  name     = "secuguard"
  role_arn = aws_iam_role.config_recorder[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  count = local.config

  name           = "secuguard"
  s3_bucket_name = aws_s3_bucket.logs[0].id
  s3_key_prefix  = "config"

  depends_on = [aws_config_configuration_recorder.main, aws_s3_bucket_policy.logs]
}

resource "aws_config_configuration_recorder_status" "main" {
  count = local.config

  name       = aws_config_configuration_recorder.main[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# ------------------------------------------------------------------ Security Hub

resource "aws_securityhub_account" "main" {
  count = local.security_hub

  enable_default_standards = false
}

# AWS's own baseline of security best practices, evaluated automatically.
resource "aws_securityhub_standards_subscription" "best_practices" {
  count = local.security_hub

  standards_arn = "arn:aws:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"

  # Security Hub can take several minutes to finish enabling a standard in a new account.
  # The default wait of three minutes is often too short.
  timeouts {
    create = "20m"
    delete = "20m"
  }

  depends_on = [aws_securityhub_account.main, aws_config_configuration_recorder_status.main]
}
