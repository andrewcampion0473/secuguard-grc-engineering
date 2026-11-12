# Where evidence lives. Three protections stack up here:
#   1. Encryption with a customer managed KMS key that rotates every year.
#   2. Versioning, so an overwrite creates a new version and never replaces the old one.
#   3. Object Lock, so no version can be changed or deleted during its retention period.

resource "aws_kms_key" "evidence" {
  description             = "SecuGuard evidence encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  tags = { Name = "secuguard-evidence" }
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/secuguard-evidence"
  target_key_id = aws_kms_key.evidence.key_id
}

resource "aws_s3_bucket" "evidence" {
  # Bucket names are global across all of AWS, so the account ID keeps this one unique.
  bucket              = "secuguard-evidence-${data.aws_caller_identity.current.account_id}"
  object_lock_enabled = true

  # Lets 'terraform destroy' empty the bucket once every file's lock has ended, so the
  # demo can be torn down. Locked files still cannot be removed. Never set this on a real
  # evidence bucket.
  force_destroy = true

  tags = { Name = "secuguard-evidence" }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode = var.evidence_lock_mode
      days = var.evidence_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Refuse any request that does not use TLS.
data "aws_iam_policy_document" "evidence_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.evidence.arn,
      "${aws_s3_bucket.evidence.arn}/*",
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

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = data.aws_iam_policy_document.evidence_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.evidence]
}
