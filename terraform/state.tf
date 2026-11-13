# Where Terraform keeps its record of what it has built, and who may read it.
#
# Terraform's record is called its state. At first it is a file on one computer, which
# means nobody else, and no automated check, can tell what has been built. Moving it into
# a bucket in AWS lets GitHub read it, so a proposed change can be judged before it is merged.
#
# The state lists every resource and can hold secret values, so the bucket is private,
# versioned, and encrypted with a key of its own.

resource "aws_kms_key" "tfstate" {
  description             = "SecuGuard Terraform state encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  tags = { Name = "secuguard-tfstate" }
}

resource "aws_kms_alias" "tfstate" {
  name          = "alias/secuguard-tfstate"
  target_key_id = aws_kms_key.tfstate.key_id
}

resource "aws_s3_bucket" "tfstate" {
  bucket        = "secuguard-tfstate-${data.aws_caller_identity.current.account_id}"
  force_destroy = true # so the demo can be torn down. Never set this on a real state bucket.

  tags = { Name = "secuguard-tfstate" }
}

# Every earlier version of the state is kept, so a bad change to it can be undone.
resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.tfstate.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "tfstate_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.tfstate.arn,
      "${aws_s3_bucket.tfstate.arn}/*",
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

resource "aws_s3_bucket_policy" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  policy = data.aws_iam_policy_document.tfstate_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.tfstate]
}

# ------------------------------------------------------------------ the plan checker's role

# A second role for GitHub, separate from the evidence collector. Only a proposed change
# (a pull request) in this one repository can use it. It can read the account and the
# state so that Terraform can work out a plan. It cannot change anything.

locals {
  # How a pull request in this repository names itself to AWS. See github_oidc.tf.
  github_pull_request_subject = (
    var.github_owner_id != ""
    ? "repo:${local.github_owner}@${var.github_owner_id}/${local.github_repo}@${var.github_repository_id}:pull_request"
    : "repo:${var.github_repository}:pull_request"
  )
}

data "aws_iam_policy_document" "plan_checker_trust" {
  count = local.github_enabled ? 1 : 0

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github[0].arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.github_pull_request_subject]
    }
  }
}

resource "aws_iam_role" "plan_checker" {
  count = local.github_enabled ? 1 : 0

  name                 = "secuguard-plan-checker"
  description          = "Read-only role that lets GitHub work out a Terraform plan for a proposed change"
  assume_role_policy   = data.aws_iam_policy_document.plan_checker_trust[0].json
  max_session_duration = 3600
}

# AWS's own read-only policy. Terraform has to read every resource it manages to plan a change.
resource "aws_iam_role_policy_attachment" "plan_checker_read_only" {
  count = local.github_enabled ? 1 : 0

  role       = aws_iam_role.plan_checker[0].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Reading the state needs the state's key. This grants reading only. The role cannot write
# to the state, so a proposed change can never alter the record of what has been built.
data "aws_iam_policy_document" "plan_checker_state" {
  count = local.github_enabled ? 1 : 0

  statement {
    sid       = "ReadTerraformState"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.tfstate.arn, "${aws_s3_bucket.tfstate.arn}/*"]
  }

  statement {
    sid       = "DecryptTerraformState"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [aws_kms_key.tfstate.arn]
  }
}

resource "aws_iam_role_policy" "plan_checker_state" {
  count = local.github_enabled ? 1 : 0

  name   = "read-terraform-state"
  role   = aws_iam_role.plan_checker[0].id
  policy = data.aws_iam_policy_document.plan_checker_state[0].json
}
