# Lets GitHub Actions collect evidence on a schedule without any stored AWS keys.
# GitHub proves which repository and branch a workflow is running from, and AWS hands
# back credentials that last one hour. Created only when github_repository is set.

locals {
  github_enabled = var.github_repository != ""
}

resource "aws_iam_openid_connect_provider" "github" {
  count = local.github_enabled ? 1 : 0

  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "github_trust" {
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

    # Only workflows on the main branch of this one repository may use the role.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "evidence_collector" {
  count = local.github_enabled ? 1 : 0

  name                 = "secuguard-evidence-collector"
  description          = "Read-only evidence collection from GitHub Actions"
  assume_role_policy   = data.aws_iam_policy_document.github_trust[0].json
  max_session_duration = 3600
}

# AWS's own read-only policy for auditors. It can read configuration, never data or secrets.
resource "aws_iam_role_policy_attachment" "security_audit" {
  count = local.github_enabled ? 1 : 0

  role       = aws_iam_role.evidence_collector[0].name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# The one thing the collector may write: new evidence files. It cannot delete them
# and cannot remove their locks.
data "aws_iam_policy_document" "evidence_writer" {
  count = local.github_enabled ? 1 : 0

  statement {
    sid       = "WriteAndReadEvidence"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/*"]
  }

  statement {
    sid       = "ListEvidenceBucket"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.evidence.arn]
  }

  statement {
    sid       = "UseEvidenceKey"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.evidence.arn]
  }
}

resource "aws_iam_role_policy" "evidence_writer" {
  count = local.github_enabled ? 1 : 0

  name   = "evidence-writer"
  role   = aws_iam_role.evidence_collector[0].id
  policy = data.aws_iam_policy_document.evidence_writer[0].json
}
