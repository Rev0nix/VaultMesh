data "aws_caller_identity" "current" {}

# 1. Least-Privilege Read-Only IAM Role for VaultMesh STS AssumeRole
resource "aws_iam_role" "vaultmesh_audit_role" {
  name        = "VaultMeshSecurityAuditRole"
  description = "Least-privilege read-only role assumed by VaultMesh CSPM via STS ExternalId"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = var.trusted_principal_arn
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "vaultmesh_readonly_policy" {
  name = "VaultMeshCSPMReadOnlyPolicy"
  role = aws_iam_role.vaultmesh_audit_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "VaultMeshPostureAndTelemetryRead"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketEncryption",
          "s3:GetBucketVersioning",
          "s3:GetBucketPolicyStatus",
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVolumes",
          "iam:GetAccountSummary",
          "iam:ListUsers",
          "iam:ListRoles",
          "iam:ListPolicies",
          "iam:GetPolicyVersion",
          "iam:ListAttachedUserPolicies",
          "iam:ListAttachedRolePolicies",
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:LookupEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# 2. Optional Encrypted S3 Audit Storage (Disabled by default for ₹0 dev budget)
resource "aws_s3_bucket" "audit_logs" {
  count  = var.enable_cloudtrail_bucket ? 1 : 0
  bucket = "vaultmesh-audit-logs-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
}

resource "aws_s3_bucket_public_access_block" "audit_logs_block" {
  count                   = var.enable_cloudtrail_bucket ? 1 : 0
  bucket                  = aws_s3_bucket.audit_logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs_enc" {
  count  = var.enable_cloudtrail_bucket ? 1 : 0
  bucket = aws_s3_bucket.audit_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "audit_logs_ver" {
  count  = var.enable_cloudtrail_bucket ? 1 : 0
  bucket = aws_s3_bucket.audit_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}
