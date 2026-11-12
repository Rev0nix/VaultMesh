output "vaultmesh_audit_role_arn" {
  description = "Copy this Role ARN into VaultMesh Cloud Accounts onboarding"
  value       = aws_iam_role.vaultmesh_audit_role.arn
}

output "aws_account_id" {
  description = "12-digit AWS Account ID"
  value       = data.aws_caller_identity.current.account_id
}
