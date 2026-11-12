from dataclasses import dataclass
from typing import Any
from app.models.domain import CloudResource, SeverityLevel


@dataclass
class EvaluatedFinding:
    rule_id: str
    title: str
    description: str
    severity: SeverityLevel
    evidence: dict[str, Any]
    remediation_summary: str
    remediation_cli: str
    remediation_terraform: str
    aws_doc_url: str


SEVERITY_PENALTIES = {
    SeverityLevel.CRITICAL: 18,
    SeverityLevel.HIGH: 10,
    SeverityLevel.MEDIUM: 4,
    SeverityLevel.LOW: 1,
    SeverityLevel.INFO: 0,
}


class CSPMScannerEngine:
    @staticmethod
    def evaluate_resource(resource: CloudResource) -> list[EvaluatedFinding]:
        cfg = resource.configuration or {}
        rtype = resource.resource_type
        findings: list[EvaluatedFinding] = []

        if rtype == "AWS::S3::Bucket":
            bname = resource.resource_id
            if not (
                cfg.get("block_public_acls")
                and cfg.get("block_public_policy")
                and cfg.get("ignore_public_acls")
                and cfg.get("restrict_public_buckets")
            ):
                findings.append(
                    EvaluatedFinding(
                        rule_id="S3_PUBLIC_ACCESS_BLOCK_DISABLED",
                        title=f"S3 Bucket '{bname}' does not block all public access",
                        description="Public Access Block settings are disabled or incomplete, exposing bucket objects or policies to unintended public internet access.",
                        severity=SeverityLevel.CRITICAL,
                        evidence={
                            "bucket": bname,
                            "block_public_acls": cfg.get("block_public_acls"),
                            "block_public_policy": cfg.get("block_public_policy"),
                        },
                        remediation_summary="Enable all four S3 Block Public Access settings on the bucket.",
                        remediation_cli=f"aws s3api put-public-access-block --bucket {bname} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                        remediation_terraform=f'resource "aws_s3_bucket_public_access_block" "block" {{\n  bucket                  = "{bname}"\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}}',
                        aws_doc_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                    )
                )

            if not cfg.get("encryption_enabled"):
                findings.append(
                    EvaluatedFinding(
                        rule_id="S3_DEFAULT_ENCRYPTION_MISSING",
                        title=f"S3 Bucket '{bname}' lacks default server-side encryption",
                        description="Default encryption is not enforced on this bucket, risking unencrypted data-at-rest storage.",
                        severity=SeverityLevel.HIGH,
                        evidence={"bucket": bname, "encryption_enabled": False},
                        remediation_summary="Configure default SSE-S3 (AES256) or SSE-KMS encryption on the S3 bucket.",
                        remediation_cli=f'aws s3api put-bucket-encryption --bucket {bname} --server-side-encryption-configuration \'{{"Rules":[{{"ApplyServerSideEncryptionByDefault":{{"SSEAlgorithm":"AES256"}}}}]}}\'',
                        remediation_terraform=f'resource "aws_s3_bucket_server_side_encryption_configuration" "enc" {{\n  bucket = "{bname}"\n  rule {{\n    apply_server_side_encryption_by_default {{\n      sse_algorithm = "AES256"\n    }}\n  }}\n}}',
                        aws_doc_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html",
                    )
                )

        elif rtype == "AWS::IAM::User":
            uname = resource.resource_name or resource.resource_id
            if cfg.get("console_access") and not cfg.get("mfa_enabled"):
                findings.append(
                    EvaluatedFinding(
                        rule_id="IAM_USER_MFA_DISABLED",
                        title=f"IAM User '{uname}' has console access without MFA",
                        description="Console-enabled IAM users without Multi-Factor Authentication are vulnerable to credential stuffing and phishing.",
                        severity=SeverityLevel.HIGH,
                        evidence={"user": uname, "console_access": True, "mfa_enabled": False},
                        remediation_summary="Assign a virtual or hardware MFA device to this IAM user immediately.",
                        remediation_cli=f"aws iam create-virtual-mfa-device --virtual-mfa-device-name {uname}-mfa --outfile /tmp/QRCode.png --bootstrap-method QRCodePNG",
                        remediation_terraform="# Enforce MFA via IAM condition key aws:MultiFactorAuthPresent = true",
                        aws_doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html",
                    )
                )

            if "arn:aws:iam::aws:policy/AdministratorAccess" in cfg.get("attached_policies", []) or cfg.get("inline_wildcard_admin"):
                findings.append(
                    EvaluatedFinding(
                        rule_id="IAM_WILDCARD_ADMIN_PRIVILEGES",
                        title=f"IAM User '{uname}' holds unrestricted AdministratorAccess (*:*)",
                        description="Full administrative privileges violate the Principle of Least Privilege and expand the blast radius if keys are compromised.",
                        severity=SeverityLevel.CRITICAL,
                        evidence={"user": uname, "attached_policies": cfg.get("attached_policies", [])},
                        remediation_summary="Detach AdministratorAccess and replace with scoped service-specific IAM policies.",
                        remediation_cli=f"aws iam detach-user-policy --user-name {uname} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                        remediation_terraform=f"# Replace AdministratorAccess on {uname} with least-privilege aws_iam_policy statements",
                        aws_doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
                    )
                )

        elif rtype == "AWS::EC2::SecurityGroup":
            sg_id = resource.resource_id
            for rule in cfg.get("ingress_rules", []):
                cidr = rule.get("cidr", "")
                from_p = rule.get("from_port", 0)
                to_p = rule.get("to_port", 65535)
                if cidr == "0.0.0.0/0":
                    if from_p <= 22 <= to_p:
                        findings.append(
                            EvaluatedFinding(
                                rule_id="SG_UNRESTRICTED_SSH_INGRESS",
                                title=f"Security Group '{sg_id}' exposes SSH (Port 22) to 0.0.0.0/0",
                                description="Allowing unrestricted inbound SSH from the entire internet exposes instances to automated brute-force attacks.",
                                severity=SeverityLevel.CRITICAL,
                                evidence={"security_group": sg_id, "rule": rule},
                                remediation_summary="Revoke 0.0.0.0/0 on TCP port 22 and use AWS Systems Manager Session Manager or a restricted corporate CIDR.",
                                remediation_cli=f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port 22 --cidr 0.0.0.0/0",
                                remediation_terraform=f'# Restrict ingress cidr_blocks in aws_security_group "{sg_id}" to trusted VPN IP',
                                aws_doc_url="https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",
                            )
                        )
                    if from_p <= 3389 <= to_p:
                        findings.append(
                            EvaluatedFinding(
                                rule_id="SG_UNRESTRICTED_RDP_INGRESS",
                                title=f"Security Group '{sg_id}' exposes RDP (Port 3389) to 0.0.0.0/0",
                                description="Publicly exposed Remote Desktop Protocol (3389) is a primary vector for ransomware and credential attacks.",
                                severity=SeverityLevel.HIGH,
                                evidence={"security_group": sg_id, "rule": rule},
                                remediation_summary="Revoke 0.0.0.0/0 on TCP port 3389 and tunnel administrative access via Bastion/VPN.",
                                remediation_cli=f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port 3389 --cidr 0.0.0.0/0",
                                remediation_terraform=f'# Remove 0.0.0.0/0 ingress block on port 3389 for {sg_id}',
                                aws_doc_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html",
                            )
                        )

        elif rtype == "AWS::EC2::Instance":
            inst_id = resource.resource_id
            if not cfg.get("imdsv2_required"):
                findings.append(
                    EvaluatedFinding(
                        rule_id="EC2_IMDSV2_NOT_ENFORCED",
                        title=f"EC2 Instance '{inst_id}' allows legacy IMDSv1 metadata access",
                        description="IMDSv1 is susceptible to Server-Side Request Forgery (SSRF) attacks stealing IAM instance role credentials.",
                        severity=SeverityLevel.MEDIUM,
                        evidence={"instance_id": inst_id, "imdsv2_required": False},
                        remediation_summary="Enforce HttpTokens=required so only session-oriented IMDSv2 requests succeed.",
                        remediation_cli=f"aws ec2 modify-instance-metadata-options --instance-id {inst_id} --http-tokens required --http-endpoint enabled",
                        remediation_terraform='metadata_options {\n  http_endpoint = "enabled"\n  http_tokens   = "required"\n}',
                        aws_doc_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
                    )
                )

        elif rtype == "AWS::EC2::Volume":
            vol_id = resource.resource_id
            if not cfg.get("encrypted"):
                findings.append(
                    EvaluatedFinding(
                        rule_id="EBS_VOLUME_UNENCRYPTED",
                        title=f"EBS Volume '{vol_id}' is not encrypted at rest",
                        description="Unencrypted EBS block storage exposes snapshots and underlying disk data if improperly shared.",
                        severity=SeverityLevel.MEDIUM,
                        evidence={"volume_id": vol_id, "encrypted": False},
                        remediation_summary="Enable EBS encryption by default in the region and migrate data to an encrypted snapshot/volume.",
                        remediation_cli=f"aws ec2 enable-ebs-encryption-by-default --region {resource.region}",
                        remediation_terraform='resource "aws_ebs_encryption_by_default" "default" {\n  enabled = true\n}',
                        aws_doc_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
                    )
                )

        elif rtype == "AWS::CloudTrail::Trail":
            trail = resource.resource_id
            if not cfg.get("is_logging"):
                findings.append(
                    EvaluatedFinding(
                        rule_id="CLOUDTRAIL_LOGGING_DISABLED",
                        title=f"CloudTrail '{trail}' has active API event logging disabled",
                        description="Without active CloudTrail logging, API activity and security incidents cannot be audited or investigated.",
                        severity=SeverityLevel.CRITICAL,
                        evidence={"trail": trail, "is_logging": False},
                        remediation_summary="Start CloudTrail logging immediately and enable log file integrity validation.",
                        remediation_cli=f"aws cloudtrail start-logging --name {trail}",
                        remediation_terraform=f'resource "aws_cloudtrail" "main" {{\n  name                       = "{trail}"\n  enable_logging             = true\n  enable_log_file_validation = true\n  is_multi_region_trail      = true\n}}',
                        aws_doc_url="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html",
                    )
                )

        return findings

    @staticmethod
    def calculate_security_score(severities: list[SeverityLevel]) -> int:
        total_penalty = sum(SEVERITY_PENALTIES.get(sev, 0) for sev in severities)
        return max(0, min(100, round(100 * (100 / (100 + total_penalty)))))
