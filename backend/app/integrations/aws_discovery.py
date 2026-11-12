from typing import Any
import boto3
from botocore.exceptions import BotoCoreError, ClientError


class AWSDiscoveryProvider:
    @staticmethod
    def discover_resources(
        aws_account_id: str,
        regions: list[str],
        is_mock: bool,
        role_arn: str | None = None,
        external_id: str | None = None,
    ) -> list[dict[str, Any]]:
        if is_mock:
            return AWSDiscoveryProvider._get_mock_inventory(aws_account_id, regions)
        return AWSDiscoveryProvider._get_live_inventory(
            aws_account_id=aws_account_id,
            regions=regions,
            role_arn=role_arn,
            external_id=external_id,
        )

    @staticmethod
    def _get_mock_inventory(aws_account_id: str, regions: list[str]) -> list[dict[str, Any]]:
        primary = regions[0] if regions else "ap-south-1"
        return [
            {
                "resource_arn": f"arn:aws:s3:::vaultmesh-prod-customer-backups-{aws_account_id}",
                "resource_id": f"vaultmesh-prod-customer-backups-{aws_account_id}",
                "resource_name": f"vaultmesh-prod-customer-backups-{aws_account_id}",
                "service": "S3",
                "resource_type": "AWS::S3::Bucket",
                "region": "global",
                "tags": {"Environment": "Production"},
                "configuration": {
                    "block_public_acls": False,
                    "block_public_policy": False,
                    "ignore_public_acls": False,
                    "restrict_public_buckets": False,
                    "encryption_enabled": False,
                },
            },
            {
                "resource_arn": f"arn:aws:s3:::vaultmesh-secure-audit-logs-{aws_account_id}",
                "resource_id": f"vaultmesh-secure-audit-logs-{aws_account_id}",
                "resource_name": f"vaultmesh-secure-audit-logs-{aws_account_id}",
                "service": "S3",
                "resource_type": "AWS::S3::Bucket",
                "region": "global",
                "tags": {"Environment": "Security"},
                "configuration": {
                    "block_public_acls": True,
                    "block_public_policy": True,
                    "ignore_public_acls": True,
                    "restrict_public_buckets": True,
                    "encryption_enabled": True,
                },
            },
            {
                "resource_arn": f"arn:aws:iam::{aws_account_id}:user/ci-deploy-bot",
                "resource_id": "AIDA_MOCK_CI_DEPLOY_BOT",
                "resource_name": "ci-deploy-bot",
                "service": "IAM",
                "resource_type": "AWS::IAM::User",
                "region": "global",
                "tags": {"Team": "DevOps"},
                "configuration": {
                    "mfa_enabled": False,
                    "console_access": True,
                    "attached_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"],
                    "inline_wildcard_admin": True,
                },
            },
            {
                "resource_arn": f"arn:aws:iam::{aws_account_id}:role/AppBackendEC2Role",
                "resource_id": "AROA_MOCK_APP_BACKEND",
                "resource_name": "AppBackendEC2Role",
                "service": "IAM",
                "resource_type": "AWS::IAM::Role",
                "region": "global",
                "tags": {"Service": "PaymentsAPI"},
                "configuration": {
                    "trust_principal": "ec2.amazonaws.com",
                    "attached_policies": ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"],
                    "inline_wildcard_admin": False,
                },
            },
            {
                "resource_arn": f"arn:aws:ec2:{primary}:{aws_account_id}:security-group/sg-0a91b82c7d6e5f401",
                "resource_id": "sg-0a91b82c7d6e5f401",
                "resource_name": "prod-bastion-open-sg",
                "service": "EC2",
                "resource_type": "AWS::EC2::SecurityGroup",
                "region": primary,
                "tags": {"Name": "prod-bastion-open-sg"},
                "configuration": {
                    "vpc_id": "vpc-0123456789abcdef0",
                    "ingress_rules": [
                        {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"},
                        {"protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr": "0.0.0.0/0"},
                        {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"},
                    ],
                },
            },
            {
                "resource_arn": f"arn:aws:ec2:{primary}:{aws_account_id}:instance/i-0f8e7d6c5b4a32109",
                "resource_id": "i-0f8e7d6c5b4a32109",
                "resource_name": "legacy-api-node-01",
                "service": "EC2",
                "resource_type": "AWS::EC2::Instance",
                "region": primary,
                "tags": {"Name": "legacy-api-node-01"},
                "configuration": {"instance_type": "t3.micro", "imdsv2_required": False},
            },
            {
                "resource_arn": f"arn:aws:ec2:{primary}:{aws_account_id}:volume/vol-0987654321fedcba0",
                "resource_id": "vol-0987654321fedcba0",
                "resource_name": "legacy-api-root-vol",
                "service": "EC2",
                "resource_type": "AWS::EC2::Volume",
                "region": primary,
                "tags": {"AttachedTo": "i-0f8e7d6c5b4a32109"},
                "configuration": {"encrypted": False, "size_gb": 30, "volume_type": "gp3"},
            },
            {
                "resource_arn": f"arn:aws:cloudtrail:{primary}:{aws_account_id}:trail/org-management-trail",
                "resource_id": "org-management-trail",
                "resource_name": "org-management-trail",
                "service": "CloudTrail",
                "resource_type": "AWS::CloudTrail::Trail",
                "region": primary,
                "tags": {"Scope": "Organization"},
                "configuration": {"is_multi_region_trail": True, "is_logging": False},
            },
        ]

    @staticmethod
    def _get_live_inventory(
        aws_account_id: str,
        regions: list[str],
        role_arn: str | None,
        external_id: str | None,
    ) -> list[dict[str, Any]]:
        if not role_arn:
            raise ValueError("Live discovery requires an IAM Role ARN.")
        primary_region = regions[0] if regions else "ap-south-1"
        sts = boto3.client("sts", region_name=primary_region)
        assume_kwargs: dict[str, Any] = {
            "RoleArn": role_arn,
            "RoleSessionName": "VaultMeshDiscoverySession",
            "DurationSeconds": 900,
        }
        if external_id:
            assume_kwargs["ExternalId"] = external_id
        creds = sts.assume_role(**assume_kwargs)["Credentials"]
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
        discovered: list[dict[str, Any]] = []
        try:
            s3 = session.client("s3")
            for b in s3.list_buckets().get("Buckets", []):
                bname = b["Name"]
                pab = {}
                try:
                    pab = s3.get_public_access_block(Bucket=bname)["PublicAccessBlockConfiguration"]
                except ClientError:
                    pass
                enc_enabled = False
                try:
                    s3.get_bucket_encryption(Bucket=bname)
                    enc_enabled = True
                except ClientError:
                    pass
                discovered.append({
                    "resource_arn": f"arn:aws:s3:::{bname}",
                    "resource_id": bname,
                    "resource_name": bname,
                    "service": "S3",
                    "resource_type": "AWS::S3::Bucket",
                    "region": "global",
                    "tags": {},
                    "configuration": {
                        "block_public_acls": pab.get("BlockPublicAcls", False),
                        "block_public_policy": pab.get("BlockPublicPolicy", False),
                        "ignore_public_acls": pab.get("IgnorePublicAcls", False),
                        "restrict_public_buckets": pab.get("RestrictPublicBuckets", False),
                        "encryption_enabled": enc_enabled,
                    },
                })
        except (ClientError, BotoCoreError):
            pass
        return discovered
