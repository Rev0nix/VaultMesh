from dataclasses import dataclass
from datetime import datetime, timezone
import boto3
from botocore.exceptions import BotoCoreError, ClientError


@dataclass
class STSValidationResult:
    success: bool
    status: str
    caller_arn: str
    message: str
    validated_at: datetime
    temporary_credentials: dict | None = None


class AWSSTSClient:
    """
    Handles AWS account verification using temporary STS AssumeRole credentials.
    Supports offline Mock Mode (₹0) and Live AWS Mode without storing static keys.
    """

    @staticmethod
    def validate_and_assume_role(
        aws_account_id: str,
        role_arn: str | None,
        external_id: str | None,
        region: str,
        is_mock: bool,
    ) -> STSValidationResult:
        now = datetime.now(timezone.utc)

        if is_mock:
            simulated_arn = role_arn or f"arn:aws:sts::{aws_account_id}:assumed-role/VaultMeshMockAuditRole/vaultmesh-session"
            return STSValidationResult(
                success=True,
                status="CONNECTED",
                caller_arn=simulated_arn,
                message="Sandbox Mock STS session verified (offline ₹0 simulation mode).",
                validated_at=now,
                temporary_credentials={
                    "AccessKeyId": "ASIA_MOCK_TEMPORARY_KEY",
                    "SecretAccessKey": "MOCK_SECRET_KEY",
                    "SessionToken": "MOCK_SESSION_TOKEN",
                },
            )

        if not role_arn:
            return STSValidationResult(
                success=False,
                status="ERROR",
                caller_arn="",
                message="Live AWS integration requires a valid IAM Role ARN.",
                validated_at=now,
            )

        if f":{aws_account_id}:" not in role_arn:
            return STSValidationResult(
                success=False,
                status="ERROR",
                caller_arn="",
                message="Role ARN account ID does not match the provided 12-digit AWS Account ID.",
                validated_at=now,
            )

        try:
            sts_base = boto3.client("sts", region_name=region)
            assume_kwargs = {
                "RoleArn": role_arn,
                "RoleSessionName": "VaultMeshSecurityAuditSession",
                "DurationSeconds": 900,  # Least-privilege 15-minute session
            }
            if external_id:
                assume_kwargs["ExternalId"] = external_id

            assumed = sts_base.assume_role(**assume_kwargs)
            creds = assumed["Credentials"]

            # Verify identity using the newly issued temporary credentials
            sts_assumed = boto3.client(
                "sts",
                region_name=region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
            identity = sts_assumed.get_caller_identity()

            if identity.get("Account") != aws_account_id:
                return STSValidationResult(
                    success=False,
                    status="ERROR",
                    caller_arn=identity.get("Arn", ""),
                    message="Assumed role belongs to a different AWS account ID.",
                    validated_at=now,
                )

            return STSValidationResult(
                success=True,
                status="CONNECTED",
                caller_arn=identity["Arn"],
                message="Live AWS STS AssumeRole verified with 15-minute temporary credentials.",
                validated_at=now,
                temporary_credentials=creds,
            )

        except (ClientError, BotoCoreError) as exc:
            return STSValidationResult(
                success=False,
                status="FAILED",
                caller_arn="",
                message=f"AWS STS AssumeRole failed: {str(exc)}",
                validated_at=now,
            )
