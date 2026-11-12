from datetime import datetime, timezone
import secrets
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from app.api.deps import get_current_user, get_db, require_roles
from app.integrations.aws_sts import AWSSTSClient
from app.models.domain import AuditLog, AWSAccount, AWSRegion, User, UserRole
from app.schemas.account import (
    AWSAccountCreateRequest,
    AWSAccountResponse,
    ConnectionValidationResponse,
)

router = APIRouter(prefix="/accounts", tags=["AWS Cloud Accounts"])


@router.get("/onboarding-template")
def get_iam_onboarding_template(current_user: User = Depends(get_current_user)):
    """Generate a unique ExternalId and least-privilege IAM Read-Only policy for AWS onboarding."""
    external_id = f"vm-ext-{current_user.organization_id}-{secrets.token_hex(8)}"
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::<YOUR_TRUSTED_PRINCIPAL_ACCOUNT>:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }
        ],
    }
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "VaultMeshReadOnlyCSPM",
                "Effect": "Allow",
                "Action": [
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
                    "cloudtrail:LookupEvents",
                ],
                "Resource": "*",
            }
        ],
    }
    return {
        "suggested_role_name": "VaultMeshSecurityAuditRole",
        "generated_external_id": external_id,
        "trust_policy": trust_policy,
        "permissions_policy": permissions_policy,
    }


@router.get("", response_model=list[AWSAccountResponse])
def list_aws_accounts(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all AWS accounts connected to the current user's organization."""
    return (
        db.query(AWSAccount)
        .filter(AWSAccount.organization_id == current_user.organization_id)
        .order_by(AWSAccount.created_at.desc())
        .all()
    )


@router.post("", response_model=AWSAccountResponse, status_code=status.HTTP_201_CREATED)
def connect_aws_account(
    payload: AWSAccountCreateRequest,
    request: Request,
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.SECURITY_ANALYST)),
    db: Session = Depends(get_db),
):
    """Connect and verify a Sandbox Mock or Live AWS account via STS AssumeRole."""
    existing = (
        db.query(AWSAccount)
        .filter(
            AWSAccount.organization_id == current_user.organization_id,
            AWSAccount.aws_account_id == payload.aws_account_id,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"AWS Account {payload.aws_account_id} is already connected to this organization.",
        )

    sts_result = AWSSTSClient.validate_and_assume_role(
        aws_account_id=payload.aws_account_id,
        role_arn=payload.role_arn,
        external_id=payload.external_id,
        region=payload.default_region,
        is_mock=payload.is_mock,
    )

    if not sts_result.success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=sts_result.message,
        )

    account = AWSAccount(
        organization_id=current_user.organization_id,
        aws_account_id=payload.aws_account_id,
        alias=payload.alias.strip(),
        role_arn=payload.role_arn,
        external_id=payload.external_id,
        default_region=payload.default_region,
        is_mock=payload.is_mock,
        connection_status=sts_result.status,
        last_synced_at=sts_result.validated_at,
    )
    db.add(account)
    db.flush()

    unique_regions = list(dict.fromkeys([payload.default_region, *payload.regions]))
    for reg in unique_regions:
        db.add(AWSRegion(aws_account_id=account.id, region_code=reg, is_enabled=True))

    db.add(
        AuditLog(
            organization_id=current_user.organization_id,
            actor_user_id=current_user.id,
            action="AWS_ACCOUNT_CONNECTED",
            target_type="AWSAccount",
            target_id=payload.aws_account_id,
            ip_address=request.client.host if request.client else "unknown",
            details={
                "alias": account.alias,
                "is_mock": account.is_mock,
                "caller_arn": sts_result.caller_arn,
            },
        )
    )
    db.commit()
    db.refresh(account)
    return account


@router.post("/{account_id}/validate", response_model=ConnectionValidationResponse)
def revalidate_aws_account(
    account_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Re-verify STS AssumeRole connectivity for an existing AWS account."""
    account = (
        db.query(AWSAccount)
        .filter(
            AWSAccount.id == account_id,
            AWSAccount.organization_id == current_user.organization_id,
        )
        .first()
    )
    if not account:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AWS account not found.")

    result = AWSSTSClient.validate_and_assume_role(
        aws_account_id=account.aws_account_id,
        role_arn=account.role_arn,
        external_id=account.external_id,
        region=account.default_region,
        is_mock=account.is_mock,
    )

    account.connection_status = result.status
    if result.success:
        account.last_synced_at = result.validated_at

    db.add(
        AuditLog(
            organization_id=current_user.organization_id,
            actor_user_id=current_user.id,
            action="AWS_ACCOUNT_VALIDATED",
            target_type="AWSAccount",
            target_id=account.aws_account_id,
            ip_address=request.client.host if request.client else "unknown",
            details={"status": result.status, "message": result.message},
        )
    )
    db.commit()

    return ConnectionValidationResponse(
        account_id=account.id,
        aws_account_id=account.aws_account_id,
        is_mock=account.is_mock,
        status=result.status,
        caller_arn=result.caller_arn,
        message=result.message,
        validated_at=result.validated_at,
    )


@router.delete("/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
def disconnect_aws_account(
    account_id: int,
    request: Request,
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    """Disconnect an AWS account (ADMIN only). Cascades resources and findings."""
    account = (
        db.query(AWSAccount)
        .filter(
            AWSAccount.id == account_id,
            AWSAccount.organization_id == current_user.organization_id,
        )
        .first()
    )
    if not account:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AWS account not found.")

    aws_id = account.aws_account_id
    db.delete(account)
    db.add(
        AuditLog(
            organization_id=current_user.organization_id,
            actor_user_id=current_user.id,
            action="AWS_ACCOUNT_DISCONNECTED",
            target_type="AWSAccount",
            target_id=aws_id,
            ip_address=request.client.host if request.client else "unknown",
            details={},
        )
    )
    db.commit()
    return None
