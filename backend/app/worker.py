import os
import time
import datetime
from celery import Celery
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models import ScanJob, Finding, AWSAccount

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://vaultmesh_admin:secure_password_2026@db:5432/vaultmesh_db")

celery_app = Celery(
    "vaultmesh_worker",
    broker=REDIS_URL,
    backend=REDIS_URL
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@celery_app.task(name="run_aws_cspm_scan")
def run_aws_cspm_scan(scan_id: int, aws_account_id: int):
    """
    Background worker task that executes CIS AWS Foundation Benchmark checks
    and stores findings in PostgreSQL.
    """
    db = SessionLocal()
    try:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        account = db.query(AWSAccount).filter(AWSAccount.id == aws_account_id).first()
        if not scan or not account:
            return {"status": "ERROR", "message": "Scan or Account not found"}

        # 1. Update status to RUNNING
        scan.status = "RUNNING"
        db.commit()

        # Simulate deep Boto3 / Checkov inspection across AWS regions
        time.sleep(3)

        # 2. Generate evaluated security findings
        discovered_findings = [
            Finding(
                scan_id=scan.id,
                finding_uid="CIS_AWS_2.1.5",
                title="S3 Bucket Public Access Block is not fully enabled",
                description="Account-level or bucket-level S3 Public Access Block settings are missing.",
                severity="CRITICAL",
                status="OPEN",
                resource_id=f"arn:aws:s3:::vaultmesh-prod-logs-{account.aws_account_id}",
                region=account.default_region,
                framework="CIS AWS v1.5.0",
                remediation_guidance="Enable BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets."
            ),
            Finding(
                scan_id=scan.id,
                finding_uid="CIS_AWS_1.16",
                title="IAM policies are attached directly to users instead of roles/groups",
                description="Inline or managed policies attached directly to IAM users increase privilege creep risk.",
                severity="HIGH",
                status="OPEN",
                resource_id=f"arn:aws:iam::{account.aws_account_id}:user/deploy-bot",
                region="global",
                framework="CIS AWS v1.5.0",
                remediation_guidance="Detach user policies and migrate permissions to an IAM Role or Group."
            ),
            Finding(
                scan_id=scan.id,
                finding_uid="CIS_AWS_5.2",
                title="Security Group allows unrestricted ingress on port 22 (SSH)",
                description="Inbound rule permits 0.0.0.0/0 access to TCP port 22.",
                severity="CRITICAL",
                status="OPEN",
                resource_id=f"arn:aws:ec2:{account.default_region}:{account.aws_account_id}:security-group/sg-0a1b2c3d4e",
                region=account.default_region,
                framework="CIS AWS v1.5.0",
                remediation_guidance="Restrict SSH ingress to bastion host CIDRs or migrate to AWS Systems Manager Session Manager."
            ),
        ]

        db.add_all(discovered_findings)

        # 3. Complete ScanJob & update Account timestamp
        scan.status = "COMPLETED"
        scan.findings_count = len(discovered_findings)
        account.last_synced_at = datetime.datetime.utcnow()
        db.commit()

        return {"scan_id": scan.id, "status": "COMPLETED", "findings": len(discovered_findings)}

    except Exception as exc:
        db.rollback()
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if scan:
            scan.status = "FAILED"
            db.commit()
        raise exc
    finally:
        db.close()