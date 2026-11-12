from datetime import datetime, timezone
import hashlib
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from app.api.deps import get_current_user, get_db, require_roles
from app.integrations.aws_discovery import AWSDiscoveryProvider
from app.models.domain import (
    AuditLog,
    AWSAccount,
    CloudResource,
    Finding,
    FindingStatus,
    ScanJob,
    ScanResult,
    ScanStatus,
    User,
    UserRole,
)
from app.scanners.engine import CSPMScannerEngine
from app.schemas.scan import ScanJobResponse, ScanTriggerRequest

router = APIRouter(prefix="/scans", tags=["Security Scans"])


@router.get("", response_model=list[ScanJobResponse])
def list_scan_jobs(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List security scan jobs for the user's organization."""
    return (
        db.query(ScanJob)
        .join(AWSAccount, ScanJob.aws_account_id == AWSAccount.id)
        .filter(AWSAccount.organization_id == current_user.organization_id)
        .order_by(ScanJob.started_at.desc())
        .all()
    )


@router.post("/run", response_model=ScanJobResponse, status_code=status.HTTP_201_CREATED)
def run_security_scan(
    payload: ScanTriggerRequest,
    request: Request,
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.SECURITY_ANALYST)),
    db: Session = Depends(get_db),
):
    """Discover cloud resources and run CSPM security scanners on an AWS account."""
    account = (
        db.query(AWSAccount)
        .filter(
            AWSAccount.id == payload.aws_account_id,
            AWSAccount.organization_id == current_user.organization_id,
        )
        .first()
    )
    if not account:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AWS account not found.")

    enabled_regions = [r.region_code for r in account.regions if r.is_enabled] or [account.default_region]

    scan_job = ScanJob(
        aws_account_id=account.id,
        triggered_by_user_id=current_user.id,
        status=ScanStatus.RUNNING,
        regions_scanned=enabled_regions,
        is_mock=account.is_mock,
    )
    db.add(scan_job)
    db.flush()

    try:
        raw_resources = AWSDiscoveryProvider.discover_resources(
            aws_account_id=account.aws_account_id,
            regions=enabled_regions,
            is_mock=account.is_mock,
            role_arn=account.role_arn,
            external_id=account.external_id,
        )

        generated_findings_severities = []
        checks_passed = 0
        checks_failed = 0

        for item in raw_resources:
            resource = (
                db.query(CloudResource)
                .filter(
                    CloudResource.aws_account_id == account.id,
                    CloudResource.resource_arn == item["resource_arn"],
                )
                .first()
            )
            if resource is None:
                resource = CloudResource(
                    aws_account_id=account.id,
                    resource_arn=item["resource_arn"],
                    resource_id=item["resource_id"],
                    resource_name=item.get("resource_name"),
                    service=item["service"],
                    resource_type=item["resource_type"],
                    region=item["region"],
                    configuration=item.get("configuration", {}),
                    tags=item.get("tags", {}),
                    is_mock=account.is_mock,
                )
                db.add(resource)
                db.flush()
            else:
                resource.configuration = item.get("configuration", {})
                resource.tags = item.get("tags", {})
                resource.is_mock = account.is_mock

            evaluated = CSPMScannerEngine.evaluate_resource(resource)
            if not evaluated:
                checks_passed += 1
            else:
                checks_failed += len(evaluated)

            for ef in evaluated:
                # Deterministic UID per (account, resource_arn, rule_id) so re-scans preserve analyst status/notes!
                digest = hashlib.sha256(
                    f"{account.id}:{resource.resource_arn}:{ef.rule_id}".encode("utf-8")
                ).hexdigest()[:10]
                finding_uid = f"VM-{ef.rule_id[:6]}-{digest}".upper()

                existing_finding = (
                    db.query(Finding).filter(Finding.finding_uid == finding_uid).first()
                )
                if existing_finding:
                    existing_finding.scan_job_id = scan_job.id
                    existing_finding.evidence = ef.evidence
                    existing_finding.detected_at = datetime.now(timezone.utc)
                    if existing_finding.status in (FindingStatus.OPEN, FindingStatus.IN_PROGRESS):
                        generated_findings_severities.append(existing_finding.severity)
                else:
                    new_finding = Finding(
                        finding_uid=finding_uid,
                        scan_job_id=scan_job.id,
                        resource_id=resource.id,
                        rule_id=ef.rule_id,
                        title=ef.title,
                        description=ef.description,
                        severity=ef.severity,
                        status=FindingStatus.OPEN,
                        evidence=ef.evidence,
                        remediation_summary=ef.remediation_summary,
                        remediation_cli=ef.remediation_cli,
                        remediation_terraform=ef.remediation_terraform,
                        aws_doc_url=ef.aws_doc_url,
                        is_mock=account.is_mock,
                    )
                    db.add(new_finding)
                    generated_findings_severities.append(ef.severity)

        score = CSPMScannerEngine.calculate_security_score(generated_findings_severities)

        db.add(
            ScanResult(
                scan_job_id=scan_job.id,
                scanner_name="UnifiedMultiServiceScanner",
                checks_passed=checks_passed,
                checks_failed=checks_failed,
                raw_summary={
                    "resources_discovered": len(raw_resources),
                    "open_findings": len(generated_findings_severities),
                },
            )
        )

        scan_job.status = ScanStatus.COMPLETED
        scan_job.resources_scanned = len(raw_resources)
        scan_job.findings_count = len(generated_findings_severities)
        scan_job.security_score = score
        scan_job.completed_at = datetime.now(timezone.utc)
        account.last_synced_at = datetime.now(timezone.utc)

        db.add(
            AuditLog(
                organization_id=current_user.organization_id,
                actor_user_id=current_user.id,
                action="SECURITY_SCAN_COMPLETED",
                target_type="ScanJob",
                target_id=str(scan_job.id),
                ip_address=request.client.host if request.client else "unknown",
                details={
                    "aws_account_id": account.aws_account_id,
                    "resources_scanned": len(raw_resources),
                    "findings_count": len(generated_findings_severities),
                    "security_score": score,
                    "is_mock": account.is_mock,
                },
            )
        )
        db.commit()
        db.refresh(scan_job)
        return scan_job

    except Exception as exc:
        scan_job.status = ScanStatus.FAILED
        scan_job.error_message = str(exc)
        scan_job.completed_at = datetime.now(timezone.utc)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Security scan failed: {str(exc)}",
        )
