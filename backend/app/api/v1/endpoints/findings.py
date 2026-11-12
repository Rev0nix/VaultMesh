from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session, joinedload
from app.api.deps import get_current_user, get_db, require_roles
from app.models.domain import (
    AuditLog,
    AWSAccount,
    CloudResource,
    Finding,
    FindingStatus,
    ScanJob,
    SeverityLevel,
    User,
    UserRole,
)
from app.scanners.engine import CSPMScannerEngine
from app.schemas.scan import FindingResponse, FindingUpdateRequest

router = APIRouter(prefix="/findings", tags=["Security Findings"])


@router.get("", response_model=list[FindingResponse])
def list_findings(
    severity: SeverityLevel | None = Query(default=None),
    finding_status: FindingStatus | None = Query(default=None, alias="status"),
    service: str | None = Query(default=None),
    search: str | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List security findings for the organization with optional filtering."""
    query = (
        db.query(Finding)
        .options(joinedload(Finding.resource))
        .join(CloudResource, Finding.resource_id == CloudResource.id)
        .join(AWSAccount, CloudResource.aws_account_id == AWSAccount.id)
        .filter(AWSAccount.organization_id == current_user.organization_id)
    )

    if severity:
        query = query.filter(Finding.severity == severity)
    if finding_status:
        query = query.filter(Finding.status == finding_status)
    if service:
        query = query.filter(CloudResource.service == service.upper())
    if search:
        like_term = f"%{search.strip()}%"
        query = query.filter(
            (Finding.title.ilike(like_term))
            | (Finding.rule_id.ilike(like_term))
            | (CloudResource.resource_arn.ilike(like_term))
        )

    return query.order_by(Finding.detected_at.desc()).all()


@router.patch("/{finding_id}", response_model=FindingResponse)
def update_finding(
    finding_id: int,
    payload: FindingUpdateRequest,
    request: Request,
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.SECURITY_ANALYST)),
    db: Session = Depends(get_db),
):
    """Update finding status (RESOLVED, RISK_ACCEPTED, OPEN) or add investigation notes."""
    finding = (
        db.query(Finding)
        .options(joinedload(Finding.resource))
        .join(CloudResource, Finding.resource_id == CloudResource.id)
        .join(AWSAccount, CloudResource.aws_account_id == AWSAccount.id)
        .filter(
            Finding.id == finding_id,
            AWSAccount.organization_id == current_user.organization_id,
        )
        .first()
    )
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    old_status = finding.status.value
    if payload.status is not None:
        finding.status = payload.status
    if payload.investigation_notes is not None:
        finding.investigation_notes = payload.investigation_notes.strip()

    db.flush()
    # Recalculate latest scan posture score dynamically based on remaining open findings
    account_id = finding.resource.aws_account_id
    open_severities = [
        row[0]
        for row in db.query(Finding.severity)
        .join(CloudResource, Finding.resource_id == CloudResource.id)
        .filter(
            CloudResource.aws_account_id == account_id,
            Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
        )
        .all()
    ]
    latest_scan = (
        db.query(ScanJob)
        .filter(ScanJob.aws_account_id == account_id)
        .order_by(ScanJob.started_at.desc())
        .first()
    )
    if latest_scan:
        latest_scan.security_score = CSPMScannerEngine.calculate_security_score(open_severities)

    db.add(
        AuditLog(
            organization_id=current_user.organization_id,
            actor_user_id=current_user.id,
            action="FINDING_UPDATED",
            target_type="Finding",
            target_id=finding.finding_uid,
            ip_address=request.client.host if request.client else "unknown",
            details={
                "old_status": old_status,
                "new_status": finding.status.value,
                "notes_updated": payload.investigation_notes is not None,
            },
        )
    )
    db.commit()
    db.refresh(finding)
    return finding
