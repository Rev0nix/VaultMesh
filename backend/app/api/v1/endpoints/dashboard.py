from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.api.deps import get_current_user, get_db
from app.core.config import settings
from app.models.domain import (
    AWSAccount,
    CloudResource,
    Finding,
    FindingStatus,
    ScanJob,
    SeverityLevel,
    ThreatEvent,
    User,
)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/overview")
def get_dashboard_overview(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Aggregate real-time security posture metrics from the database for the user's org."""
    org_id = current_user.organization_id

    account_ids_subq = (
        db.query(AWSAccount.id)
        .filter(AWSAccount.organization_id == org_id)
        .subquery()
    )

    accounts_count = db.query(func.count(AWSAccount.id)).filter(
        AWSAccount.organization_id == org_id
    ).scalar() or 0

    resources_count = db.query(func.count(CloudResource.id)).filter(
        CloudResource.aws_account_id.in_(account_ids_subq)
    ).scalar() or 0

    # Open findings grouped by severity
    open_findings_q = (
        db.query(Finding.severity, func.count(Finding.id))
        .join(CloudResource, Finding.resource_id == CloudResource.id)
        .filter(
            CloudResource.aws_account_id.in_(account_ids_subq),
            Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
        )
        .group_by(Finding.severity)
        .all()
    )

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }
    for sev, count in open_findings_q:
        key = sev.value if hasattr(sev, "value") else str(sev)
        if key in severity_counts:
            severity_counts[key] = count

    # Latest completed scan score (defaults to None if no scans have run yet)
    latest_scan = (
        db.query(ScanJob)
        .filter(ScanJob.aws_account_id.in_(account_ids_subq))
        .order_by(ScanJob.started_at.desc())
        .first()
    )

    recent_scans = (
        db.query(ScanJob)
        .filter(ScanJob.aws_account_id.in_(account_ids_subq))
        .order_by(ScanJob.started_at.desc())
        .limit(5)
        .all()
    )

    recent_threats = (
        db.query(ThreatEvent)
        .filter(ThreatEvent.aws_account_id.in_(account_ids_subq))
        .order_by(ThreatEvent.occurred_at.desc())
        .limit(5)
        .all()
    )

    # Resource breakdown by AWS service (S3, IAM, EC2, etc.)
    service_dist_rows = (
        db.query(CloudResource.service, func.count(CloudResource.id))
        .filter(CloudResource.aws_account_id.in_(account_ids_subq))
        .group_by(CloudResource.service)
        .all()
    )

    return {
        "organization_id": org_id,
        "aws_mode": settings.AWS_INTEGRATION_MODE,
        "has_scan_data": latest_scan is not None,
        "security_score": latest_scan.security_score if latest_scan else None,
        "aws_accounts_connected": accounts_count,
        "monitored_resources": resources_count,
        "findings_by_severity": severity_counts,
        "total_open_findings": sum(severity_counts.values()),
        "resource_distribution": [
            {"service": svc, "count": cnt} for svc, cnt in service_dist_rows
        ],
        "scan_history": [
            {
                "id": s.id,
                "status": s.status.value,
                "security_score": s.security_score,
                "findings_count": s.findings_count,
                "resources_scanned": s.resources_scanned,
                "is_mock": s.is_mock,
                "started_at": s.started_at.isoformat(),
            }
            for s in recent_scans
        ],
        "recent_threats": [
            {
                "id": t.id,
                "event_name": t.event_name,
                "severity": t.severity.value,
                "rule_triggered": t.rule_triggered,
                "region": t.region,
                "occurred_at": t.occurred_at.isoformat(),
            }
            for t in recent_threats
        ],
    }
