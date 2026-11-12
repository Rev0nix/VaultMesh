import json
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session, joinedload
from app.api.deps import get_current_user, get_db
from app.api.v1.endpoints.dashboard import get_dashboard_overview
from app.models.domain import (
    AuditLog,
    AWSAccount,
    CloudResource,
    Finding,
    Organization,
    ThreatEvent,
    User,
)
from app.reports.generator import SecurityReportGenerator

router = APIRouter(prefix="/reports", tags=["Executive Reports"])


@router.get("/export")
def export_security_report(
    request: Request,
    fmt: str = Query(default="json", pattern="^(json|pdf)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate and download a complete JSON or PDF security assessment report."""
    org = db.query(Organization).filter(Organization.id == current_user.organization_id).first()
    overview = get_dashboard_overview(current_user=current_user, db=db)

    findings_rows = (
        db.query(Finding)
        .options(joinedload(Finding.resource))
        .join(CloudResource, Finding.resource_id == CloudResource.id)
        .join(AWSAccount, CloudResource.aws_account_id == AWSAccount.id)
        .filter(AWSAccount.organization_id == current_user.organization_id)
        .order_by(Finding.detected_at.desc())
        .all()
    )
    findings_payload = [
        {
            "finding_uid": f.finding_uid,
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity.value,
            "status": f.status.value,
            "resource_arn": f.resource.resource_arn,
            "evidence": f.evidence,
            "remediation_summary": f.remediation_summary,
            "remediation_cli": f.remediation_cli,
            "detected_at": f.detected_at.isoformat(),
        }
        for f in findings_rows
    ]

    threats_rows = (
        db.query(ThreatEvent)
        .join(AWSAccount, ThreatEvent.aws_account_id == AWSAccount.id)
        .filter(AWSAccount.organization_id == current_user.organization_id)
        .order_by(ThreatEvent.occurred_at.desc())
        .all()
    )
    threats_payload = [
        {
            "event_id": t.event_id,
            "event_name": t.event_name,
            "severity": t.severity.value,
            "rule_triggered": t.rule_triggered,
            "source_ip": t.source_ip,
            "explanation": t.explanation,
            "occurred_at": t.occurred_at.isoformat(),
        }
        for t in threats_rows
    ]

    report_data = SecurityReportGenerator.build_json_payload(
        org_name=org.name if org else "VaultMesh Organization",
        generated_by=current_user.email,
        overview=overview,
        findings=findings_payload,
        threats=threats_payload,
    )

    db.add(
        AuditLog(
            organization_id=current_user.organization_id,
            actor_user_id=current_user.id,
            action="SECURITY_REPORT_EXPORTED",
            target_type="Report",
            target_id=fmt.upper(),
            ip_address=request.client.host if request.client else "unknown",
            details={"format": fmt, "findings_included": len(findings_payload)},
        )
    )
    db.commit()

    if fmt == "pdf":
        pdf_bytes = SecurityReportGenerator.build_pdf_bytes(report_data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="vaultmesh-security-report.pdf"'},
        )

    return Response(
        content=json.dumps(report_data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="vaultmesh-security-report.json"'},
    )
