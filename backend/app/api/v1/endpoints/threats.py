from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.api.deps import get_current_user, get_db, require_roles
from app.detectors.cloudtrail_detector import CloudTrailThreatDetector
from app.models.domain import AuditLog, AWSAccount, ThreatEvent, User, UserRole

router = APIRouter(prefix="/threats", tags=["Threat Detection"])


class ThreatAnalyzeRequest(BaseModel):
    aws_account_id: int


@router.get("")
def list_threat_events(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List detected CloudTrail threat events for the organization."""
    events = (
        db.query(ThreatEvent)
        .join(AWSAccount, ThreatEvent.aws_account_id == AWSAccount.id)
        .filter(AWSAccount.organization_id == current_user.organization_id)
        .order_by(ThreatEvent.occurred_at.desc())
        .all()
    )
    return [
        {
            "id": e.id,
            "aws_account_id": e.aws_account_id,
            "event_id": e.event_id,
            "event_name": e.event_name,
            "event_source": e.event_source,
            "actor_arn": e.actor_arn,
            "source_ip": e.source_ip,
            "region": e.region,
            "severity": e.severity.value,
            "rule_triggered": e.rule_triggered,
            "explanation": e.explanation,
            "raw_event": e.raw_event,
            "is_mock": e.is_mock,
            "occurred_at": e.occurred_at.isoformat(),
        }
        for e in events
    ]


@router.post("/analyze", status_code=status.HTTP_201_CREATED)
def analyze_cloudtrail_threats(
    payload: ThreatAnalyzeRequest,
    request: Request,
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.SECURITY_ANALYST)),
    db: Session = Depends(get_db),
):
    """Ingest CloudTrail events and run explainable threat detection rules."""
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

    raw_events = CloudTrailThreatDetector.fetch_events(
        aws_account_id=account.aws_account_id,
        region=account.default_region,
        is_mock=account.is_mock,
        role_arn=account.role_arn,
        external_id=account.external_id,
    )
    alerts = CloudTrailThreatDetector.evaluate_events(raw_events, account.default_region)

    newly_created = 0
    for alert in alerts:
        existing = db.query(ThreatEvent).filter(ThreatEvent.event_id == alert["event_id"]).first()
        if existing is None:
            db.add(
                ThreatEvent(
                    aws_account_id=account.id,
                    event_id=alert["event_id"],
                    event_name=alert["event_name"],
                    event_source=alert["event_source"],
                    actor_arn=alert["actor_arn"],
                    source_ip=alert["source_ip"],
                    region=alert["region"],
                    severity=alert["severity"],
                    rule_triggered=alert["rule_triggered"],
                    explanation=alert["explanation"],
                    raw_event=alert["raw_event"],
                    is_mock=account.is_mock,
                    occurred_at=alert["occurred_at"],
                )
            )
            newly_created += 1

    db.add(
        AuditLog(
            organization_id=current_user.organization_id,
            actor_user_id=current_user.id,
            action="THREAT_ANALYSIS_EXECUTED",
            target_type="AWSAccount",
            target_id=account.aws_account_id,
            ip_address=request.client.host if request.client else "unknown",
            details={
                "events_inspected": len(raw_events),
                "alerts_matched": len(alerts),
                "new_alerts_saved": newly_created,
            },
        )
    )
    db.commit()

    return {
        "events_inspected": len(raw_events),
        "alerts_matched": len(alerts),
        "new_alerts_saved": newly_created,
    }
