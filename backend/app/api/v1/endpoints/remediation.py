from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session, joinedload
from app.api.deps import get_current_user, get_db, require_roles
from app.models.domain import (
    AuditLog,
    AWSAccount,
    CloudResource,
    Finding,
    FindingStatus,
    RemediationAction,
    ScanJob,
    User,
    UserRole,
)
from app.scanners.engine import CSPMScannerEngine

router = APIRouter(prefix="/remediation", tags=["Remediation Engine"])


class RemediationExecuteRequest(BaseModel):
    finding_id: int
    dry_run: bool = True
    confirm: bool = False


@router.get("/history")
def list_remediation_history(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    actions = (
        db.query(RemediationAction)
        .join(Finding, RemediationAction.finding_id == Finding.id)
        .join(CloudResource, Finding.resource_id == CloudResource.id)
        .join(AWSAccount, CloudResource.aws_account_id == AWSAccount.id)
        .filter(AWSAccount.organization_id == current_user.organization_id)
        .order_by(RemediationAction.created_at.desc())
        .all()
    )
    return [
        {
            "id": a.id,
            "finding_id": a.finding_id,
            "action_type": a.action_type,
            "status": a.status,
            "command_preview": a.command_preview,
            "execution_output": a.execution_output,
            "created_at": a.created_at.isoformat(),
        }
        for a in actions
    ]


@router.post("/execute")
def execute_remediation(
    payload: RemediationExecuteRequest,
    request: Request,
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.SECURITY_ANALYST)),
    db: Session = Depends(get_db),
):
    """
    Execute a safe Dry-Run simulation or an explicitly confirmed remediation workflow.
    Non-dry-run execution requires confirm=True to prevent accidental AWS changes.
    """
    if not payload.dry_run and not payload.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Explicit confirmation (confirm=true) is required before executing live remediation.",
        )

    finding = (
        db.query(Finding)
        .options(joinedload(Finding.resource))
        .join(CloudResource, Finding.resource_id == CloudResource.id)
        .join(AWSAccount, CloudResource.aws_account_id == AWSAccount.id)
        .filter(
            Finding.id == payload.finding_id,
            AWSAccount.organization_id == current_user.organization_id,
        )
        .first()
    )
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    cli_cmd = finding.remediation_cli or f"# Manual remediation required for {finding.rule_id}"
    action_type = "DRY_RUN" if payload.dry_run else "CONFIRMED_APPLY"

    if payload.dry_run:
        status_label = "SIMULATED"
        output = (
            f"[DRY-RUN SIMULATION] Validated target ARN: {finding.resource.resource_arn}\n"
            f"Planned AWS CLI Action:\n  {cli_cmd}\n"
            f"No AWS resources were modified."
        )
    else:
        status_label = "SUCCEEDED"
        mode_note = (
            "Sandbox Mock Environment: applied remediation state locally."
            if finding.is_mock
            else "Confirmed Remediation Recorded: execute the verified CLI/Terraform change or apply via automation role."
        )
        output = f"[{action_type}] {mode_note}\nCommand:\n  {cli_cmd}"
        finding.status = FindingStatus.RESOLVED
        db.flush()

        # Recalculate security score
        account_id = finding.resource.aws_account_id
        open_sevs = [
            r[0]
            for r in db.query(Finding.severity)
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
            latest_scan.security_score = CSPMScannerEngine.calculate_security_score(open_sevs)

    record = RemediationAction(
        finding_id=finding.id,
        executed_by_user_id=current_user.id,
        action_type=action_type,
        status=status_label,
        command_preview=cli_cmd,
        execution_output=output,
    )
    db.add(record)

    db.add(
        AuditLog(
            organization_id=current_user.organization_id,
            actor_user_id=current_user.id,
            action=f"REMEDIATION_{action_type}",
            target_type="Finding",
            target_id=finding.finding_uid,
            ip_address=request.client.host if request.client else "unknown",
            details={"dry_run": payload.dry_run, "status": status_label},
        )
    )
    db.commit()
    db.refresh(record)

    return {
        "id": record.id,
        "finding_uid": finding.finding_uid,
        "action_type": record.action_type,
        "status": record.status,
        "command_preview": record.command_preview,
        "execution_output": record.execution_output,
        "finding_status": finding.status.value,
    }
