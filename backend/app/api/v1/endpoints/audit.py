from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.api.deps import get_current_user, get_db
from app.models.domain import AuditLog, User

router = APIRouter(prefix="/audit", tags=["Audit Logs & Governance"])


@router.get("/logs")
def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return chronological security & governance audit logs for the organization."""
    logs = (
        db.query(AuditLog)
        .filter(AuditLog.organization_id == current_user.organization_id)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
        .all()
    )
    user_map = {
        u.id: u.email
        for u in db.query(User).filter(User.organization_id == current_user.organization_id).all()
    }
    return [
        {
            "id": log.id,
            "actor_email": user_map.get(log.actor_user_id, "system"),
            "action": log.action,
            "target_type": log.target_type,
            "target_id": log.target_id,
            "ip_address": log.ip_address,
            "details": log.details,
            "created_at": log.created_at.isoformat(),
        }
        for log in logs
    ]


@router.get("/team")
def list_organization_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List team members and their RBAC roles inside the organization."""
    users = (
        db.query(User)
        .filter(User.organization_id == current_user.organization_id)
        .order_by(User.created_at.asc())
        .all()
    )
    return [
        {
            "id": u.id,
            "email": u.email,
            "full_name": u.full_name,
            "role": u.role.value,
            "is_active": u.is_active,
            "created_at": u.created_at.isoformat(),
        }
        for u in users
    ]
