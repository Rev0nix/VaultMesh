from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.analyzers.iam_analyzer import IAMAnalyzerService
from app.analyzers.network_analyzer import NetworkAnalyzerService
from app.api.deps import get_current_user, get_db
from app.models.domain import AWSAccount, CloudResource, User

router = APIRouter(prefix="/analyzers", tags=["IAM & Network Analyzers"])


def _get_org_resources(db: Session, org_id: int) -> list[CloudResource]:
    return (
        db.query(CloudResource)
        .join(AWSAccount, CloudResource.aws_account_id == AWSAccount.id)
        .filter(AWSAccount.organization_id == org_id)
        .all()
    )


@router.get("/iam")
def get_iam_analysis(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Run deep least-privilege and trust analysis across discovered IAM Users and Roles."""
    resources = _get_org_resources(db, current_user.organization_id)
    return IAMAnalyzerService.analyze_iam_resources(resources)


@router.get("/network")
def get_network_analysis(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Analyze VPC Security Group ingress rules and public internet port exposure."""
    resources = _get_org_resources(db, current_user.organization_id)
    return NetworkAnalyzerService.analyze_network_resources(resources)
