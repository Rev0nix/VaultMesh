from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.api.deps import get_current_user, get_db
from app.models.domain import AWSAccount, CloudResource, Finding, FindingStatus, User

router = APIRouter(prefix="/compliance", tags=["Compliance Mappings"])

COMPLIANCE_CATALOG = [
    {
        "framework": "CIS AWS Foundations Benchmark v1.5",
        "control_id": "CIS-2.1.5",
        "title": "Ensure S3 Buckets are configured with Block Public Access",
        "mapped_rules": ["S3_PUBLIC_ACCESS_BLOCK_DISABLED"],
    },
    {
        "framework": "CIS AWS Foundations Benchmark v1.5",
        "control_id": "CIS-2.1.1",
        "title": "Ensure S3 Bucket default server-side encryption is enabled",
        "mapped_rules": ["S3_DEFAULT_ENCRYPTION_MISSING"],
    },
    {
        "framework": "CIS AWS Foundations Benchmark v1.5",
        "control_id": "CIS-1.10",
        "title": "Ensure Multi-Factor Authentication (MFA) is enabled for all IAM users with console access",
        "mapped_rules": ["IAM_USER_MFA_DISABLED"],
    },
    {
        "framework": "CIS AWS Foundations Benchmark v1.5",
        "control_id": "CIS-1.16",
        "title": "Ensure IAM policies do not allow full '*:*' administrative privileges",
        "mapped_rules": ["IAM_WILDCARD_ADMIN_PRIVILEGES"],
    },
    {
        "framework": "CIS AWS Foundations Benchmark v1.5",
        "control_id": "CIS-5.2",
        "title": "Ensure no Security Groups allow ingress from 0.0.0.0/0 to remote server admin ports (22/3389)",
        "mapped_rules": ["SG_UNRESTRICTED_SSH_INGRESS", "SG_UNRESTRICTED_RDP_INGRESS"],
    },
    {
        "framework": "CIS AWS Foundations Benchmark v1.5",
        "control_id": "CIS-3.1",
        "title": "Ensure CloudTrail is enabled and actively logging in all regions",
        "mapped_rules": ["CLOUDTRAIL_LOGGING_DISABLED"],
    },
    {
        "framework": "NIST Cybersecurity Framework (CSF)",
        "control_id": "PR.AC-4",
        "title": "Access permissions and authorizations are managed incorporating principles of least privilege",
        "mapped_rules": ["IAM_WILDCARD_ADMIN_PRIVILEGES", "IAM_USER_MFA_DISABLED"],
    },
    {
        "framework": "NIST Cybersecurity Framework (CSF)",
        "control_id": "PR.DS-1",
        "title": "Data-at-rest is protected using strong encryption",
        "mapped_rules": ["S3_DEFAULT_ENCRYPTION_MISSING", "EBS_VOLUME_UNENCRYPTED"],
    },
    {
        "framework": "AWS Well-Architected Security Pillar",
        "control_id": "SEC-05",
        "title": "Protect network resources and enforce Instance Metadata Service v2 (IMDSv2)",
        "mapped_rules": ["EC2_IMDSV2_NOT_ENFORCED", "SG_UNRESTRICTED_SSH_INGRESS", "SG_UNRESTRICTED_RDP_INGRESS"],
    },
]


@router.get("")
def get_compliance_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Evaluate informational compliance control status based on open findings."""
    open_findings = (
        db.query(Finding)
        .join(CloudResource, Finding.resource_id == CloudResource.id)
        .join(AWSAccount, CloudResource.aws_account_id == AWSAccount.id)
        .filter(
            AWSAccount.organization_id == current_user.organization_id,
            Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
        )
        .all()
    )
    failing_rules = {f.rule_id for f in open_findings}

    controls_evaluated = []
    passed = 0
    for item in COMPLIANCE_CATALOG:
        violated_by = [r for r in item["mapped_rules"] if r in failing_rules]
        status_str = "FAIL" if violated_by else "PASS"
        if status_str == "PASS":
            passed += 1
        controls_evaluated.append({
            **item,
            "status": status_str,
            "violated_rules": violated_by,
        })

    total = len(controls_evaluated)
    readiness_pct = round((passed / total) * 100) if total else 100

    return {
        "disclaimer": "Informational mapping to CIS AWS Foundations Benchmark v1.5, NIST CSF, and AWS Well-Architected Security Pillar. Does not represent formal third-party compliance certification.",
        "summary": {
            "total_controls": total,
            "passing_controls": passed,
            "failing_controls": total - passed,
            "readiness_percentage": readiness_pct,
        },
        "controls": controls_evaluated,
    }
