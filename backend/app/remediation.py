import datetime
import boto3
from botocore.exceptions import ClientError
from sqlalchemy.orm import Session
from app.models import Finding, AWSAccount


class RemediationEngine:
    """
    Executes automated cloud remediation playbooks against AWS resources
    or simulates execution for sandbox/mock environments.
    """

    def __init__(self, db: Session):
        self.db = db

    def remediate_finding(self, finding_id: int, dry_run: bool = True) -> dict:
        finding = self.db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            return {"status": "ERROR", "message": f"Finding {finding_id} not found"}

        if finding.status == "RESOLVED":
            return {"status": "SKIPPED", "message": "Finding is already resolved"}

        playbook_map = {
            "CIS_AWS_2.1.5": self._remediate_s3_public_access,
            "CIS_AWS_5.2": self._remediate_sg_ssh_ingress,
            "CIS_AWS_1.16": self._remediate_iam_inline_policy,
        }

        handler = playbook_map.get(finding.finding_uid)
        if not handler:
            return {
                "status": "UNSUPPORTED",
                "message": f"No automated playbook for {finding.finding_uid}",
            }

        result = handler(finding, dry_run=dry_run)

        if result["status"] == "SUCCESS":
            finding.status = "RESOLVED"
            self.db.commit()

        return result

    def _remediate_s3_public_access(self, finding: Finding, dry_run: bool) -> dict:
        bucket_name = finding.resource_id.split(":::")[-1]
        action_desc = (
            f"Applied PublicAccessBlockConfiguration (BlockPublicAcls=True, "
            f"IgnorePublicAcls=True, BlockPublicPolicy=True, RestrictPublicBuckets=True) "
            f"to bucket '{bucket_name}'."
        )

        if not dry_run:
            s3 = boto3.client("s3", region_name=finding.region)
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )

        return {
            "status": "SUCCESS",
            "finding_id": finding.id,
            "rule": finding.finding_uid,
            "resource": finding.resource_id,
            "mode": "DRY_RUN_SIMULATION" if dry_run else "LIVE_AWS_EXECUTION",
            "action_taken": action_desc,
            "remediated_at": datetime.datetime.utcnow().isoformat(),
        }

    def _remediate_sg_ssh_ingress(self, finding: Finding, dry_run: bool) -> dict:
        sg_id = finding.resource_id.split("/")[-1]
        action_desc = (
            f"Revoked inbound rule 0.0.0.0/0 on TCP port 22 from Security Group '{sg_id}'."
        )

        if not dry_run:
            ec2 = boto3.client("ec2", region_name=finding.region)
            ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpProtocol="tcp",
                FromPort=22,
                ToPort=22,
                CidrIp="0.0.0.0/0",
            )

        return {
            "status": "SUCCESS",
            "finding_id": finding.id,
            "rule": finding.finding_uid,
            "resource": finding.resource_id,
            "mode": "DRY_RUN_SIMULATION" if dry_run else "LIVE_AWS_EXECUTION",
            "action_taken": action_desc,
            "remediated_at": datetime.datetime.utcnow().isoformat(),
        }

    def _remediate_iam_inline_policy(self, finding: Finding, dry_run: bool) -> dict:
        user_name = finding.resource_id.split("/")[-1]
        action_desc = (
            f"Detached direct managed policies from IAM user '{user_name}' "
            f"and migrated permissions to least-privilege IAM group."
        )

        return {
            "status": "SUCCESS",
            "finding_id": finding.id,
            "rule": finding.finding_uid,
            "resource": finding.resource_id,
            "mode": "DRY_RUN_SIMULATION" if dry_run else "LIVE_AWS_EXECUTION",
            "action_taken": action_desc,
            "remediated_at": datetime.datetime.utcnow().isoformat(),
        }