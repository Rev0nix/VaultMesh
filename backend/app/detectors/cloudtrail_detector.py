from collections import Counter
from datetime import datetime, timedelta, timezone
import json
from typing import Any
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from app.models.domain import SeverityLevel


class CloudTrailThreatDetector:
    """
    Explainable rule-based threat detection engine for AWS CloudTrail events.
    Supports offline Sandbox Mock CloudTrail streams (₹0) and live LookupEvents.
    """

    @staticmethod
    def fetch_events(
        aws_account_id: str,
        region: str,
        is_mock: bool,
        role_arn: str | None = None,
        external_id: str | None = None,
    ) -> list[dict[str, Any]]:
        if is_mock:
            return CloudTrailThreatDetector._get_mock_cloudtrail_events(aws_account_id, region)
        return CloudTrailThreatDetector._get_live_cloudtrail_events(
            region=region,
            role_arn=role_arn,
            external_id=external_id,
        )

    @staticmethod
    def _get_mock_cloudtrail_events(aws_account_id: str, region: str) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc)
        attacker_ip = "185.220.101.44"
        return [
            # 1. Brute-force login sequence (4 failed ConsoleLogins from same external IP)
            *[
                {
                    "eventID": f"ct-mock-bf-00{i}",
                    "eventName": "ConsoleLogin",
                    "eventSource": "signin.amazonaws.com",
                    "eventTime": (now - timedelta(minutes=15 - i)).isoformat(),
                    "awsRegion": "us-east-1",
                    "sourceIPAddress": attacker_ip,
                    "userIdentity": {"arn": f"arn:aws:iam::{aws_account_id}:user/ops-admin"},
                    "errorMessage": "Failed authentication",
                    "requestParameters": {"MFAUsed": "No"},
                }
                for i in range(1, 5)
            ],
            # 2. CloudTrail Defense Evasion (StopLogging)
            {
                "eventID": "ct-mock-trail-stop-01",
                "eventName": "StopLogging",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventTime": (now - timedelta(minutes=8)).isoformat(),
                "awsRegion": region,
                "sourceIPAddress": attacker_ip,
                "userIdentity": {"arn": f"arn:aws:iam::{aws_account_id}:user/ci-deploy-bot"},
                "requestParameters": {
                    "name": f"arn:aws:cloudtrail:{region}:{aws_account_id}:trail/org-management-trail"
                },
            },
            # 3. Privilege Escalation (Attaching AdministratorAccess)
            {
                "eventID": "ct-mock-privesc-01",
                "eventName": "AttachUserPolicy",
                "eventSource": "iam.amazonaws.com",
                "eventTime": (now - timedelta(minutes=6)).isoformat(),
                "awsRegion": "us-east-1",
                "sourceIPAddress": attacker_ip,
                "userIdentity": {"arn": f"arn:aws:iam::{aws_account_id}:user/ci-deploy-bot"},
                "requestParameters": {
                    "userName": "temp-contractor",
                    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                },
            },
            # 4. Security Group Perimeter Modification (0.0.0.0/0 SSH ingress)
            {
                "eventID": "ct-mock-sg-open-01",
                "eventName": "AuthorizeSecurityGroupIngress",
                "eventSource": "ec2.amazonaws.com",
                "eventTime": (now - timedelta(minutes=4)).isoformat(),
                "awsRegion": region,
                "sourceIPAddress": "45.33.32.156",
                "userIdentity": {"arn": f"arn:aws:iam::{aws_account_id}:user/ci-deploy-bot"},
                "requestParameters": {
                    "groupId": "sg-0a91b82c7d6e5f401",
                    "cidrIp": "0.0.0.0/0",
                    "fromPort": 22,
                    "toPort": 22,
                },
            },
            # 5. S3 Public Access Block Removal
            {
                "eventID": "ct-mock-s3-pub-01",
                "eventName": "DeleteBucketPublicAccessBlock",
                "eventSource": "s3.amazonaws.com",
                "eventTime": (now - timedelta(minutes=2)).isoformat(),
                "awsRegion": region,
                "sourceIPAddress": "45.33.32.156",
                "userIdentity": {"arn": f"arn:aws:iam::{aws_account_id}:user/ci-deploy-bot"},
                "requestParameters": {
                    "bucketName": f"vaultmesh-prod-customer-backups-{aws_account_id}"
                },
            },
        ]

    @staticmethod
    def _get_live_cloudtrail_events(
        region: str,
        role_arn: str | None,
        external_id: str | None,
    ) -> list[dict[str, Any]]:
        if not role_arn:
            raise ValueError("Live CloudTrail analysis requires an IAM Role ARN.")
        sts = boto3.client("sts", region_name=region)
        assume_kwargs: dict[str, Any] = {
            "RoleArn": role_arn,
            "RoleSessionName": "VaultMeshThreatDetectionSession",
            "DurationSeconds": 900,
        }
        if external_id:
            assume_kwargs["ExternalId"] = external_id
        creds = sts.assume_role(**assume_kwargs)["Credentials"]
        ct = boto3.client(
            "cloudtrail",
            region_name=region,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
        parsed_events: list[dict[str, Any]] = []
        try:
            resp = ct.lookup_events(MaxResults=50)
            for item in resp.get("Events", []):
                raw = json.loads(item.get("CloudTrailEvent", "{}"))
                if raw:
                    parsed_events.append(raw)
        except (ClientError, BotoCoreError):
            pass
        return parsed_events

    @staticmethod
    def evaluate_events(events: list[dict[str, Any]], default_region: str) -> list[dict[str, Any]]:
        """Evaluate explainable behavioral rules across CloudTrail events."""
        alerts: list[dict[str, Any]] = []

        # Rule 1: Detect brute-force login spikes (>=3 failed ConsoleLogins per source IP)
        failed_login_ips = Counter(
            ev.get("sourceIPAddress", "unknown")
            for ev in events
            if ev.get("eventName") == "ConsoleLogin" and ev.get("errorMessage")
        )
        flagged_bf_ips = set()

        for ev in events:
            ev_id = ev.get("eventID", "")
            ev_name = ev.get("eventName", "")
            ev_source = ev.get("eventSource", "aws.amazonaws.com")
            src_ip = ev.get("sourceIPAddress", "unknown")
            actor_arn = (ev.get("userIdentity") or {}).get("arn", "unknown-principal")
            region = ev.get("awsRegion") or default_region
            params = ev.get("requestParameters") or {}
            occurred_raw = ev.get("eventTime")
            occurred_at = (
                datetime.fromisoformat(occurred_raw.replace("Z", "+00:00"))
                if isinstance(occurred_raw, str)
                else datetime.now(timezone.utc)
            )

            # Rule 1 Match
            if (
                ev_name == "ConsoleLogin"
                and ev.get("errorMessage")
                and failed_login_ips[src_ip] >= 3
                and src_ip not in flagged_bf_ips
            ):
                flagged_bf_ips.add(src_ip)
                alerts.append({
                    "event_id": ev_id,
                    "event_name": ev_name,
                    "event_source": ev_source,
                    "actor_arn": actor_arn,
                    "source_ip": src_ip,
                    "region": region,
                    "severity": SeverityLevel.HIGH,
                    "rule_triggered": "AUTH_BRUTE_FORCE_SPIKE",
                    "explanation": f"Detected {failed_login_ips[src_ip]} consecutive failed AWS Console login attempts from IP {src_ip}.",
                    "raw_event": ev,
                    "occurred_at": occurred_at,
                })

            # Rule 2: CloudTrail StopLogging / DeleteTrail
            elif ev_name in ("StopLogging", "DeleteTrail"):
                alerts.append({
                    "event_id": ev_id,
                    "event_name": ev_name,
                    "event_source": ev_source,
                    "actor_arn": actor_arn,
                    "source_ip": src_ip,
                    "region": region,
                    "severity": SeverityLevel.CRITICAL,
                    "rule_triggered": "CLOUDTRAIL_LOGGING_TAMPER",
                    "explanation": f"Defense evasion detected: {actor_arn} invoked {ev_name} from {src_ip} to blind audit logging.",
                    "raw_event": ev,
                    "occurred_at": occurred_at,
                })

            # Rule 3: IAM Privilege Escalation
            elif ev_name in ("AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "CreateAccessKey"):
                policy_arn = str(params.get("policyArn", ""))
                is_admin_attach = "AdministratorAccess" in policy_arn or ev_name == "CreateAccessKey"
                alerts.append({
                    "event_id": ev_id,
                    "event_name": ev_name,
                    "event_source": ev_source,
                    "actor_arn": actor_arn,
                    "source_ip": src_ip,
                    "region": region,
                    "severity": SeverityLevel.CRITICAL if is_admin_attach else SeverityLevel.HIGH,
                    "rule_triggered": "IAM_PRIVILEGE_ESCALATION",
                    "explanation": f"IAM privilege modification ({ev_name}) executed by {actor_arn} targeting {params.get('userName', 'IAM principal')}.",
                    "raw_event": ev,
                    "occurred_at": occurred_at,
                })

            # Rule 4: Security Group Public Ingress Modification
            elif ev_name == "AuthorizeSecurityGroupIngress" and "0.0.0.0/0" in json.dumps(params):
                alerts.append({
                    "event_id": ev_id,
                    "event_name": ev_name,
                    "event_source": ev_source,
                    "actor_arn": actor_arn,
                    "source_ip": src_ip,
                    "region": region,
                    "severity": SeverityLevel.HIGH,
                    "rule_triggered": "SG_PUBLIC_INGRESS_MODIFIED",
                    "explanation": f"Security Group {params.get('groupId', '')} was opened to 0.0.0.0/0 on port {params.get('fromPort', 'any')} by {actor_arn}.",
                    "raw_event": ev,
                    "occurred_at": occurred_at,
                })

            # Rule 5: S3 Public Access Block Removal / Public Bucket Policy
            elif ev_name in ("DeleteBucketPublicAccessBlock", "PutBucketPolicy"):
                alerts.append({
                    "event_id": ev_id,
                    "event_name": ev_name,
                    "event_source": ev_source,
                    "actor_arn": actor_arn,
                    "source_ip": src_ip,
                    "region": region,
                    "severity": SeverityLevel.CRITICAL,
                    "rule_triggered": "S3_PUBLIC_PROTECTION_REMOVED",
                    "explanation": f"S3 bucket protection modified ({ev_name}) on '{params.get('bucketName', 'bucket')}' by {actor_arn}.",
                    "raw_event": ev,
                    "occurred_at": occurred_at,
                })

        return alerts
