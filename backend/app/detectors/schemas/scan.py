from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field
from app.models.domain import FindingStatus, ScanStatus, SeverityLevel


class ScanTriggerRequest(BaseModel):
    aws_account_id: int = Field(..., description="Database ID of the connected AWSAccount")


class ScanJobResponse(BaseModel):
    id: int
    aws_account_id: int
    status: ScanStatus
    regions_scanned: list[str]
    resources_scanned: int
    findings_count: int
    security_score: int
    is_mock: bool
    started_at: datetime
    completed_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class FindingResourceSummary(BaseModel):
    id: int
    resource_arn: str
    resource_id: str
    resource_name: str | None
    service: str
    resource_type: str
    region: str

    model_config = ConfigDict(from_attributes=True)


class FindingResponse(BaseModel):
    id: int
    finding_uid: str
    scan_job_id: int
    rule_id: str
    title: str
    description: str
    severity: SeverityLevel
    status: FindingStatus
    evidence: dict[str, Any]
    remediation_summary: str
    remediation_cli: str | None
    remediation_terraform: str | None
    aws_doc_url: str | None
    investigation_notes: str | None
    is_mock: bool
    detected_at: datetime
    updated_at: datetime
    resource: FindingResourceSummary

    model_config = ConfigDict(from_attributes=True)


class FindingUpdateRequest(BaseModel):
    status: FindingStatus | None = None
    investigation_notes: str | None = Field(default=None, max_length=2000)
