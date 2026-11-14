from datetime import datetime
import re
from pydantic import BaseModel, ConfigDict, Field, field_validator


class AWSAccountCreateRequest(BaseModel):
    aws_account_id: str = Field(..., min_length=12, max_length=12, examples=["123456789012"])
    alias: str = Field(..., min_length=2, max_length=120, examples=["Production Sandbox"])
    is_mock: bool = Field(default=True)
    role_arn: str | None = Field(
        default=None,
        max_length=255,
        examples=["arn:aws:iam::123456789012:role/VaultMeshReadOnlyRole"],
    )
    external_id: str | None = Field(default=None, max_length=128)
    default_region: str = Field(default="ap-south-1", max_length=32)
    regions: list[str] = Field(default=["ap-south-1", "us-east-1"])

    @field_validator("aws_account_id")
    @classmethod
    def validate_account_id(cls, v: str) -> str:
        if not re.fullmatch(r"\d{12}", v):
            raise ValueError("AWS Account ID must be exactly 12 digits.")
        return v

    @field_validator("role_arn")
    @classmethod
    def validate_role_arn(cls, v: str | None) -> str | None:
        if v is None or v.strip() == "":
            return None
        pattern = r"^arn:aws(-[a-z]+)?:iam::\d{12}:role\/[\w+=,.@-]+$"
        if not re.fullmatch(pattern, v.strip()):
            raise ValueError(
                "Invalid IAM Role ARN format. Expected: arn:aws:iam::<12-digit-id>:role/<RoleName>"
            )
        return v.strip()


class AWSRegionResponse(BaseModel):
    id: int
    region_code: str
    is_enabled: bool

    model_config = ConfigDict(from_attributes=True)


class AWSAccountResponse(BaseModel):
    id: int
    organization_id: int
    aws_account_id: str
    alias: str
    role_arn: str | None
    external_id: str | None
    default_region: str
    is_mock: bool
    connection_status: str
    last_synced_at: datetime | None
    created_at: datetime
    regions: list[AWSRegionResponse] = []

    model_config = ConfigDict(from_attributes=True)


class ConnectionValidationResponse(BaseModel):
    account_id: int
    aws_account_id: str
    is_mock: bool
    status: str
    caller_arn: str
    message: str
    validated_at: datetime
