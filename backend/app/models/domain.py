from datetime import datetime, timezone
from enum import Enum as PyEnum
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UserRole(str, PyEnum):
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    VIEWER = "VIEWER"


class SeverityLevel(str, PyEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, PyEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    RISK_ACCEPTED = "RISK_ACCEPTED"


class ScanStatus(str, PyEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


# Many-to-Many association table between Findings and ComplianceControls
finding_compliance_map = Table(
    "finding_compliance_map",
    Base.metadata,
    Column("finding_id", Integer, ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True),
    Column("control_id", Integer, ForeignKey("compliance_controls.id", ondelete="CASCADE"), primary_key=True),
)


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), unique=True, nullable=False)
    slug = Column(String(120), unique=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    aws_accounts = relationship("AWSAccount", back_populates="organization", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="organization", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(120), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.SECURITY_ANALYST, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    organization = relationship("Organization", back_populates="users")
    notifications = relationship("Notification", back_populates="user", cascade="all, delete-orphan")


class AWSAccount(Base):
    __tablename__ = "aws_accounts"
    __table_args__ = (
        UniqueConstraint("organization_id", "aws_account_id", name="uq_org_aws_account"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    aws_account_id = Column(String(12), nullable=False, index=True)  # 12-digit AWS account ID
    alias = Column(String(120), nullable=False)
    role_arn = Column(String(255), nullable=True)  # e.g., arn:aws:iam::123456789012:role/VaultMeshReadOnly
    external_id = Column(String(128), nullable=True)
    default_region = Column(String(32), default="ap-south-1", nullable=False)
    is_mock = Column(Boolean, default=True, nullable=False)
    connection_status = Column(String(32), default="CONNECTED", nullable=False)
    last_synced_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    organization = relationship("Organization", back_populates="aws_accounts")
    regions = relationship("AWSRegion", back_populates="aws_account", cascade="all, delete-orphan")
    resources = relationship("CloudResource", back_populates="aws_account", cascade="all, delete-orphan")
    scan_jobs = relationship("ScanJob", back_populates="aws_account", cascade="all, delete-orphan")
    threat_events = relationship("ThreatEvent", back_populates="aws_account", cascade="all, delete-orphan")


class AWSRegion(Base):
    __tablename__ = "aws_regions"
    __table_args__ = (
        UniqueConstraint("aws_account_id", "region_code", name="uq_account_region"),
    )

    id = Column(Integer, primary_key=True, index=True)
    aws_account_id = Column(Integer, ForeignKey("aws_accounts.id", ondelete="CASCADE"), nullable=False)
    region_code = Column(String(32), nullable=False)  # e.g., ap-south-1, us-east-1
    is_enabled = Column(Boolean, default=True, nullable=False)

    aws_account = relationship("AWSAccount", back_populates="regions")


class CloudResource(Base):
    __tablename__ = "cloud_resources"
    __table_args__ = (
        UniqueConstraint("aws_account_id", "resource_arn", name="uq_account_resource_arn"),
        Index("ix_resource_service_region", "service", "region"),
    )

    id = Column(Integer, primary_key=True, index=True)
    aws_account_id = Column(Integer, ForeignKey("aws_accounts.id", ondelete="CASCADE"), nullable=False)
    resource_arn = Column(String(512), nullable=False, index=True)
    resource_id = Column(String(255), nullable=False)
    resource_name = Column(String(255), nullable=True)
    service = Column(String(64), nullable=False)  # S3, IAM, EC2, VPC, KMS, CloudTrail
    resource_type = Column(String(100), nullable=False)  # AWS::S3::Bucket, AWS::EC2::SecurityGroup
    region = Column(String(32), nullable=False)
    configuration = Column(JSON, default=dict, nullable=False)
    tags = Column(JSON, default=dict, nullable=False)
    is_mock = Column(Boolean, default=True, nullable=False)
    discovered_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    aws_account = relationship("AWSAccount", back_populates="resources")
    findings = relationship("Finding", back_populates="resource", cascade="all, delete-orphan")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    aws_account_id = Column(Integer, ForeignKey("aws_accounts.id", ondelete="CASCADE"), nullable=False)
    triggered_by_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    regions_scanned = Column(JSON, default=list, nullable=False)
    resources_scanned = Column(Integer, default=0, nullable=False)
    findings_count = Column(Integer, default=0, nullable=False)
    security_score = Column(Integer, default=100, nullable=False)  # 0 to 100
    is_mock = Column(Boolean, default=True, nullable=False)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    aws_account = relationship("AWSAccount", back_populates="scan_jobs")
    results = relationship("ScanResult", back_populates="scan_job", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan_job", cascade="all, delete-orphan")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    scanner_name = Column(String(100), nullable=False)  # e.g., S3PublicAccessScanner
    checks_passed = Column(Integer, default=0, nullable=False)
    checks_failed = Column(Integer, default=0, nullable=False)
    raw_summary = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    scan_job = relationship("ScanJob", back_populates="results")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_finding_severity_status", "severity", "status"),
    )

    id = Column(Integer, primary_key=True, index=True)
    finding_uid = Column(String(64), unique=True, nullable=False, index=True)  # e.g., VM-S3-001-a8f9
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    resource_id = Column(Integer, ForeignKey("cloud_resources.id", ondelete="CASCADE"), nullable=False)
    rule_id = Column(String(64), nullable=False, index=True)  # e.g., S3_PUBLIC_READ_BLOCK
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(Enum(SeverityLevel), nullable=False, index=True)
    status = Column(Enum(FindingStatus), default=FindingStatus.OPEN, nullable=False, index=True)
    evidence = Column(JSON, default=dict, nullable=False)
    remediation_summary = Column(Text, nullable=False)
    remediation_cli = Column(Text, nullable=True)
    remediation_terraform = Column(Text, nullable=True)
    aws_doc_url = Column(String(512), nullable=True)
    investigation_notes = Column(Text, nullable=True)
    is_mock = Column(Boolean, default=True, nullable=False)
    detected_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    scan_job = relationship("ScanJob", back_populates="findings")
    resource = relationship("CloudResource", back_populates="findings")
    remediation_actions = relationship("RemediationAction", back_populates="finding", cascade="all, delete-orphan")
    compliance_controls = relationship(
        "ComplianceControl",
        secondary=finding_compliance_map,
        back_populates="findings",
    )


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id = Column(Integer, primary_key=True, index=True)
    aws_account_id = Column(Integer, ForeignKey("aws_accounts.id", ondelete="CASCADE"), nullable=False)
    event_id = Column(String(128), unique=True, nullable=False, index=True)
    event_name = Column(String(128), nullable=False, index=True)  # e.g., ConsoleLogin, StopLogging
    event_source = Column(String(128), nullable=False)  # e.g., signin.amazonaws.com
    actor_arn = Column(String(512), nullable=True)
    source_ip = Column(String(64), nullable=True)
    region = Column(String(32), nullable=False)
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.MEDIUM, nullable=False)
    rule_triggered = Column(String(128), nullable=False)
    explanation = Column(Text, nullable=False)
    raw_event = Column(JSON, default=dict, nullable=False)
    is_mock = Column(Boolean, default=True, nullable=False)
    occurred_at = Column(DateTime(timezone=True), nullable=False)
    detected_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    aws_account = relationship("AWSAccount", back_populates="threat_events")


class RemediationAction(Base):
    __tablename__ = "remediation_actions"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    executed_by_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action_type = Column(String(64), nullable=False)  # DRY_RUN | LIVE_APPLY
    status = Column(String(32), nullable=False)  # SIMULATED | SUCCEEDED | FAILED
    command_preview = Column(Text, nullable=False)
    execution_output = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    finding = relationship("Finding", back_populates="remediation_actions")


class ComplianceControl(Base):
    __tablename__ = "compliance_controls"
    __table_args__ = (
        UniqueConstraint("framework", "control_id", name="uq_framework_control"),
    )

    id = Column(Integer, primary_key=True, index=True)
    framework = Column(String(64), nullable=False, index=True)  # CIS_AWS_1_5 | NIST_CSF | AWS_WAF
    control_id = Column(String(32), nullable=False)  # e.g., 2.1.5
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)

    findings = relationship(
        "Finding",
        secondary=finding_compliance_map,
        back_populates="compliance_controls",
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    actor_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(String(100), nullable=False, index=True)  # USER_LOGIN, SCAN_STARTED, FINDING_UPDATED
    target_type = Column(String(64), nullable=True)
    target_id = Column(String(128), nullable=True)
    ip_address = Column(String(64), nullable=True)
    details = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

    organization = relationship("Organization", back_populates="audit_logs")


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(160), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.INFO, nullable=False)
    is_read = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    user = relationship("User", back_populates="notifications")
