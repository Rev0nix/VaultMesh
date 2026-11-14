from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime

Base = declarative_base()

class Organization(Base):
    __tablename__ = "organizations"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    users = relationship("User", back_populates="organization")
    accounts = relationship("AWSAccount", back_populates="organization")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    role = Column(String, default="ADMIN") # ADMIN, AUDITOR, VIEWER
    is_active = Column(Boolean, default=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    organization = relationship("Organization", back_populates="users")

class AWSAccount(Base):
    __tablename__ = "aws_accounts"

    id = Column(Integer, primary_key=True, index=True)
    aws_account_id = Column(String, unique=True, index=True, nullable=False)
    alias = Column(String, nullable=False)
    role_arn = Column(String, nullable=False)
    external_id = Column(String, nullable=True)
    default_region = Column(String, default="ap-south-1")
    connection_status = Column(String, default="PENDING") # PENDING, CONNECTED, FAILED
    organization_id = Column(Integer, ForeignKey("organizations.id"))
    last_synced_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    organization = relationship("Organization", back_populates="accounts")
    scans = relationship("ScanJob", back_populates="account")

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    aws_account_id = Column(Integer, ForeignKey("aws_accounts.id"))
    status = Column(String, default="QUEUED") # QUEUED, RUNNING, COMPLETED, FAILED
    findings_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    account = relationship("AWSAccount", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_jobs.id"))
    finding_uid = Column(String, index=True, nullable=False) # e.g. CKV_AWS_20
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=False) # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String, default="OPEN") # OPEN, RESOLVED, SUPPRESSED
    resource_id = Column(String, nullable=False)
    region = Column(String, nullable=False)
    framework = Column(String, nullable=False) # CIS AWS, SOC2, HIPAA
    remediation_guidance = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("ScanJob", back_populates="findings")