"""
Database models for audit history tracking.
Supports both SQLite (local) and PostgreSQL (production).
"""

from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum as SQLEnum,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class SeverityLevel(str, Enum):
    """Finding severity levels"""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ApprovalState(str, Enum):
    """Remediation approval states"""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"


class AuditRun(Base):
    """Main audit execution record"""

    __tablename__ = "audit_runs"

    # Primary identification
    audit_id = Column(String(50), primary_key=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)

    # System information
    platform = Column(String(20), nullable=False)
    hostname = Column(String(255), nullable=False)
    platform_version = Column(String(100))

    # Results summary
    risk_score = Column(Integer)
    risk_level = Column(String(20))
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    # Execution metadata
    executed_by = Column(String(100))
    execution_time_seconds = Column(Float)
    collectors_executed = Column(Integer, default=0)
    collectors_failed = Column(Integer, default=0)

    # AI analysis metadata
    ai_provider = Column(String(20))
    ai_model = Column(String(50))
    ai_api_calls = Column(Integer, default=0)
    ai_api_latency_ms = Column(Float)
    ai_api_errors = Column(Integer, default=0)

    # Raw results (JSON)
    raw_results = Column(MutableDict.as_mutable(JSON))

    # Integrity verification
    results_hash = Column(String(64))  # SHA-256 hash

    # Relationships
    findings = relationship(
        "AuditFinding", back_populates="audit_run", cascade="all, delete-orphan"
    )
    remediations = relationship(
        "RemediationExecution", back_populates="audit_run", cascade="all, delete-orphan"
    )

    # Indexes for common queries
    __table_args__ = (
        Index("idx_timestamp", "timestamp"),
        Index("idx_hostname", "hostname"),
        Index("idx_risk_score", "risk_score"),
        Index("idx_platform", "platform"),
    )

    def __repr__(self):
        return f"<AuditRun(audit_id='{self.audit_id}', timestamp='{self.timestamp}', risk_score={self.risk_score})>"


class AuditFinding(Base):
    """Individual security/configuration finding"""

    __tablename__ = "audit_findings"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Foreign key
    audit_id = Column(String(50), ForeignKey("audit_runs.audit_id"), nullable=False)

    # Finding details
    check_id = Column(String(50), nullable=False)
    severity: Any = Column(SQLEnum(SeverityLevel), nullable=False)
    description = Column(Text, nullable=False)
    current_value = Column(Text)
    expected_value = Column(Text)
    remediation_hint = Column(Text)

    # Metadata
    collector_name = Column(String(50))
    detected_at = Column(DateTime, default=datetime.utcnow)

    # Resolution tracking
    resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime)
    resolution_notes = Column(Text)

    # Relationship
    audit_run = relationship("AuditRun", back_populates="findings")

    # Indexes
    __table_args__ = (
        Index("idx_audit_severity", "audit_id", "severity"),
        Index("idx_check_id", "check_id"),
        Index("idx_resolved", "resolved"),
    )

    def __repr__(self):
        return (
            f"<AuditFinding(id={self.id}, check_id='{self.check_id}', severity='{self.severity}')>"
        )


class RemediationExecution(Base):
    """Remediation script execution tracking"""

    __tablename__ = "remediation_executions"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Foreign key
    audit_id = Column(String(50), ForeignKey("audit_runs.audit_id"), nullable=False)

    # Remediation details
    script_id = Column(String(100), nullable=False)
    check_id = Column(String(50), nullable=False)
    script_filename = Column(String(255))
    script_content = Column(Text)
    rollback_script = Column(Text)

    # State management
    approval_state: Any = Column(SQLEnum(ApprovalState), default=ApprovalState.PENDING)
    approved_by = Column(String(100))
    approved_at = Column(DateTime)

    # Execution tracking
    executed_at = Column(DateTime)
    executed_by = Column(String(100))
    execution_success = Column(Boolean)
    execution_log = Column(Text)
    execution_duration_seconds = Column(Float)

    # Pre/post execution state
    pre_execution_state = Column(JSON)
    post_execution_state = Column(JSON)

    # Rollback tracking
    rolled_back = Column(Boolean, default=False)
    rolled_back_at = Column(DateTime)
    rollback_success = Column(Boolean)
    rollback_log = Column(Text)

    # Relationship
    audit_run = relationship("AuditRun", back_populates="remediations")

    # Indexes
    __table_args__ = (
        Index("idx_audit_script", "audit_id", "script_id"),
        Index("idx_approval_state", "approval_state"),
        Index("idx_executed_at", "executed_at"),
    )

    def __repr__(self):
        return f"<RemediationExecution(id={self.id}, script_id='{self.script_id}', state='{self.approval_state}')>"
