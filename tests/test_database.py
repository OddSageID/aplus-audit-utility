"""
Comprehensive tests for database repository.
Tests audit history, finding tracking, and remediation management.
"""

import pytest
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import json

from src.database.models import (
    AuditRun,
    AuditFinding,
    RemediationExecution,
    SeverityLevel,
    ApprovalState,
)
from src.database.repository import AuditRepository


@pytest.fixture
def temp_db():
    """Create temporary database for testing"""
    temp_dir = tempfile.mkdtemp()
    db_path = Path(temp_dir) / "test_audit.db"
    db_url = f"sqlite:///{db_path}"
    yield db_url
    # Cleanup
    if db_path.exists():
        db_path.unlink()


@pytest.fixture
def repository(temp_db):
    """Create repository instance with temp database"""
    return AuditRepository(database_url=temp_db)


@pytest.fixture
def sample_audit_results():
    """Create sample audit results for testing"""
    return {
        "audit_id": "20241214_120000",
        "timestamp": datetime.utcnow().isoformat(),
        "platform": "Linux",
        "hostname": "test-server-01",
        "platform_version": "Ubuntu 22.04",
        "all_findings": [
            {
                "check_id": "CIS-1.1-001",
                "severity": "CRITICAL",
                "description": "Test critical finding",
                "current_value": "Disabled",
                "expected_value": "Enabled",
                "remediation_hint": "Enable the setting",
                "collector_name": "SecurityCollector",
            },
            {
                "check_id": "CIS-2.1-001",
                "severity": "HIGH",
                "description": "Test high finding",
                "current_value": "Off",
                "expected_value": "On",
                "remediation_hint": "Turn it on",
                "collector_name": "OSConfigCollector",
            },
            {
                "check_id": "HW-001",
                "severity": "MEDIUM",
                "description": "Test medium finding",
                "current_value": "2GB",
                "expected_value": "4GB",
                "remediation_hint": "Upgrade RAM",
                "collector_name": "HardwareCollector",
            },
        ],
        "ai_analysis": {
            "risk_score": 75,
            "executive_summary": "System has critical security issues",
            "critical_issues": ["Critical finding 1"],
            "recommendations": ["Fix critical issues", "Update system"],
        },
        "collector_results": {
            "SecurityCollector": {"status": "success"},
            "HardwareCollector": {"status": "success"},
        },
        "remediation_scripts": {
            "CIS-1.1-001": {
                "filename": "fix_cis_1_1_001.sh",
                "content": '#!/bin/bash\necho "Fixing issue"',
                "finding": {"check_id": "CIS-1.1-001"},
            }
        },
    }


class TestAuditRunPersistence:
    """Test audit run creation and retrieval"""

    def test_save_audit_run(self, repository, sample_audit_results):
        """Test saving complete audit run"""
        audit_run = repository.save_audit_run(
            sample_audit_results, executed_by="test_user", execution_time_seconds=45.5
        )

        assert audit_run is not None
        assert audit_run.audit_id == "20241214_120000"
        assert audit_run.risk_score == 75
        assert audit_run.total_findings == 3
        assert audit_run.critical_count == 1
        assert audit_run.high_count == 1
        assert audit_run.medium_count == 1
        assert audit_run.executed_by == "test_user"
        assert audit_run.execution_time_seconds == 45.5

    def test_get_audit_run(self, repository, sample_audit_results):
        """Test retrieving audit run by ID"""
        # Save audit
        saved = repository.save_audit_run(sample_audit_results)

        # Retrieve it
        retrieved = repository.get_audit_run(saved.audit_id)

        assert retrieved is not None
        assert retrieved.audit_id == saved.audit_id
        assert retrieved.hostname == "test-server-01"
        assert retrieved.platform == "Linux"

    def test_get_nonexistent_audit(self, repository):
        """Test retrieving non-existent audit returns None"""
        result = repository.get_audit_run("nonexistent_id")
        assert result is None

    def test_audit_run_relationships(self, repository, sample_audit_results):
        """Test that relationships are properly saved"""
        audit_run = repository.save_audit_run(sample_audit_results)
        retrieved = repository.get_audit_run(audit_run.audit_id)

        # Check findings relationship
        assert len(retrieved.findings) == 3

        # Check remediations relationship
        assert len(retrieved.remediations) == 1

    def test_risk_level_calculation(self, repository, sample_audit_results):
        """Test that risk level is calculated correctly"""
        # Critical risk (75+)
        sample_audit_results["ai_analysis"]["risk_score"] = 80
        audit_run = repository.save_audit_run(sample_audit_results)
        assert audit_run.risk_level == "CRITICAL"

        # High risk (50-74)
        sample_audit_results["audit_id"] = "20241214_120001"
        sample_audit_results["ai_analysis"]["risk_score"] = 60
        audit_run = repository.save_audit_run(sample_audit_results)
        assert audit_run.risk_level == "HIGH"

        # Medium risk (25-49)
        sample_audit_results["audit_id"] = "20241214_120002"
        sample_audit_results["ai_analysis"]["risk_score"] = 30
        audit_run = repository.save_audit_run(sample_audit_results)
        assert audit_run.risk_level == "MEDIUM"

        # Low risk (0-24)
        sample_audit_results["audit_id"] = "20241214_120003"
        sample_audit_results["ai_analysis"]["risk_score"] = 10
        audit_run = repository.save_audit_run(sample_audit_results)
        assert audit_run.risk_level == "LOW"


class TestFindingManagement:
    """Test finding creation, retrieval, and resolution"""

    def test_findings_saved_with_audit(self, repository, sample_audit_results):
        """Test that findings are saved with audit run"""
        audit_run = repository.save_audit_run(sample_audit_results)
        findings = repository.get_audit_run(audit_run.audit_id).findings

        assert len(findings) == 3

        # Check first finding
        critical_finding = next(f for f in findings if f.severity == SeverityLevel.CRITICAL)
        assert critical_finding.check_id == "CIS-1.1-001"
        assert critical_finding.description == "Test critical finding"
        assert critical_finding.collector_name == "SecurityCollector"

    def test_get_unresolved_findings(self, repository, sample_audit_results):
        """Test retrieving unresolved findings"""
        repository.save_audit_run(sample_audit_results)

        unresolved = repository.get_unresolved_findings()
        assert len(unresolved) == 3
        assert all(not f.resolved for f in unresolved)

    def test_get_unresolved_by_severity(self, repository, sample_audit_results):
        """Test filtering unresolved findings by severity"""
        repository.save_audit_run(sample_audit_results)

        critical_only = repository.get_unresolved_findings(severity=SeverityLevel.CRITICAL)
        assert len(critical_only) == 1
        assert critical_only[0].severity == SeverityLevel.CRITICAL

    def test_mark_finding_resolved(self, repository, sample_audit_results):
        """Test marking a finding as resolved"""
        audit_run = repository.save_audit_run(sample_audit_results)
        finding = audit_run.findings[0]

        # Mark as resolved
        success = repository.mark_finding_resolved(
            finding.id, resolution_notes="Fixed by applying patch"
        )

        assert success is True

        # Verify it's marked resolved
        retrieved = repository.get_audit_run(audit_run.audit_id)
        resolved_finding = next(f for f in retrieved.findings if f.id == finding.id)
        assert resolved_finding.resolved is True
        assert resolved_finding.resolution_notes == "Fixed by applying patch"
        assert resolved_finding.resolved_at is not None

    def test_mark_nonexistent_finding_resolved(self, repository):
        """Test marking non-existent finding returns False"""
        success = repository.mark_finding_resolved(99999)
        assert success is False


class TestRemediationManagement:
    """Test remediation script tracking"""

    def test_remediation_saved_with_audit(self, repository, sample_audit_results):
        """Test that remediation scripts are saved"""
        audit_run = repository.save_audit_run(sample_audit_results)
        remediations = audit_run.remediations

        assert len(remediations) == 1

        remediation = remediations[0]
        assert remediation.script_id == "CIS-1.1-001"
        assert remediation.check_id == "CIS-1.1-001"
        assert remediation.script_filename == "fix_cis_1_1_001.sh"
        assert remediation.approval_state == ApprovalState.PENDING

    def test_get_remediation_by_id(self, repository, sample_audit_results):
        """Test retrieving remediation by ID"""
        audit_run = repository.save_audit_run(sample_audit_results)
        remediation_id = audit_run.remediations[0].id

        retrieved = repository.get_remediation_by_id(remediation_id)
        assert retrieved is not None
        assert retrieved.script_id == "CIS-1.1-001"

    def test_update_remediation_approval(self, repository, sample_audit_results):
        """Test updating remediation approval state"""
        audit_run = repository.save_audit_run(sample_audit_results)
        remediation_id = audit_run.remediations[0].id

        # Approve remediation
        success = repository.update_remediation_approval(
            remediation_id, ApprovalState.APPROVED, approved_by="admin_user"
        )

        assert success is True

        # Verify update
        retrieved = repository.get_remediation_by_id(remediation_id)
        assert retrieved.approval_state == ApprovalState.APPROVED
        assert retrieved.approved_by == "admin_user"
        assert retrieved.approved_at is not None

    def test_record_remediation_execution(self, repository, sample_audit_results):
        """Test recording remediation execution"""
        audit_run = repository.save_audit_run(sample_audit_results)
        remediation_id = audit_run.remediations[0].id

        # Record execution
        success = repository.record_remediation_execution(
            remediation_id,
            success=True,
            executed_by="automation_user",
            execution_log="Successfully applied fix\nNo errors",
            duration_seconds=2.5,
            pre_state={"setting": "disabled"},
            post_state={"setting": "enabled"},
        )

        assert success is True

        # Verify execution record
        retrieved = repository.get_remediation_by_id(remediation_id)
        assert retrieved.execution_success is True
        assert retrieved.executed_by == "automation_user"
        assert retrieved.execution_duration_seconds == 2.5
        assert retrieved.pre_execution_state == {"setting": "disabled"}
        assert retrieved.post_execution_state == {"setting": "enabled"}
        assert retrieved.approval_state == ApprovalState.EXECUTED


class TestQueryOperations:
    """Test querying and filtering operations"""

    def test_get_recent_audits(self, repository, sample_audit_results):
        """Test retrieving recent audits"""
        # Create multiple audits
        for i in range(5):
            sample_audit_results["audit_id"] = f"20241214_12000{i}"
            repository.save_audit_run(sample_audit_results)

        # Get recent audits
        recent = repository.get_recent_audits(limit=3)
        assert len(recent) == 3

        # Should be ordered by timestamp descending
        for i in range(len(recent) - 1):
            assert recent[i].timestamp >= recent[i + 1].timestamp

    def test_get_recent_audits_by_hostname(self, repository, sample_audit_results):
        """Test filtering recent audits by hostname"""
        # Create audits for different hosts
        for i, hostname in enumerate(["host1", "host2", "host1"]):
            sample_audit_results["audit_id"] = f"20241214_12000{i}"
            sample_audit_results["hostname"] = hostname
            repository.save_audit_run(sample_audit_results)

        # Get audits for host1
        host1_audits = repository.get_recent_audits(hostname="host1")
        assert len(host1_audits) == 2
        assert all(a.hostname == "host1" for a in host1_audits)

    def test_get_audit_trends(self, repository, sample_audit_results):
        """Test retrieving audit trends"""
        # Create audits with varying risk scores
        risk_scores = [20, 40, 60, 80]
        for i, score in enumerate(risk_scores):
            sample_audit_results["audit_id"] = f"20241214_12000{i}"
            sample_audit_results["ai_analysis"]["risk_score"] = score
            repository.save_audit_run(sample_audit_results)

        # Get trends
        trends = repository.get_audit_trends(days=30)

        assert len(trends["risk_scores"]) == 4
        assert len(trends["finding_counts"]) == 4

        # Verify risk score values
        score_values = [score for _, score in trends["risk_scores"]]
        assert score_values == risk_scores

    def test_get_statistics(self, repository, sample_audit_results):
        """Test getting aggregate statistics"""
        # Create multiple audits
        for i in range(3):
            sample_audit_results["audit_id"] = f"20241214_12000{i}"
            sample_audit_results["ai_analysis"]["risk_score"] = 50 + (i * 10)
            repository.save_audit_run(sample_audit_results)

        # Get statistics
        stats = repository.get_statistics()

        assert stats["total_audits"] == 3
        assert stats["avg_risk_score"] == pytest.approx(60.0, rel=0.1)
        assert stats["total_findings"] == 9  # 3 findings per audit
        assert stats["critical_findings"] == 3  # 1 per audit

    def test_get_statistics_by_hostname(self, repository, sample_audit_results):
        """Test getting statistics filtered by hostname"""
        # Create audits for different hosts
        for hostname in ["host1", "host2"]:
            for i in range(2):
                sample_audit_results["audit_id"] = f"{hostname}_12000{i}"
                sample_audit_results["hostname"] = hostname
                repository.save_audit_run(sample_audit_results)

        # Get stats for host1
        stats = repository.get_statistics(hostname="host1")
        assert stats["total_audits"] == 2


class TestDataIntegrity:
    """Test data integrity and hash verification"""

    def test_results_hash_generated(self, repository, sample_audit_results):
        """Test that results hash is generated"""
        audit_run = repository.save_audit_run(sample_audit_results)

        assert audit_run.results_hash is not None
        assert len(audit_run.results_hash) == 64  # SHA-256 produces 64 hex chars

    def test_verify_integrity_success(self, repository, sample_audit_results):
        """Test successful integrity verification"""
        audit_run = repository.save_audit_run(sample_audit_results)

        # Verify integrity
        is_valid = repository.verify_integrity(audit_run.audit_id)
        assert is_valid is True

    def test_verify_integrity_tampered_data(self, repository, sample_audit_results):
        """Test that tampered data is detected"""
        audit_run = repository.save_audit_run(sample_audit_results)

        # Manually tamper with stored data
        from sqlalchemy.orm import Session

        session = repository._get_session()
        try:
            audit = session.query(AuditRun).filter(AuditRun.audit_id == audit_run.audit_id).first()

            # Modify raw results
            audit.raw_results["tampered"] = True
            session.commit()
        finally:
            session.close()

        # Verification should fail
        is_valid = repository.verify_integrity(audit_run.audit_id)
        assert is_valid is False


class TestEdgeCases:
    """Test edge cases and error handling"""

    def test_empty_findings_list(self, repository, sample_audit_results):
        """Test handling audit with no findings"""
        sample_audit_results["all_findings"] = []
        sample_audit_results["ai_analysis"]["risk_score"] = 0

        audit_run = repository.save_audit_run(sample_audit_results)

        assert audit_run.total_findings == 0
        assert audit_run.critical_count == 0
        assert len(audit_run.findings) == 0

    def test_missing_optional_fields(self, repository, sample_audit_results):
        """Test handling missing optional fields"""
        # Remove optional fields
        del sample_audit_results["remediation_scripts"]
        sample_audit_results["ai_analysis"] = {"risk_score": 0}

        audit_run = repository.save_audit_run(sample_audit_results)

        assert audit_run is not None
        assert len(audit_run.remediations) == 0

    def test_duplicate_audit_id(self, repository, sample_audit_results):
        """Test handling duplicate audit IDs"""
        # Save first audit
        repository.save_audit_run(sample_audit_results)

        # Attempt to save with same ID should raise error
        with pytest.raises(Exception):
            repository.save_audit_run(sample_audit_results)

    def test_statistics_with_no_audits(self, repository):
        """Test getting statistics when no audits exist"""
        stats = repository.get_statistics()

        assert stats["total_audits"] == 0
        assert stats["avg_risk_score"] == 0
        assert stats["total_findings"] == 0


class TestDatabaseConnections:
    """Test database connection management"""

    def test_database_initialization(self, temp_db):
        """Test that database is properly initialized"""
        repo = AuditRepository(database_url=temp_db)

        # Tables should exist
        from sqlalchemy import inspect

        inspector = inspect(repo.engine)
        tables = inspector.get_table_names()

        assert "audit_runs" in tables
        assert "audit_findings" in tables
        assert "remediation_executions" in tables

    def test_session_cleanup(self, repository, sample_audit_results):
        """Test that database sessions are properly cleaned up"""
        # Perform multiple operations
        for i in range(10):
            sample_audit_results["audit_id"] = f"20241214_12000{i}"
            repository.save_audit_run(sample_audit_results)

        # Pool should not be exhausted
        recent = repository.get_recent_audits(limit=5)
        assert len(recent) == 5
