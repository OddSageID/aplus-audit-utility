"""
Comprehensive tests for input validation module.
Tests all validation schemas and edge cases.
"""

import pytest
from pydantic import ValidationError

from src.core.validation import (
    CLIArgumentsSchema,
    AIAnalysisResponseSchema,
    FindingSchema,
    RemediationScriptSchema,
    AuditConfigSchema,
    DatabaseConfigSchema,
    RateLimitConfigSchema,
    validate_cli_args,
    validate_ai_response,
    validate_finding,
)


class TestCLIArgumentsValidation:
    """Test suite for CLI arguments validation"""

    def test_valid_cli_args(self):
        """Test validation of valid CLI arguments"""
        args = {
            "quick": False,
            "no_admin": False,
            "no_remediation": False,
            "verbose": True,
            "ai": "anthropic",
            "collectors": ["hardware", "security"],
            "formats": ["html", "json"],
            "model": "claude-3-5-haiku-20241022",
            "output": "./test_output",
        }

        validated = validate_cli_args(args)
        assert validated.verbose is True
        assert validated.ai == "anthropic"
        assert len(validated.collectors) == 2

    def test_path_traversal_detection(self):
        """Test that path traversal is detected and rejected"""
        args = {"output": "../../../etc/passwd"}

        with pytest.raises(ValidationError) as exc_info:
            validate_cli_args(args)

        assert "Path traversal" in str(exc_info.value)

    def test_system_directory_protection(self):
        """Test that writing to system directories is blocked"""
        dangerous_paths = ["/etc/config", "/sys/kernel", "C:\\Windows\\System32"]

        for path in dangerous_paths:
            with pytest.raises(ValidationError):
                validate_cli_args({"output": path})

    def test_empty_collectors_rejected(self):
        """Test that empty collectors list is rejected"""
        with pytest.raises(ValidationError) as exc_info:
            CLIArgumentsSchema(collectors=[])

        assert "At least one collector" in str(exc_info.value)

    def test_invalid_collector_name(self):
        """Test that invalid collector names are rejected"""
        with pytest.raises(ValidationError):
            CLIArgumentsSchema(collectors=["invalid_collector"])

    def test_model_string_constraints(self):
        """Test model name string constraints"""
        # Too long
        with pytest.raises(ValidationError):
            CLIArgumentsSchema(model="x" * 101)

        # Empty string
        with pytest.raises(ValidationError):
            CLIArgumentsSchema(model="")

    def test_output_path_length_limit(self):
        """Test output path length limit"""
        with pytest.raises(ValidationError):
            CLIArgumentsSchema(output="x" * 501)


class TestAIAnalysisResponseValidation:
    """Test suite for AI response validation"""

    def test_valid_ai_response(self):
        """Test validation of valid AI response"""
        response = {
            "risk_score": 65,
            "executive_summary": "System has 12 security findings requiring immediate attention.",
            "critical_issues": ["Windows Defender disabled", "Firewall not active"],
            "recommendations": [
                "Enable Windows Defender Real-time Protection",
                "Activate Windows Firewall",
            ],
        }

        validated = validate_ai_response(response)
        assert validated.risk_score == 65
        assert len(validated.critical_issues) == 2
        assert len(validated.recommendations) == 2

    def test_risk_score_boundaries(self):
        """Test risk score must be 0-100"""
        # Below minimum
        with pytest.raises(ValidationError):
            AIAnalysisResponseSchema(
                risk_score=-1,
                executive_summary="Test summary",
                recommendations=["Test"],
            )

        # Above maximum
        with pytest.raises(ValidationError):
            AIAnalysisResponseSchema(
                risk_score=101,
                executive_summary="Test summary",
                recommendations=["Test"],
            )

        # Valid boundaries
        assert (
            AIAnalysisResponseSchema(
                risk_score=0, executive_summary="Test summary", recommendations=["Test"]
            ).risk_score
            == 0
        )

        assert (
            AIAnalysisResponseSchema(
                risk_score=100,
                executive_summary="Test summary",
                recommendations=["Test"],
            ).risk_score
            == 100
        )

    def test_script_injection_prevention(self):
        """Test that script tags are rejected"""
        with pytest.raises(ValidationError) as exc_info:
            AIAnalysisResponseSchema(
                risk_score=50,
                executive_summary='<script>alert("xss")</script>Test',
                recommendations=["Test"],
            )

        assert "Script tags not allowed" in str(exc_info.value)

    def test_javascript_injection_prevention(self):
        """Test that javascript: protocol is rejected"""
        with pytest.raises(ValidationError):
            AIAnalysisResponseSchema(
                risk_score=50,
                executive_summary="Valid summary",
                recommendations=['javascript:alert("xss")'],
            )

    def test_summary_length_constraints(self):
        """Test executive summary length constraints"""
        # Too short
        with pytest.raises(ValidationError):
            AIAnalysisResponseSchema(
                risk_score=50, executive_summary="Short", recommendations=["Test"]
            )

        # Too long
        with pytest.raises(ValidationError):
            AIAnalysisResponseSchema(
                risk_score=50, executive_summary="x" * 2001, recommendations=["Test"]
            )

    def test_list_item_length_limits(self):
        """Test that list items have length limits"""
        with pytest.raises(ValidationError):
            AIAnalysisResponseSchema(
                risk_score=50,
                executive_summary="Valid summary text here",
                recommendations=["x" * 501],
            )

    def test_max_list_items(self):
        """Test maximum number of list items"""
        with pytest.raises(ValidationError):
            AIAnalysisResponseSchema(
                risk_score=50,
                executive_summary="Valid summary text here",
                critical_issues=[f"Issue {i}" for i in range(51)],
            )


class TestFindingValidation:
    """Test suite for finding validation"""

    def test_valid_finding(self):
        """Test validation of valid finding"""
        finding = {
            "check_id": "CIS-10.1-001",
            "severity": "CRITICAL",
            "description": "Windows Defender Real-time Protection is disabled",
            "current_value": "Disabled",
            "expected_value": "Enabled",
            "remediation_hint": "Enable via Windows Security settings",
        }

        validated = validate_finding(finding)
        assert validated.check_id == "CIS-10.1-001"
        assert validated.severity == "CRITICAL"

    def test_check_id_format(self):
        """Test check ID format validation"""
        # Valid formats
        valid_ids = ["CIS-1.1-001", "HW-001", "SEC.001", "A-B-C-1-2-3"]
        for check_id in valid_ids:
            finding = FindingSchema(
                check_id=check_id,
                severity="LOW",
                description="Test finding description",
                current_value="Current",
                expected_value="Expected",
            )
            assert finding.check_id == check_id

        # Invalid formats (lowercase, special chars)
        invalid_ids = ["cis-1.1-001", "test@123", "test finding"]
        for check_id in invalid_ids:
            with pytest.raises(ValidationError):
                FindingSchema(
                    check_id=check_id,
                    severity="LOW",
                    description="Test finding description",
                    current_value="Current",
                    expected_value="Expected",
                )

    def test_severity_enum(self):
        """Test severity must be valid enum value"""
        valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

        for severity in valid_severities:
            finding = FindingSchema(
                check_id="TEST-001",
                severity=severity,
                description="Test finding description",
                current_value="Current",
                expected_value="Expected",
            )
            assert finding.severity == severity

        # Invalid severity
        with pytest.raises(ValidationError):
            FindingSchema(
                check_id="TEST-001",
                severity="INVALID",
                description="Test finding description",
                current_value="Current",
                expected_value="Expected",
            )

    def test_description_length(self):
        """Test description length constraints"""
        # Too short
        with pytest.raises(ValidationError):
            FindingSchema(
                check_id="TEST-001",
                severity="LOW",
                description="Short",
                current_value="Current",
                expected_value="Expected",
            )

        # Too long
        with pytest.raises(ValidationError):
            FindingSchema(
                check_id="TEST-001",
                severity="LOW",
                description="x" * 1001,
                current_value="Current",
                expected_value="Expected",
            )


class TestRemediationScriptValidation:
    """Test suite for remediation script validation"""

    def test_valid_script(self):
        """Test validation of valid remediation script"""
        script = RemediationScriptSchema(
            filename="remediate_CIS-10.1-001.ps1",
            content="# Enable Windows Defender\nSet-MpPreference -DisableRealtimeMonitoring $false",
            check_id="CIS-10.1-001",
        )
        assert script.filename == "remediate_CIS-10.1-001.ps1"

    def test_filename_path_traversal(self):
        """Test that path traversal in filenames is blocked"""
        invalid_filenames = [
            "../../../etc/passwd.sh",
            "subdir/script.ps1",
            "C:\\Windows\\script.bat",
        ]

        for filename in invalid_filenames:
            with pytest.raises(ValidationError):
                RemediationScriptSchema(filename=filename, content="echo test", check_id="TEST-001")

    def test_valid_extensions(self):
        """Test that only valid script extensions are allowed"""
        valid_filenames = ["test.ps1", "test.sh", "test.bat"]
        for filename in valid_filenames:
            script = RemediationScriptSchema(
                filename=filename, content="echo test", check_id="TEST-001"
            )
            assert script.filename == filename

        # Invalid extension
        with pytest.raises(ValidationError):
            RemediationScriptSchema(filename="test.exe", content="echo test", check_id="TEST-001")

    def test_dangerous_pattern_detection(self):
        """Test that dangerous script patterns are detected"""
        dangerous_scripts = [
            "rm -rf /",
            "del /f /q C:\\",
            "format C:",
            ":(){:|:&};:",  # Fork bomb
        ]

        for content in dangerous_scripts:
            with pytest.raises(ValidationError) as exc_info:
                RemediationScriptSchema(filename="test.sh", content=content, check_id="TEST-001")
            assert "dangerous pattern" in str(exc_info.value).lower()


class TestDatabaseConfigValidation:
    """Test suite for database configuration validation"""

    def test_valid_sqlite_url(self):
        """Test validation of SQLite URLs"""
        config = DatabaseConfigSchema(database_url="sqlite:///./test.db")
        assert config.database_url == "sqlite:///./test.db"

    def test_valid_postgresql_url(self):
        """Test validation of PostgreSQL URLs"""
        config = DatabaseConfigSchema(database_url="postgresql://user:pass@localhost:5432/audit_db")
        assert "postgresql://" in config.database_url

    def test_invalid_database_prefix(self):
        """Test that invalid database prefixes are rejected"""
        with pytest.raises(ValidationError):
            DatabaseConfigSchema(database_url="mongodb://localhost/test")

    def test_sql_injection_prevention(self):
        """Test that SQL injection attempts are detected"""
        with pytest.raises(ValidationError):
            DatabaseConfigSchema(
                database_url="postgresql://user:pass@localhost/db;DROP TABLE users--"
            )


class TestRateLimitConfigValidation:
    """Test suite for rate limit configuration validation"""

    def test_valid_config(self):
        """Test validation of valid rate limit config"""
        config = RateLimitConfigSchema(
            max_requests_per_minute=100,
            max_requests_per_hour=5000,
            max_concurrent_requests=10,
        )
        assert config.max_requests_per_minute == 100

    def test_boundary_values(self):
        """Test boundary value validation"""
        # Minimum values
        config = RateLimitConfigSchema(
            max_requests_per_minute=1,
            max_requests_per_hour=1,
            max_concurrent_requests=1,
        )
        assert config.max_requests_per_minute == 1

        # Below minimum
        with pytest.raises(ValidationError):
            RateLimitConfigSchema(max_requests_per_minute=0)

        # Above maximum
        with pytest.raises(ValidationError):
            RateLimitConfigSchema(max_requests_per_minute=1001)

    def test_consistency_validation(self):
        """Test that hourly limit is consistent with per-minute limit"""
        # This should fail: per-minute * 60 should be >= hourly
        with pytest.raises(ValidationError):
            RateLimitConfigSchema(
                max_requests_per_minute=100,
                max_requests_per_hour=1000,  # 100*60=6000, but hourly is only 1000
            )


class TestAuditConfigValidation:
    """Test suite for audit configuration validation"""

    def test_valid_config(self):
        """Test validation of valid audit config"""
        config = AuditConfigSchema(require_admin=True, timeout_seconds=600, log_level="INFO")
        assert config.timeout_seconds == 600
        assert config.log_level == "INFO"

    def test_timeout_boundaries(self):
        """Test timeout value boundaries"""
        # Too low
        with pytest.raises(ValidationError):
            AuditConfigSchema(timeout_seconds=5)

        # Too high
        with pytest.raises(ValidationError):
            AuditConfigSchema(timeout_seconds=3601)

        # Valid
        config = AuditConfigSchema(timeout_seconds=300)
        assert config.timeout_seconds == 300

    def test_log_level_validation(self):
        """Test log level validation"""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        for level in valid_levels:
            config = AuditConfigSchema(log_level=level)
            assert config.log_level == level

        # Invalid level
        with pytest.raises(ValidationError):
            AuditConfigSchema(log_level="INVALID")

    def test_cis_level_validation(self):
        """Test CIS benchmark level validation"""
        # Valid levels
        for level in [1, 2]:
            config = AuditConfigSchema(cis_level=level)
            assert config.cis_level == level

        # Invalid levels
        for level in [0, 3]:
            with pytest.raises(ValidationError):
                AuditConfigSchema(cis_level=level)


# Integration tests
class TestValidationIntegration:
    """Integration tests for validation workflows"""

    def test_full_cli_workflow(self):
        """Test complete CLI argument validation workflow"""
        raw_args = {
            "quick": False,
            "no_admin": True,
            "ai": "anthropic",
            "collectors": ["security", "network"],
            "formats": ["html"],
            "output": "./safe_output",
            "verbose": True,
        }

        validated = validate_cli_args(raw_args)
        assert validated.no_admin is True
        assert "security" in validated.collectors

    def test_malicious_input_chain(self):
        """Test that chained malicious inputs are all blocked"""
        # Path traversal + injection
        with pytest.raises(ValidationError):
            validate_cli_args({"output": "../../../etc/passwd<script>alert(1)</script>"})

        # AI response with multiple attack vectors
        with pytest.raises(ValidationError):
            validate_ai_response(
                {
                    "risk_score": 150,  # Out of range
                    "executive_summary": "<script>evil</script>",  # XSS
                    "recommendations": ["javascript:alert(1)"],  # Protocol injection
                }
            )
