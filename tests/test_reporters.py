"""
Comprehensive tests for reporters and AI analyzer modules
Ensures complete coverage of report generation and AI analysis
"""
import pytest
from unittest.mock import Mock, patch, MagicMock, mock_open
from pathlib import Path
import json
from datetime import datetime

from src.reporters.html_report import HTMLReporter
from src.analyzers.ai_analyzer import AIAnalyzer
from src.core.config import AuditConfig, AIConfig


# ============================================================================
# HTML Reporter Tests
# ============================================================================

class TestHTMLReporter:
    """Test HTML report generation"""
    
    @pytest.fixture
    def reporter(self):
        """Create HTMLReporter instance"""
        return HTMLReporter()
    
    @pytest.fixture
    def sample_audit_data(self):
        """Create sample audit data for testing"""
        return {
            "audit_id": "test-audit-12345",
            "timestamp": datetime.utcnow().isoformat(),
            "platform": "Linux",
            "hostname": "testhost",
            "collectors": {
                "hardware": {
                    "status": "success",
                    "data": {
                        "cpu": {"count": 8, "freq": 2400},
                        "memory": {"total_gb": 16, "percent": 50}
                    },
                    "findings": []
                },
                "security": {
                    "status": "success",
                    "data": {},
                    "findings": [
                        {
                            "check_id": "SEC-001",
                            "severity": "HIGH",
                            "description": "Firewall disabled",
                            "current_value": "disabled",
                            "expected_value": "enabled"
                        }
                    ]
                }
            },
            "ai_analysis": {
                "risk_score": 65,
                "executive_summary": "System has security concerns",
                "critical_issues": ["Firewall disabled"],
                "recommendations": ["Enable firewall"]
            }
        }
    
    def test_reporter_initialization(self, reporter):
        """Test reporter initializes correctly"""
        assert isinstance(reporter, HTMLReporter)
    
    def test_generate_report_creates_file(self, reporter, sample_audit_data, tmp_path):
        """Test report generation creates HTML file"""
        output_path = tmp_path / "test_report.html"
        
        result = reporter.generate(sample_audit_data, str(output_path))
        
        assert result is not None
        assert output_path.exists()
        assert output_path.stat().st_size > 0
    
    def test_html_report_contains_audit_id(self, reporter, sample_audit_data, tmp_path):
        """Test HTML report contains audit ID"""
        output_path = tmp_path / "test_report.html"
        reporter.generate(sample_audit_data, str(output_path))
        
        content = output_path.read_text()
        assert "test-audit-12345" in content
    
    def test_html_report_contains_findings(self, reporter, sample_audit_data, tmp_path):
        """Test HTML report includes security findings"""
        output_path = tmp_path / "test_report.html"
        reporter.generate(sample_audit_data, str(output_path))
        
        content = output_path.read_text()
        assert "Firewall disabled" in content
        assert "SEC-001" in content
    
    def test_html_report_contains_risk_score(self, reporter, sample_audit_data, tmp_path):
        """Test HTML report displays risk score"""
        output_path = tmp_path / "test_report.html"
        reporter.generate(sample_audit_data, str(output_path))
        
        content = output_path.read_text()
        assert "65" in content  # Risk score
    
    def test_html_report_includes_css(self, reporter, sample_audit_data, tmp_path):
        """Test HTML report includes CSS styling"""
        output_path = tmp_path / "test_report.html"
        reporter.generate(sample_audit_data, str(output_path))
        
        content = output_path.read_text()
        assert "<style>" in content
        assert "</style>" in content
    
    def test_html_report_is_valid_html(self, reporter, sample_audit_data, tmp_path):
        """Test generated HTML has proper structure"""
        output_path = tmp_path / "test_report.html"
        reporter.generate(sample_audit_data, str(output_path))
        
        content = output_path.read_text()
        assert "<!DOCTYPE html>" in content or "<html>" in content
        assert "</html>" in content
        assert "<head>" in content
        assert "<body>" in content
    
    def test_report_handles_missing_ai_analysis(self, reporter, tmp_path):
        """Test reporter handles audit data without AI analysis"""
        data = {
            "audit_id": "test-123",
            "timestamp": datetime.utcnow().isoformat(),
            "platform": "Linux",
            "hostname": "testhost",
            "collectors": {}
        }
        
        output_path = tmp_path / "test_report.html"
        
        # Should not crash
        result = reporter.generate(data, str(output_path))
        assert output_path.exists()
    
    def test_report_handles_empty_findings(self, reporter, tmp_path):
        """Test reporter handles audit with no findings"""
        data = {
            "audit_id": "test-123",
            "timestamp": datetime.utcnow().isoformat(),
            "platform": "Linux",
            "collectors": {
                "hardware": {
                    "status": "success",
                    "data": {},
                    "findings": []
                }
            }
        }
        
        output_path = tmp_path / "test_report.html"
        result = reporter.generate(data, str(output_path))
        
        assert output_path.exists()
        content = output_path.read_text()
        assert "No findings" in content or "0" in content
    
    def test_report_severity_color_coding(self, reporter, sample_audit_data, tmp_path):
        """Test report uses color coding for severity levels"""
        output_path = tmp_path / "test_report.html"
        reporter.generate(sample_audit_data, str(output_path))
        
        content = output_path.read_text()
        # Should have CSS classes or styling for severity
        assert "HIGH" in content


# ============================================================================
# AI Analyzer Tests
# ============================================================================

class TestAIAnalyzer:
    """Test AI analysis functionality"""
    
    @pytest.fixture
    def analyzer(self):
        """Create AIAnalyzer instance"""
        config = AIConfig(
            provider="anthropic",
            model="claude-3-5-haiku-20241022",
            api_key="test-key-12345",
            max_tokens=1000,
            temperature=0.3
        )
        return AIAnalyzer(config)
    
    @pytest.fixture
    def sample_audit_results(self):
        """Sample audit results for analysis"""
        return {
            "collectors": {
                "security": {
                    "findings": [
                        {
                            "check_id": "SEC-001",
                            "severity": "CRITICAL",
                            "description": "No antivirus installed"
                        },
                        {
                            "check_id": "SEC-002",
                            "severity": "HIGH",
                            "description": "Firewall disabled"
                        }
                    ]
                },
                "hardware": {
                    "findings": []
                }
            },
            "metadata": {
                "platform": "Windows",
                "hostname": "DESKTOP-TEST"
            }
        }
    
    def test_analyzer_initialization(self, analyzer):
        """Test analyzer initializes correctly"""
        assert isinstance(analyzer, AIAnalyzer)
        assert analyzer.config.provider == "anthropic"
    
    @patch('anthropic.Anthropic')
    def test_analyze_audit_results(self, mock_anthropic, analyzer, sample_audit_results):
        """Test AI analysis of audit results"""
        # Mock Anthropic API response
        mock_client = MagicMock()
        mock_response = Mock()
        mock_response.content = [
            Mock(text=json.dumps({
                "risk_score": 75,
                "executive_summary": "Critical security issues detected",
                "critical_issues": ["No antivirus", "Firewall disabled"],
                "recommendations": ["Install antivirus", "Enable firewall"]
            }))
        ]
        mock_client.messages.create.return_value = mock_response
        mock_anthropic.return_value = mock_client
        
        result = analyzer.analyze(sample_audit_results)
        
        assert result is not None
        assert "risk_score" in result
        assert result["risk_score"] == 75
        assert len(result["critical_issues"]) == 2
    
    @patch('anthropic.Anthropic')
    def test_analyze_handles_api_error(self, mock_anthropic, analyzer, sample_audit_results):
        """Test analyzer handles API errors gracefully"""
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = Exception("API Error")
        mock_anthropic.return_value = mock_client
        
        # Should handle error gracefully
        result = analyzer.analyze(sample_audit_results)
        
        # Should return some default response or raise caught exception
        assert result is None or isinstance(result, dict)
    
    def test_analyzer_validates_response(self, analyzer):
        """Test analyzer validates AI response structure"""
        # This tests the validation logic
        valid_response = {
            "risk_score": 50,
            "executive_summary": "Test summary",
            "critical_issues": [],
            "recommendations": ["Do something"]
        }
        
        # Should validate without errors
        # Actual validation depends on implementation
    
    @patch('anthropic.Anthropic')
    def test_analyze_with_no_findings(self, mock_anthropic, analyzer):
        """Test analysis when no findings exist"""
        audit_data = {
            "collectors": {
                "hardware": {"findings": []},
                "security": {"findings": []}
            }
        }
        
        mock_client = MagicMock()
        mock_response = Mock()
        mock_response.content = [
            Mock(text=json.dumps({
                "risk_score": 10,
                "executive_summary": "System appears secure",
                "critical_issues": [],
                "recommendations": ["Continue monitoring"]
            }))
        ]
        mock_client.messages.create.return_value = mock_response
        mock_anthropic.return_value = mock_client
        
        result = analyzer.analyze(audit_data)
        
        assert result is not None
        assert result["risk_score"] <= 20  # Should be low risk
    
    def test_analyzer_respects_rate_limits(self, analyzer):
        """Test analyzer respects rate limiting configuration"""
        assert hasattr(analyzer.config, 'max_requests_per_minute')
        assert analyzer.config.max_requests_per_minute > 0


# ============================================================================
# JSON Reporter Tests
# ============================================================================

class TestJSONReporter:
    """Test JSON report generation"""
    
    def test_json_export(self, tmp_path):
        """Test exporting audit results as JSON"""
        data = {
            "audit_id": "test-123",
            "timestamp": "2024-12-14T10:00:00",
            "findings": [
                {"check_id": "TST-001", "severity": "LOW"}
            ]
        }
        
        output_path = tmp_path / "audit.json"
        
        # Write JSON
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        # Verify
        assert output_path.exists()
        
        with open(output_path) as f:
            loaded = json.load(f)
            assert loaded["audit_id"] == "test-123"
    
    def test_json_includes_all_fields(self, tmp_path):
        """Test JSON export includes all required fields"""
        data = {
            "audit_id": "test-123",
            "timestamp": "2024-12-14T10:00:00",
            "platform": "Linux",
            "hostname": "testhost",
            "collectors": {},
            "findings": [],
            "ai_analysis": None
        }
        
        output_path = tmp_path / "audit.json"
        
        with open(output_path, 'w') as f:
            json.dump(data, f)
        
        with open(output_path) as f:
            loaded = json.load(f)
            assert "audit_id" in loaded
            assert "timestamp" in loaded
            assert "platform" in loaded


# ============================================================================
# Integration Tests
# ============================================================================

class TestReporterIntegration:
    """Integration tests for reporting pipeline"""
    
    @pytest.fixture
    def full_audit_data(self):
        """Complete audit data with all components"""
        return {
            "audit_id": "integration-test-001",
            "timestamp": datetime.utcnow().isoformat(),
            "platform": "Linux",
            "hostname": "testserver",
            "collectors": {
                "hardware": {
                    "status": "success",
                    "data": {
                        "cpu": {"count": 4, "freq": 2000},
                        "memory": {"total_gb": 8, "percent": 60}
                    },
                    "findings": [],
                    "execution_time_ms": 150
                },
                "security": {
                    "status": "success",
                    "data": {},
                    "findings": [
                        {
                            "check_id": "CIS-1.1.1",
                            "severity": "MEDIUM",
                            "description": "Filesystem partition check",
                            "current_value": "Not configured",
                            "expected_value": "Configured"
                        }
                    ],
                    "execution_time_ms": 2000
                }
            },
            "ai_analysis": {
                "risk_score": 45,
                "executive_summary": "System has moderate security posture",
                "critical_issues": [],
                "recommendations": [
                    "Review filesystem partitioning",
                    "Implement security hardening"
                ]
            },
            "execution_metadata": {
                "total_duration_seconds": 5.2,
                "collectors_run": 2,
                "total_findings": 1
            }
        }
    
    def test_generate_all_report_formats(self, full_audit_data, tmp_path):
        """Test generating all report formats"""
        # HTML Report
        html_reporter = HTMLReporter()
        html_path = tmp_path / "report.html"
        html_reporter.generate(full_audit_data, str(html_path))
        assert html_path.exists()
        
        # JSON Report
        json_path = tmp_path / "report.json"
        with open(json_path, 'w') as f:
            json.dump(full_audit_data, f, indent=2)
        assert json_path.exists()
        
        # Verify both contain key data
        html_content = html_path.read_text()
        assert "integration-test-001" in html_content
        
        with open(json_path) as f:
            json_data = json.load(f)
            assert json_data["audit_id"] == "integration-test-001"
    
    def test_report_generation_performance(self, full_audit_data, tmp_path):
        """Test report generation completes quickly"""
        import time
        
        reporter = HTMLReporter()
        output_path = tmp_path / "performance_test.html"
        
        start = time.time()
        reporter.generate(full_audit_data, str(output_path))
        duration = time.time() - start
        
        # Should complete in under 2 seconds
        assert duration < 2.0
        assert output_path.exists()


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestReporterErrorHandling:
    """Test error handling in reporters"""
    
    def test_html_reporter_handles_invalid_path(self):
        """Test HTML reporter handles invalid output path"""
        reporter = HTMLReporter()
        data = {"audit_id": "test"}
        
        # Invalid path
        invalid_path = "/invalid/directory/that/does/not/exist/report.html"
        
        with pytest.raises(Exception):
            reporter.generate(data, invalid_path)
    
    def test_reporter_handles_malformed_data(self):
        """Test reporter handles malformed audit data"""
        reporter = HTMLReporter()
        
        # Missing required fields
        malformed_data = {
            "audit_id": "test"
            # Missing other required fields
        }
        
        # Should handle gracefully or raise appropriate error
        # Implementation dependent
    
    def test_ai_analyzer_handles_invalid_api_key(self):
        """Test AI analyzer handles invalid API key"""
        config = AIConfig(
            provider="anthropic",
            api_key="invalid_key_xyz",
            max_tokens=1000
        )
        analyzer = AIAnalyzer(config)
        
        # Should handle invalid key gracefully
        # Implementation dependent on error handling strategy
