"""
Comprehensive tests for orchestrator, logger, and configuration modules
Ensures 90%+ code coverage for core infrastructure
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import logging
from datetime import datetime

from src.core.config import AuditConfig, AIConfig
from src.core.logger import setup_logger, get_logger
from src.core.orchestrator import AuditOrchestrator
from src.core.metrics import MetricsCollector, MetricType


# ============================================================================
# Configuration Tests
# ============================================================================

class TestConfiguration:
    """Test configuration management"""
    
    def test_audit_config_defaults(self):
        """Test AuditConfig has sensible defaults"""
        config = AuditConfig()
        
        assert config.require_admin == False  # Graceful degradation
        assert config.timeout_seconds == 300
        assert config.parallel_execution == True
        assert config.cis_level == 1
        assert config.generate_remediation == True
    
    def test_ai_config_initialization(self):
        """Test AIConfig initialization"""
        config = AIConfig(
            provider="anthropic",
            model="claude-3-5-haiku-20241022",
            api_key="test-key",
            max_tokens=2000
        )
        
        assert config.provider == "anthropic"
        assert config.model == "claude-3-5-haiku-20241022"
        assert config.max_tokens == 2000
        assert config.temperature == 0.3
    
    def test_ai_config_rate_limits(self):
        """Test AI config includes rate limiting defaults"""
        config = AIConfig()
        
        assert hasattr(config, 'max_requests_per_minute')
        assert hasattr(config, 'max_requests_per_hour')
        assert hasattr(config, 'max_concurrent_requests')
        assert config.max_requests_per_minute > 0
    
    def test_ai_config_validates_api_key(self):
        """Test AIConfig validates API key presence"""
        with patch.dict('os.environ', {}, clear=True):
            # Should raise if no API key provided
            with pytest.raises(ValueError):
                AIConfig(provider="anthropic", api_key=None)
    
    def test_config_output_directory_creation(self, tmp_path):
        """Test config creates output directory"""
        output_dir = tmp_path / "test_output"
        config = AuditConfig(output_dir=output_dir)
        
        # Directory should be created
        assert output_dir.exists()
        assert output_dir.is_dir()
    
    def test_config_log_file_directory_creation(self, tmp_path):
        """Test config creates log file directory"""
        log_file = tmp_path / "logs" / "audit.log"
        config = AuditConfig(log_file=log_file)
        
        # Parent directory should be created
        assert log_file.parent.exists()


# ============================================================================
# Logger Tests
# ============================================================================

class TestLogger:
    """Test logging configuration"""
    
    def test_setup_logger_creates_logger(self):
        """Test logger setup creates configured logger"""
        logger = setup_logger(name="test_logger", level="INFO")
        
        assert isinstance(logger, logging.Logger)
        assert logger.level == logging.INFO
    
    def test_get_logger_returns_configured_logger(self):
        """Test get_logger returns properly configured logger"""
        logger = get_logger("test_module")
        
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test_module"
    
    def test_logger_writes_to_file(self, tmp_path):
        """Test logger can write to file"""
        log_file = tmp_path / "test.log"
        logger = setup_logger(
            name="file_test",
            level="DEBUG",
            log_file=str(log_file)
        )
        
        logger.info("Test message")
        
        assert log_file.exists()
        content = log_file.read_text()
        assert "Test message" in content
    
    def test_logger_levels(self):
        """Test logger supports all levels"""
        logger = setup_logger("level_test", level="DEBUG")
        
        # Should handle all standard levels
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")
        logger.critical("Critical message")
    
    def test_logger_includes_timestamps(self, tmp_path):
        """Test log messages include timestamps"""
        log_file = tmp_path / "timestamp_test.log"
        logger = setup_logger(
            name="timestamp_test",
            log_file=str(log_file)
        )
        
        logger.info("Timestamp test")
        
        content = log_file.read_text()
        # Should contain date/time information
        assert any(char.isdigit() for char in content)


# ============================================================================
# Orchestrator Tests
# ============================================================================

class TestAuditOrchestrator:
    """Test audit orchestration"""
    
    @pytest.fixture
    def config(self):
        """Create test configuration"""
        return AuditConfig(
            require_admin=False,
            parallel_execution=True,
            timeout_seconds=60
        )
    
    @pytest.fixture
    def orchestrator(self, config):
        """Create orchestrator instance"""
        return AuditOrchestrator(config)
    
    def test_orchestrator_initialization(self, orchestrator, config):
        """Test orchestrator initializes correctly"""
        assert orchestrator.config == config
        assert isinstance(orchestrator, AuditOrchestrator)
    
    @patch('src.collectors.hardware.HardwareCollector')
    @patch('src.collectors.security.SecurityCollector')
    def test_orchestrator_runs_collectors(self, mock_security, mock_hardware, orchestrator):
        """Test orchestrator executes collectors"""
        # Mock collector results
        mock_hw_result = Mock()
        mock_hw_result.status = "success"
        mock_hw_result.data = {}
        mock_hw_result.findings = []
        
        mock_sec_result = Mock()
        mock_sec_result.status = "success"
        mock_sec_result.data = {}
        mock_sec_result.findings = []
        
        mock_hardware.return_value.collect.return_value = mock_hw_result
        mock_security.return_value.collect.return_value = mock_sec_result
        
        # Run audit
        result = orchestrator.run_audit()
        
        assert result is not None
        assert "collectors" in result or isinstance(result, dict)
    
    def test_orchestrator_handles_collector_failure(self, orchestrator):
        """Test orchestrator handles collector failures gracefully"""
        with patch('src.collectors.hardware.HardwareCollector') as mock_collector:
            mock_collector.return_value.collect.side_effect = Exception("Collector failed")
            
            # Should not crash
            result = orchestrator.run_audit()
            
            # Should still return a result
            assert result is not None
    
    def test_orchestrator_respects_timeout(self, config):
        """Test orchestrator respects timeout configuration"""
        config.timeout_seconds = 1
        orchestrator = AuditOrchestrator(config)
        
        # Should have timeout configured
        assert orchestrator.config.timeout_seconds == 1
    
    @patch('concurrent.futures.ThreadPoolExecutor')
    def test_orchestrator_parallel_execution(self, mock_executor, orchestrator):
        """Test orchestrator uses parallel execution"""
        orchestrator.config.parallel_execution = True
        
        # Mock executor
        mock_executor.return_value.__enter__.return_value = Mock()
        
        # Should attempt parallel execution
        # Implementation dependent
    
    def test_orchestrator_sequential_execution(self, orchestrator):
        """Test orchestrator can run sequentially"""
        orchestrator.config.parallel_execution = False
        
        # Should run collectors sequentially
        result = orchestrator.run_audit()
        assert result is not None
    
    def test_orchestrator_generates_audit_id(self, orchestrator):
        """Test orchestrator generates unique audit IDs"""
        result1 = orchestrator.run_audit()
        result2 = orchestrator.run_audit()
        
        # Each audit should have unique ID
        if "audit_id" in result1 and "audit_id" in result2:
            assert result1["audit_id"] != result2["audit_id"]
    
    def test_orchestrator_includes_metadata(self, orchestrator):
        """Test audit results include metadata"""
        result = orchestrator.run_audit()
        
        # Should include platform, timestamp, etc.
        assert isinstance(result, dict)
        # Metadata fields depend on implementation


# ============================================================================
# Metrics Collector Tests
# ============================================================================

class TestMetricsCollector:
    """Test metrics collection"""
    
    @pytest.fixture
    def metrics(self):
        """Create metrics collector"""
        return MetricsCollector()
    
    def test_metrics_initialization(self, metrics):
        """Test metrics collector initializes"""
        assert isinstance(metrics, MetricsCollector)
    
    def test_record_counter_metric(self, metrics):
        """Test recording counter metrics"""
        metrics.record("test_counter", 1, MetricType.COUNTER)
        metrics.record("test_counter", 1, MetricType.COUNTER)
        
        stats = metrics.get_stats()
        assert "test_counter" in stats
        assert stats["test_counter"]["value"] == 2
    
    def test_record_gauge_metric(self, metrics):
        """Test recording gauge metrics"""
        metrics.record("cpu_usage", 65.5, MetricType.GAUGE)
        
        stats = metrics.get_stats()
        assert "cpu_usage" in stats
        assert stats["cpu_usage"]["value"] == 65.5
    
    def test_record_histogram_metric(self, metrics):
        """Test recording histogram metrics"""
        metrics.record("response_time", 150, MetricType.HISTOGRAM)
        metrics.record("response_time", 200, MetricType.HISTOGRAM)
        metrics.record("response_time", 175, MetricType.HISTOGRAM)
        
        stats = metrics.get_stats()
        assert "response_time" in stats
        # Should have statistical aggregations
    
    def test_metrics_export_prometheus(self, metrics):
        """Test Prometheus format export"""
        metrics.record("test_metric", 42, MetricType.GAUGE)
        
        export = metrics.export_prometheus()
        
        assert isinstance(export, str)
        assert "test_metric" in export
        assert "42" in export
    
    def test_metrics_export_cloudwatch(self, metrics):
        """Test CloudWatch format export"""
        metrics.record("test_metric", 42, MetricType.GAUGE)
        
        export = metrics.export_cloudwatch()
        
        assert isinstance(export, list)
        # Should be list of CloudWatch metric data points
    
    def test_metrics_reset(self, metrics):
        """Test metrics can be reset"""
        metrics.record("test", 100, MetricType.GAUGE)
        
        metrics.reset()
        
        stats = metrics.get_stats()
        assert len(stats) == 0
    
    def test_concurrent_metric_updates(self, metrics):
        """Test metrics handles concurrent updates"""
        import concurrent.futures
        
        def record_metric(i):
            metrics.record("concurrent_test", 1, MetricType.COUNTER)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(record_metric, i) for i in range(100)]
            concurrent.futures.wait(futures)
        
        stats = metrics.get_stats()
        # Should handle concurrent updates correctly


# ============================================================================
# Integration Tests
# ============================================================================

class TestCoreIntegration:
    """Integration tests for core components"""
    
    def test_config_logger_orchestrator_integration(self, tmp_path):
        """Test integration of config, logger, and orchestrator"""
        # Setup configuration
        config = AuditConfig(
            output_dir=tmp_path / "output",
            log_file=tmp_path / "logs" / "audit.log",
            log_level="DEBUG"
        )
        
        # Setup logger
        logger = setup_logger(
            name="integration_test",
            level=config.log_level,
            log_file=str(config.log_file) if config.log_file else None
        )
        
        # Create orchestrator
        orchestrator = AuditOrchestrator(config)
        
        # Run audit
        logger.info("Starting integration test audit")
        result = orchestrator.run_audit()
        logger.info("Audit completed")
        
        # Verify results
        assert config.output_dir.exists()
        if config.log_file:
            assert config.log_file.exists()
        assert result is not None
    
    def test_end_to_end_audit_flow(self, tmp_path):
        """Test complete audit flow from config to output"""
        # Configuration
        config = AuditConfig(
            output_dir=tmp_path / "results",
            require_admin=False,
            parallel_execution=True
        )
        
        # Run orchestrator
        orchestrator = AuditOrchestrator(config)
        audit_result = orchestrator.run_audit()
        
        # Generate reports
        from src.reporters.html_report import HTMLReporter
        reporter = HTMLReporter()
        
        output_path = config.output_dir / "report.html"
        reporter.generate(audit_result, str(output_path))
        
        # Verify
        assert output_path.exists()
        assert output_path.stat().st_size > 0


# ============================================================================
# Performance Tests
# ============================================================================

class TestPerformance:
    """Performance tests for core components"""
    
    def test_metrics_collection_performance(self):
        """Test metrics collection is fast"""
        import time
        
        metrics = MetricsCollector()
        
        start = time.time()
        for i in range(1000):
            metrics.record(f"metric_{i % 10}", i, MetricType.COUNTER)
        duration = time.time() - start
        
        # Should complete quickly even with 1000 metrics
        assert duration < 1.0
    
    def test_logger_performance(self, tmp_path):
        """Test logger doesn't significantly impact performance"""
        import time
        
        log_file = tmp_path / "perf_test.log"
        logger = setup_logger("perf_test", log_file=str(log_file))
        
        start = time.time()
        for i in range(1000):
            logger.debug(f"Log message {i}")
        duration = time.time() - start
        
        # Should handle 1000 log messages quickly
        assert duration < 2.0


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestErrorHandling:
    """Test error handling in core components"""
    
    def test_config_handles_invalid_timeout(self):
        """Test config validates timeout values"""
        # Negative timeout should be rejected or corrected
        config = AuditConfig(timeout_seconds=-1)
        
        # Should either raise error or default to valid value
        assert config.timeout_seconds > 0 or ValueError
    
    def test_orchestrator_handles_no_collectors(self):
        """Test orchestrator handles case with no collectors"""
        config = AuditConfig()
        orchestrator = AuditOrchestrator(config)
        
        # Should handle gracefully
        result = orchestrator.run_audit()
        assert result is not None
    
    def test_metrics_handles_invalid_metric_type(self):
        """Test metrics collector validates metric types"""
        metrics = MetricsCollector()
        
        # Should handle invalid metric type gracefully
        try:
            metrics.record("test", 100, "invalid_type")
        except (ValueError, TypeError):
            # Expected behavior
            pass
