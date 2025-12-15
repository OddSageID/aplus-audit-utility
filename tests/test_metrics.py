"""
Tests for metrics collection and export functionality.
"""

import pytest
from datetime import datetime, timedelta
import json

from src.core.metrics import AuditMetrics, MetricsCollector, MetricType


@pytest.fixture
def sample_metrics():
    """Create sample audit metrics"""
    return AuditMetrics(
        audit_id="20241214_120000",
        timestamp=datetime.utcnow(),
        hostname="test-server",
        platform="Linux",
        duration_seconds=45.2,
        collectors_total=4,
        collectors_executed=4,
        collectors_failed=0,
        collectors_skipped=0,
        findings_total=12,
        findings_critical=2,
        findings_high=4,
        findings_medium=5,
        findings_low=1,
        findings_info=0,
        risk_score=65,
        risk_level="HIGH",
        ai_provider="anthropic",
        ai_model="claude-3-5-haiku-20241022",
        ai_api_calls=3,
        ai_api_latency_ms=250.5,
        ai_api_errors=0,
        ai_tokens_used=1500,
        remediation_scripts_generated=2,
        rate_limit_hits=0,
        circuit_breaker_opens=0,
        memory_used_mb=150.5,
        cpu_percent=25.3,
    )


class TestAuditMetrics:
    """Test AuditMetrics dataclass"""

    def test_metrics_creation(self, sample_metrics):
        """Test creating metrics object"""
        assert sample_metrics.audit_id == "20241214_120000"
        assert sample_metrics.risk_score == 65
        assert sample_metrics.findings_total == 12

    def test_to_dict(self, sample_metrics):
        """Test converting metrics to dictionary"""
        data = sample_metrics.to_dict()

        assert isinstance(data, dict)
        assert data["audit_id"] == "20241214_120000"
        assert data["risk_score"] == 65
        assert "timestamp" in data
        assert isinstance(data["timestamp"], str)  # Should be ISO format

    def test_to_json(self, sample_metrics):
        """Test JSON serialization"""
        json_str = sample_metrics.to_json()

        assert isinstance(json_str, str)
        data = json.loads(json_str)
        assert data["audit_id"] == "20241214_120000"
        assert data["risk_score"] == 65

    def test_to_json_compact(self, sample_metrics):
        """Test compact JSON serialization"""
        json_str = sample_metrics.to_json(pretty=False)

        assert isinstance(json_str, str)
        assert "\n" not in json_str  # No newlines in compact format


class TestPrometheusExport:
    """Test Prometheus format export"""

    def test_prometheus_format(self, sample_metrics):
        """Test Prometheus exposition format"""
        prom_output = sample_metrics.to_prometheus()

        assert isinstance(prom_output, str)
        assert "audit_duration_seconds" in prom_output
        assert "audit_risk_score" in prom_output
        assert "audit_findings_total" in prom_output

    def test_prometheus_labels(self, sample_metrics):
        """Test that Prometheus metrics include labels"""
        prom_output = sample_metrics.to_prometheus()

        assert 'audit_id="20241214_120000"' in prom_output
        assert 'hostname="test-server"' in prom_output
        assert 'platform="Linux"' in prom_output

    def test_prometheus_metric_types(self, sample_metrics):
        """Test that metric types are specified"""
        prom_output = sample_metrics.to_prometheus()

        assert "# TYPE audit_duration_seconds gauge" in prom_output
        assert "# TYPE audit_collectors_failed counter" in prom_output
        assert "# TYPE audit_risk_score gauge" in prom_output

    def test_prometheus_help_text(self, sample_metrics):
        """Test that help text is included"""
        prom_output = sample_metrics.to_prometheus()

        assert "# HELP audit_duration_seconds" in prom_output
        assert "# HELP audit_findings_total" in prom_output

    def test_prometheus_ai_metrics_conditional(self, sample_metrics):
        """Test that AI metrics only included when AI is used"""
        # With AI
        prom_output = sample_metrics.to_prometheus()
        assert "audit_ai_api_calls" in prom_output

        # Without AI
        sample_metrics.ai_provider = None
        prom_output = sample_metrics.to_prometheus()
        assert "audit_ai_api_calls" not in prom_output


class TestCloudWatchExport:
    """Test CloudWatch format export"""

    def test_cloudwatch_format(self, sample_metrics):
        """Test CloudWatch metric format"""
        cw_metrics = sample_metrics.to_cloudwatch()

        assert isinstance(cw_metrics, list)
        assert len(cw_metrics) > 0

        # Check first metric structure
        metric = cw_metrics[0]
        assert "MetricName" in metric
        assert "Dimensions" in metric
        assert "Timestamp" in metric
        assert "Value" in metric
        assert "Unit" in metric

    def test_cloudwatch_dimensions(self, sample_metrics):
        """Test that dimensions are set correctly"""
        cw_metrics = sample_metrics.to_cloudwatch()

        metric = cw_metrics[0]
        dimensions = metric["Dimensions"]

        assert len(dimensions) == 2
        assert any(d["Name"] == "Hostname" and d["Value"] == "test-server" for d in dimensions)
        assert any(d["Name"] == "Platform" and d["Value"] == "Linux" for d in dimensions)

    def test_cloudwatch_units(self, sample_metrics):
        """Test that appropriate units are used"""
        cw_metrics = sample_metrics.to_cloudwatch()

        # Find specific metrics and check units
        duration_metric = next(m for m in cw_metrics if m["MetricName"] == "AuditDuration")
        assert duration_metric["Unit"] == "Seconds"

        findings_metric = next(m for m in cw_metrics if m["MetricName"] == "FindingsTotal")
        assert findings_metric["Unit"] == "Count"


class TestAlertGeneration:
    """Test alert generation from metrics"""

    def test_critical_findings_alert(self, sample_metrics):
        """Test alert generated for critical findings"""
        sample_metrics.findings_critical = 5

        alerts = sample_metrics.get_alerts()

        critical_alert = next((a for a in alerts if a["metric"] == "findings_critical"), None)
        assert critical_alert is not None
        assert critical_alert["severity"] == "CRITICAL"
        assert "5" in critical_alert["message"]

    def test_high_risk_score_alert(self, sample_metrics):
        """Test alert generated for high risk score"""
        sample_metrics.risk_score = 85

        alerts = sample_metrics.get_alerts()

        risk_alert = next((a for a in alerts if a["metric"] == "risk_score"), None)
        assert risk_alert is not None
        assert risk_alert["severity"] == "HIGH"
        assert "85" in risk_alert["message"]

    def test_collector_failure_alert(self, sample_metrics):
        """Test alert generated for collector failures"""
        sample_metrics.collectors_total = 10
        sample_metrics.collectors_failed = 3  # 30% failure rate

        alerts = sample_metrics.get_alerts()

        failure_alert = next((a for a in alerts if a["metric"] == "collectors_failed"), None)
        assert failure_alert is not None
        assert failure_alert["severity"] == "WARNING"

    def test_ai_error_rate_alert(self, sample_metrics):
        """Test alert generated for AI API errors"""
        sample_metrics.ai_api_calls = 10
        sample_metrics.ai_api_errors = 2  # 20% error rate

        alerts = sample_metrics.get_alerts()

        api_alert = next((a for a in alerts if a["metric"] == "ai_api_errors"), None)
        assert api_alert is not None
        assert api_alert["severity"] == "WARNING"

    def test_circuit_breaker_alert(self, sample_metrics):
        """Test alert generated for circuit breaker activation"""
        sample_metrics.circuit_breaker_opens = 2

        alerts = sample_metrics.get_alerts()

        cb_alert = next((a for a in alerts if a["metric"] == "circuit_breaker_opens"), None)
        assert cb_alert is not None
        assert cb_alert["severity"] == "WARNING"

    def test_no_alerts_when_healthy(self, sample_metrics):
        """Test no alerts for healthy system"""
        sample_metrics.findings_critical = 0
        sample_metrics.findings_high = 0
        sample_metrics.risk_score = 15
        sample_metrics.collectors_failed = 0
        sample_metrics.ai_api_errors = 0

        alerts = sample_metrics.get_alerts()

        assert len(alerts) == 0


class TestMetricsCollector:
    """Test metrics aggregation and trend analysis"""

    def test_record_metrics(self, sample_metrics):
        """Test recording metrics"""
        collector = MetricsCollector()

        collector.record(sample_metrics)

        assert len(collector.metrics_history) == 1
        assert collector.metrics_history[0].audit_id == "20241214_120000"

    def test_get_trends(self, sample_metrics):
        """Test trend calculation"""
        collector = MetricsCollector()

        # Record multiple metrics
        for i in range(5):
            metrics = AuditMetrics(
                audit_id=f"audit_{i}",
                timestamp=datetime.utcnow() - timedelta(hours=i),
                hostname="test-server",
                platform="Linux",
                risk_score=50 + (i * 5),
                findings_total=10 + i,
                findings_critical=i,
            )
            collector.record(metrics)

        trends = collector.get_trends(limit=5)

        assert trends["count"] == 5
        assert "avg_risk_score" in trends
        assert "avg_findings" in trends
        assert "trend" in trends

    def test_trend_detection_improving(self, sample_metrics):
        """Test detection of improving trend"""
        collector = MetricsCollector()

        # Record decreasing risk scores (improving)
        for i in range(6):
            metrics = AuditMetrics(
                audit_id=f"audit_{i}",
                timestamp=datetime.utcnow() - timedelta(hours=i),
                hostname="test-server",
                platform="Linux",
                risk_score=80 - (i * 10),  # Decreasing
            )
            collector.record(metrics)

        trends = collector.get_trends(limit=6)
        assert trends["trend"] == "IMPROVING"

    def test_trend_detection_worsening(self, sample_metrics):
        """Test detection of worsening trend"""
        collector = MetricsCollector()

        # Record increasing risk scores (worsening)
        for i in range(6):
            metrics = AuditMetrics(
                audit_id=f"audit_{i}",
                timestamp=datetime.utcnow() - timedelta(hours=i),
                hostname="test-server",
                platform="Linux",
                risk_score=20 + (i * 10),  # Increasing
            )
            collector.record(metrics)

        trends = collector.get_trends(limit=6)
        assert trends["trend"] == "WORSENING"

    def test_trend_detection_stable(self, sample_metrics):
        """Test detection of stable trend"""
        collector = MetricsCollector()

        # Record stable risk scores
        for i in range(6):
            metrics = AuditMetrics(
                audit_id=f"audit_{i}",
                timestamp=datetime.utcnow() - timedelta(hours=i),
                hostname="test-server",
                platform="Linux",
                risk_score=50,  # Stable
            )
            collector.record(metrics)

        trends = collector.get_trends(limit=6)
        assert trends["trend"] == "STABLE"

    def test_filter_by_hostname(self, sample_metrics):
        """Test filtering trends by hostname"""
        collector = MetricsCollector()

        # Record metrics for different hosts
        for hostname in ["host1", "host2", "host1", "host2"]:
            metrics = AuditMetrics(
                audit_id=f"audit_{hostname}_{len(collector.metrics_history)}",
                timestamp=datetime.utcnow(),
                hostname=hostname,
                platform="Linux",
                risk_score=50,
            )
            collector.record(metrics)

        # Get trends for host1 only
        trends = collector.get_trends(hostname="host1")
        assert trends["count"] == 2

    def test_export_all_json(self, sample_metrics):
        """Test exporting all metrics as JSON"""
        collector = MetricsCollector()

        for i in range(3):
            metrics = AuditMetrics(
                audit_id=f"audit_{i}",
                timestamp=datetime.utcnow(),
                hostname="test-server",
                platform="Linux",
            )
            collector.record(metrics)

        json_export = collector.export_all(format="json")

        data = json.loads(json_export)
        assert len(data) == 3
        assert data[0]["audit_id"] == "audit_0"

    def test_export_all_prometheus(self, sample_metrics):
        """Test exporting all metrics in Prometheus format"""
        collector = MetricsCollector()

        for i in range(2):
            metrics = AuditMetrics(
                audit_id=f"audit_{i}",
                timestamp=datetime.utcnow(),
                hostname="test-server",
                platform="Linux",
            )
            collector.record(metrics)

        prom_export = collector.export_all(format="prometheus")

        # Should contain metrics from both audits
        assert 'audit_id="audit_0"' in prom_export
        assert 'audit_id="audit_1"' in prom_export

    def test_export_all_cloudwatch(self, sample_metrics):
        """Test exporting all metrics in CloudWatch format"""
        collector = MetricsCollector()

        for i in range(2):
            metrics = AuditMetrics(
                audit_id=f"audit_{i}",
                timestamp=datetime.utcnow(),
                hostname="test-server",
                platform="Linux",
            )
            collector.record(metrics)

        cw_export = collector.export_all(format="cloudwatch")

        data = json.loads(cw_export)
        assert isinstance(data, list)
        assert len(data) > 0

    def test_get_summary_stats(self, sample_metrics):
        """Test summary statistics calculation"""
        collector = MetricsCollector()

        # Record multiple audits
        for i in range(10):
            metrics = AuditMetrics(
                audit_id=f"audit_{i}",
                timestamp=datetime.utcnow(),
                hostname=f"host{i % 3}",  # 3 unique hosts
                platform="Linux",
                findings_total=5 + i,
                findings_critical=i % 3,
                risk_score=40 + i,
                duration_seconds=30.0 + i,
                ai_api_calls=2,
                ai_api_errors=i % 5,
            )
            collector.record(metrics)

        stats = collector.get_summary_stats()

        assert stats["total_audits"] == 10
        assert stats["unique_hosts"] == 3
        assert stats["total_findings"] == sum(5 + i for i in range(10))
        assert stats["avg_risk_score"] == pytest.approx(44.5, rel=0.1)
        assert stats["avg_duration_seconds"] == pytest.approx(34.5, rel=0.1)
        assert stats["total_ai_calls"] == 20

    def test_empty_collector_stats(self):
        """Test stats with no recorded metrics"""
        collector = MetricsCollector()

        stats = collector.get_summary_stats()
        assert stats["total_audits"] == 0

        trends = collector.get_trends()
        assert trends["count"] == 0
        assert trends["trend"] == "UNKNOWN"


class TestMetricsIntegration:
    """Integration tests for metrics workflow"""

    def test_complete_metrics_workflow(self, sample_metrics):
        """Test complete metrics collection and export workflow"""
        collector = MetricsCollector()

        # Record multiple audits
        for i in range(5):
            metrics = AuditMetrics(
                audit_id=f"audit_{i}",
                timestamp=datetime.utcnow() - timedelta(hours=i),
                hostname="test-server",
                platform="Linux",
                risk_score=60 - (i * 5),  # Improving trend
                findings_total=10,
                findings_critical=2 - (i % 2),
            )
            collector.record(metrics)

        # Get trends
        trends = collector.get_trends()
        assert trends["trend"] in ["IMPROVING", "STABLE"]

        # Export in multiple formats
        json_export = collector.export_all("json")
        assert len(json.loads(json_export)) == 5

        prom_export = collector.export_all("prometheus")
        assert "audit_risk_score" in prom_export

        # Get summary
        summary = collector.get_summary_stats()
        assert summary["total_audits"] == 5
