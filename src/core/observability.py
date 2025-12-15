"""
Service Level Objectives (SLO) and Observability Configuration
Defines production monitoring thresholds and alerting criteria

Author: Kevin Hormaza
GitHub: https://github.com/OddSageID
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum
import logging


class AlertSeverity(Enum):
    """Alert severity levels"""

    CRITICAL = "critical"  # Page on-call immediately
    HIGH = "high"  # Alert within 15 minutes
    MEDIUM = "medium"  # Alert within 1 hour
    LOW = "low"  # Log only, review daily


class MetricType(Enum):
    """Metric collection types"""

    COUNTER = "counter"  # Monotonically increasing
    GAUGE = "gauge"  # Point-in-time value
    HISTOGRAM = "histogram"  # Distribution of values
    SUMMARY = "summary"  # Aggregated statistics


@dataclass
class SLOThreshold:
    """Individual SLO threshold configuration"""

    metric_name: str
    metric_type: MetricType
    threshold_value: float
    comparison: str  # "lt", "gt", "eq", "lte", "gte"
    severity: AlertSeverity
    description: str
    remediation_hint: str

    def evaluate(self, current_value: float) -> bool:
        """
        Evaluate if current value violates SLO

        Args:
            current_value: Current metric value

        Returns:
            True if SLO violated, False otherwise
        """
        comparisons = {
            "lt": current_value < self.threshold_value,
            "gt": current_value > self.threshold_value,
            "eq": current_value == self.threshold_value,
            "lte": current_value <= self.threshold_value,
            "gte": current_value >= self.threshold_value,
        }
        return comparisons.get(self.comparison, False)


@dataclass
class SLOConfig:
    """
    Service Level Objectives for Production Monitoring

    Defines acceptable performance and reliability thresholds for:
    - Availability: System uptime and accessibility
    - Latency: Response time percentiles
    - Error Rate: Failed request percentage
    - Throughput: Requests per second capacity
    - Resource Usage: CPU, memory, disk utilization
    """

    # ============================================================================
    # AVAILABILITY OBJECTIVES
    # ============================================================================

    # Target: 99.5% uptime (43.8 hours downtime/year)
    availability_target_percent: float = 99.5
    max_consecutive_failures: int = 3
    healthcheck_interval_seconds: int = 30

    # ============================================================================
    # LATENCY OBJECTIVES (milliseconds)
    # ============================================================================

    # Audit Execution Latency
    audit_duration_p50_ms: float = 30_000  # 30 seconds (median)
    audit_duration_p95_ms: float = 120_000  # 2 minutes (95th percentile)
    audit_duration_p99_ms: float = 300_000  # 5 minutes (99th percentile)
    max_audit_duration_ms: float = 600_000  # 10 minutes (hard limit)

    # AI API Call Latency
    ai_api_latency_p50_ms: float = 1_000  # 1 second (median)
    ai_api_latency_p95_ms: float = 3_000  # 3 seconds (95th percentile)
    ai_api_latency_p99_ms: float = 5_000  # 5 seconds (99th percentile)
    max_ai_api_latency_ms: float = 10_000  # 10 seconds (hard limit)

    # Database Query Latency
    db_query_latency_p50_ms: float = 50  # 50ms (median)
    db_query_latency_p95_ms: float = 200  # 200ms (95th percentile)
    db_query_latency_p99_ms: float = 500  # 500ms (99th percentile)
    max_db_query_latency_ms: float = 2_000  # 2 seconds (hard limit)

    # ============================================================================
    # ERROR RATE OBJECTIVES (percentage)
    # ============================================================================

    # Overall System Error Rate
    max_error_rate_percent: float = 1.0  # 1% of requests can fail
    critical_error_rate_percent: float = 5.0  # 5% triggers critical alert

    # Component-Specific Error Rates
    max_collector_failure_rate_percent: float = 2.0
    max_ai_api_error_rate_percent: float = 3.0  # AI APIs less reliable
    max_database_error_rate_percent: float = 0.5  # DB should be very stable

    # ============================================================================
    # THROUGHPUT OBJECTIVES
    # ============================================================================

    # Concurrent Audits
    max_concurrent_audits: int = 10
    recommended_concurrent_audits: int = 5

    # API Rate Limits (aligned with rate_limiter.py)
    ai_requests_per_minute: int = 60
    ai_requests_per_hour: int = 1_000
    ai_max_concurrent: int = 5

    # ============================================================================
    # RESOURCE UTILIZATION OBJECTIVES (percentage)
    # ============================================================================

    # CPU Utilization
    cpu_warning_threshold_percent: float = 70.0
    cpu_critical_threshold_percent: float = 90.0

    # Memory Utilization
    memory_warning_threshold_percent: float = 75.0
    memory_critical_threshold_percent: float = 90.0

    # Disk Utilization
    disk_warning_threshold_percent: float = 80.0
    disk_critical_threshold_percent: float = 95.0

    # Database Connection Pool
    db_connection_pool_warning_percent: float = 70.0
    db_connection_pool_critical_percent: float = 90.0

    # ============================================================================
    # DATA QUALITY OBJECTIVES
    # ============================================================================

    # Finding Consistency
    min_finding_completeness_percent: float = 95.0  # Required fields populated
    max_duplicate_findings_percent: float = 5.0

    # Audit Report Quality
    min_report_generation_success_rate: float = 99.0
    max_report_size_mb: float = 50.0

    # ============================================================================
    # SECURITY OBJECTIVES
    # ============================================================================

    # Input Validation
    max_validation_failure_rate_percent: float = 0.1  # Should be very rare

    # Authentication/Authorization
    max_auth_failure_rate_percent: float = 1.0
    max_failed_login_attempts_per_hour: int = 10

    # Rate Limiting
    max_rate_limit_violations_per_hour: int = 50

    # ============================================================================
    # BUSINESS LOGIC OBJECTIVES
    # ============================================================================

    # CIS Benchmark Coverage
    min_cis_check_coverage_percent: float = 95.0
    max_false_positive_rate_percent: float = 5.0

    # Remediation Script Safety
    max_remediation_failure_rate_percent: float = 2.0
    max_rollback_failure_rate_percent: float = 1.0

    def get_thresholds(self) -> List[SLOThreshold]:
        """
        Generate list of all SLO thresholds for monitoring

        Returns:
            List of SLOThreshold objects for alert evaluation
        """
        return [
            # Availability
            SLOThreshold(
                metric_name="system_uptime_percent",
                metric_type=MetricType.GAUGE,
                threshold_value=self.availability_target_percent,
                comparison="lt",
                severity=AlertSeverity.CRITICAL,
                description=f"System availability below {self.availability_target_percent}%",
                remediation_hint="Check service health, review error logs, restart failed components",
            ),
            # Latency - Audit Duration
            SLOThreshold(
                metric_name="audit_duration_p99_ms",
                metric_type=MetricType.HISTOGRAM,
                threshold_value=self.audit_duration_p99_ms,
                comparison="gt",
                severity=AlertSeverity.HIGH,
                description=f"99th percentile audit duration exceeds {self.audit_duration_p99_ms}ms",
                remediation_hint="Optimize collector performance, check AI API latency, review database queries",
            ),
            SLOThreshold(
                metric_name="audit_duration_max_ms",
                metric_type=MetricType.GAUGE,
                threshold_value=self.max_audit_duration_ms,
                comparison="gt",
                severity=AlertSeverity.CRITICAL,
                description=f"Audit duration exceeded hard limit of {self.max_audit_duration_ms}ms",
                remediation_hint="Investigation required: possible infinite loop, API timeout, or resource exhaustion",
            ),
            # Latency - AI API
            SLOThreshold(
                metric_name="ai_api_latency_p99_ms",
                metric_type=MetricType.HISTOGRAM,
                threshold_value=self.ai_api_latency_p99_ms,
                comparison="gt",
                severity=AlertSeverity.MEDIUM,
                description=f"99th percentile AI API latency exceeds {self.ai_api_latency_p99_ms}ms",
                remediation_hint="Check AI provider status, review rate limiting, consider caching strategies",
            ),
            # Error Rates
            SLOThreshold(
                metric_name="system_error_rate_percent",
                metric_type=MetricType.GAUGE,
                threshold_value=self.max_error_rate_percent,
                comparison="gt",
                severity=AlertSeverity.HIGH,
                description=f"System error rate exceeds {self.max_error_rate_percent}%",
                remediation_hint="Review error logs, check external dependencies, verify input validation",
            ),
            SLOThreshold(
                metric_name="system_error_rate_percent",
                metric_type=MetricType.GAUGE,
                threshold_value=self.critical_error_rate_percent,
                comparison="gt",
                severity=AlertSeverity.CRITICAL,
                description=f"CRITICAL: System error rate exceeds {self.critical_error_rate_percent}%",
                remediation_hint="Immediate investigation required: possible service degradation or outage",
            ),
            # Resource Utilization
            SLOThreshold(
                metric_name="cpu_utilization_percent",
                metric_type=MetricType.GAUGE,
                threshold_value=self.cpu_warning_threshold_percent,
                comparison="gt",
                severity=AlertSeverity.MEDIUM,
                description=f"CPU utilization above {self.cpu_warning_threshold_percent}%",
                remediation_hint="Review concurrent audit count, optimize collector code, scale horizontally",
            ),
            SLOThreshold(
                metric_name="cpu_utilization_percent",
                metric_type=MetricType.GAUGE,
                threshold_value=self.cpu_critical_threshold_percent,
                comparison="gt",
                severity=AlertSeverity.CRITICAL,
                description=f"CRITICAL: CPU utilization above {self.cpu_critical_threshold_percent}%",
                remediation_hint="Reduce load immediately, scale resources, investigate CPU-intensive operations",
            ),
            SLOThreshold(
                metric_name="memory_utilization_percent",
                metric_type=MetricType.GAUGE,
                threshold_value=self.memory_critical_threshold_percent,
                comparison="gt",
                severity=AlertSeverity.CRITICAL,
                description=f"CRITICAL: Memory utilization above {self.memory_critical_threshold_percent}%",
                remediation_hint="Check for memory leaks, review object caching, restart service if necessary",
            ),
            # Database Performance
            SLOThreshold(
                metric_name="db_query_latency_p99_ms",
                metric_type=MetricType.HISTOGRAM,
                threshold_value=self.db_query_latency_p99_ms,
                comparison="gt",
                severity=AlertSeverity.HIGH,
                description=f"Database query latency (p99) exceeds {self.db_query_latency_p99_ms}ms",
                remediation_hint="Review slow queries, check indexes, optimize query patterns, consider caching",
            ),
            # Circuit Breaker
            SLOThreshold(
                metric_name="circuit_breaker_open_count",
                metric_type=MetricType.COUNTER,
                threshold_value=5.0,
                comparison="gt",
                severity=AlertSeverity.HIGH,
                description="Circuit breaker opened more than 5 times in monitoring period",
                remediation_hint="Check AI API health, review rate limiting config, verify network connectivity",
            ),
        ]


@dataclass
class MonitoringConfig:
    """
    Monitoring and Alerting Configuration
    Defines how metrics are collected, stored, and alerted on
    """

    # Metric Collection
    metrics_enabled: bool = True
    collection_interval_seconds: int = 60
    retention_days: int = 90

    # Export Formats
    prometheus_enabled: bool = True
    prometheus_port: int = 9090

    cloudwatch_enabled: bool = False
    cloudwatch_namespace: str = "APlus/AuditUtility"
    cloudwatch_region: str = "us-east-1"

    # Alerting
    alerting_enabled: bool = True
    alert_webhook_url: Optional[str] = None
    alert_email: Optional[str] = None

    # Slack Integration
    slack_webhook_url: Optional[str] = None
    slack_channel: str = "#alerts"

    # PagerDuty Integration
    pagerduty_integration_key: Optional[str] = None

    # Logging
    structured_logging: bool = True
    log_level: str = "INFO"
    log_format: str = "json"  # "json" or "text"

    # SLO Configuration
    slo_config: SLOConfig = field(default_factory=SLOConfig)

    def get_alert_config(self) -> Dict:
        """Get alerting configuration for external systems"""
        return {
            "enabled": self.alerting_enabled,
            "webhooks": {
                "generic": self.alert_webhook_url,
                "slack": self.slack_webhook_url,
                "pagerduty": self.pagerduty_integration_key,
            },
            "email": self.alert_email,
            "severity_mapping": {
                AlertSeverity.CRITICAL.value: "page_immediately",
                AlertSeverity.HIGH.value: "alert_15min",
                AlertSeverity.MEDIUM.value: "alert_1hour",
                AlertSeverity.LOW.value: "log_only",
            },
        }


class SLOMonitor:
    """
    Active SLO monitoring and violation detection
    Evaluates metrics against thresholds and triggers alerts
    """

    def __init__(self, config: MonitoringConfig):
        self.config = config
        self.slo_config = config.slo_config
        self.logger = logging.getLogger(__name__)
        self.violation_history: List[Dict] = []

    def evaluate_slo(self, metric_name: str, current_value: float) -> Optional[SLOThreshold]:
        """
        Evaluate if metric violates any SLO threshold

        Args:
            metric_name: Name of the metric to evaluate
            current_value: Current metric value

        Returns:
            SLOThreshold if violated, None otherwise
        """
        for threshold in self.slo_config.get_thresholds():
            if threshold.metric_name == metric_name:
                if threshold.evaluate(current_value):
                    self._record_violation(threshold, current_value)
                    return threshold
        return None

    def _record_violation(self, threshold: SLOThreshold, current_value: float):
        """Record SLO violation for tracking"""
        violation = {
            "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
            "metric": threshold.metric_name,
            "threshold": threshold.threshold_value,
            "actual": current_value,
            "severity": threshold.severity.value,
            "description": threshold.description,
        }
        self.violation_history.append(violation)

        # Log violation
        if threshold.severity == AlertSeverity.CRITICAL:
            self.logger.critical(f"SLO VIOLATION: {threshold.description}")
        elif threshold.severity == AlertSeverity.HIGH:
            self.logger.error(f"SLO VIOLATION: {threshold.description}")
        else:
            self.logger.warning(f"SLO VIOLATION: {threshold.description}")

    def get_violation_summary(self) -> Dict:
        """Get summary of recent SLO violations"""
        return {
            "total_violations": len(self.violation_history),
            "critical_count": sum(1 for v in self.violation_history if v["severity"] == "critical"),
            "high_count": sum(1 for v in self.violation_history if v["severity"] == "high"),
            "recent_violations": self.violation_history[-10:],  # Last 10
        }


# ============================================================================
# EXAMPLE USAGE
# ============================================================================


def example_monitoring_setup():
    """
    Example: How to set up production monitoring with SLOs
    """
    # Configure monitoring
    monitoring_config = MonitoringConfig(
        metrics_enabled=True,
        prometheus_enabled=True,
        alerting_enabled=True,
        slack_webhook_url="https://hooks.slack.com/services/YOUR/WEBHOOK",
        alert_email="ops-team@example.com",
    )

    # Create SLO monitor
    monitor = SLOMonitor(monitoring_config)

    # Example: Evaluate audit duration
    audit_duration_ms = 350_000  # 5.8 minutes
    violation = monitor.evaluate_slo("audit_duration_p99_ms", audit_duration_ms)

    if violation:
        print(f"⚠️  SLO VIOLATION: {violation.description}")
        print(f"   Remediation: {violation.remediation_hint}")

    # Get violation summary
    summary = monitor.get_violation_summary()
    print(f"Total violations: {summary['total_violations']}")
    print(f"Critical: {summary['critical_count']}, High: {summary['high_count']}")


if __name__ == "__main__":
    example_monitoring_setup()
