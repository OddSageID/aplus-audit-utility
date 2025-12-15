"""
Metrics collection and export for monitoring and alerting.
Supports Prometheus, CloudWatch, and JSON export formats.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum
import json
import logging


class MetricType(Enum):
    """Types of metrics"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass
class AuditMetrics:
    """
    Comprehensive metrics for a single audit run.
    Designed for export to monitoring systems.
    """
    
    # Audit identification
    audit_id: str
    timestamp: datetime
    hostname: str
    platform: str
    
    # Execution metrics
    duration_seconds: float = 0.0
    collectors_total: int = 0
    collectors_executed: int = 0
    collectors_failed: int = 0
    collectors_skipped: int = 0
    
    # Finding metrics
    findings_total: int = 0
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_low: int = 0
    findings_info: int = 0
    
    # Risk assessment
    risk_score: int = 0
    risk_level: str = "UNKNOWN"
    
    # AI metrics
    ai_provider: Optional[str] = None
    ai_model: Optional[str] = None
    ai_api_calls: int = 0
    ai_api_latency_ms: float = 0.0
    ai_api_errors: int = 0
    ai_tokens_used: int = 0
    
    # Remediation metrics
    remediation_scripts_generated: int = 0
    
    # Rate limiter metrics
    rate_limit_hits: int = 0
    circuit_breaker_opens: int = 0
    
    # Resource metrics
    memory_used_mb: float = 0.0
    cpu_percent: float = 0.0
    
    # Error tracking
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        # Convert datetime to ISO format
        data['timestamp'] = self.timestamp.isoformat()
        return data
    
    def to_prometheus(self) -> str:
        """
        Export metrics in Prometheus text format.
        
        Returns:
            Multi-line string in Prometheus exposition format
        """
        lines = []
        
        # Helper to add metric
        def add_metric(name: str, value: Any, metric_type: str = "gauge", help_text: str = ""):
            if help_text:
                lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} {metric_type}")
            
            labels = f'{{audit_id="{self.audit_id}",hostname="{self.hostname}",platform="{self.platform}"}}'
            lines.append(f"{name}{labels} {value}")
        
        # Execution metrics
        add_metric(
            "audit_duration_seconds",
            self.duration_seconds,
            "gauge",
            "Total audit execution time in seconds"
        )
        
        add_metric(
            "audit_collectors_total",
            self.collectors_total,
            "gauge",
            "Total number of collectors registered"
        )
        
        add_metric(
            "audit_collectors_failed",
            self.collectors_failed,
            "counter",
            "Number of collectors that failed"
        )
        
        # Finding metrics
        add_metric(
            "audit_findings_total",
            self.findings_total,
            "gauge",
            "Total number of findings detected"
        )
        
        add_metric(
            "audit_findings_critical",
            self.findings_critical,
            "gauge",
            "Number of critical severity findings"
        )
        
        add_metric(
            "audit_findings_high",
            self.findings_high,
            "gauge",
            "Number of high severity findings"
        )
        
        add_metric(
            "audit_risk_score",
            self.risk_score,
            "gauge",
            "Overall risk score (0-100)"
        )
        
        # AI metrics
        if self.ai_provider:
            add_metric(
                "audit_ai_api_calls",
                self.ai_api_calls,
                "counter",
                "Number of AI API calls made"
            )
            
            add_metric(
                "audit_ai_api_latency_ms",
                self.ai_api_latency_ms,
                "gauge",
                "Average AI API latency in milliseconds"
            )
            
            add_metric(
                "audit_ai_api_errors",
                self.ai_api_errors,
                "counter",
                "Number of AI API errors"
            )
        
        # Rate limiting metrics
        add_metric(
            "audit_rate_limit_hits",
            self.rate_limit_hits,
            "counter",
            "Number of rate limit hits"
        )
        
        add_metric(
            "audit_circuit_breaker_opens",
            self.circuit_breaker_opens,
            "counter",
            "Number of circuit breaker activations"
        )
        
        return "\n".join(lines)
    
    def to_cloudwatch(self) -> List[Dict[str, Any]]:
        """
        Export metrics in AWS CloudWatch format.
        
        Returns:
            List of metric data dictionaries for CloudWatch PutMetricData API
        """
        namespace = "AuditUtility"
        dimensions = [
            {'Name': 'Hostname', 'Value': self.hostname},
            {'Name': 'Platform', 'Value': self.platform}
        ]
        
        metrics = []
        
        def add_metric(name: str, value: float, unit: str = "None"):
            metrics.append({
                'MetricName': name,
                'Dimensions': dimensions,
                'Timestamp': self.timestamp,
                'Value': value,
                'Unit': unit
            })
        
        # Execution metrics
        add_metric('AuditDuration', self.duration_seconds, 'Seconds')
        add_metric('CollectorsExecuted', self.collectors_executed, 'Count')
        add_metric('CollectorsFailed', self.collectors_failed, 'Count')
        
        # Finding metrics
        add_metric('FindingsTotal', self.findings_total, 'Count')
        add_metric('FindingsCritical', self.findings_critical, 'Count')
        add_metric('FindingsHigh', self.findings_high, 'Count')
        add_metric('RiskScore', self.risk_score, 'None')
        
        # AI metrics
        if self.ai_provider:
            add_metric('AIApiCalls', self.ai_api_calls, 'Count')
            add_metric('AIApiLatency', self.ai_api_latency_ms, 'Milliseconds')
            add_metric('AIApiErrors', self.ai_api_errors, 'Count')
        
        # Rate limiting metrics
        add_metric('RateLimitHits', self.rate_limit_hits, 'Count')
        add_metric('CircuitBreakerOpens', self.circuit_breaker_opens, 'Count')
        
        return metrics
    
    def to_json(self, pretty: bool = True) -> str:
        """
        Export metrics as JSON.
        
        Args:
            pretty: Whether to pretty-print JSON
            
        Returns:
            JSON string
        """
        data = self.to_dict()
        if pretty:
            return json.dumps(data, indent=2, default=str)
        return json.dumps(data, default=str)
    
    def get_alerts(self) -> List[Dict[str, str]]:
        """
        Generate alerts based on metric thresholds.
        
        Returns:
            List of alert dictionaries with severity and message
        """
        alerts = []
        
        # Critical findings alert
        if self.findings_critical > 0:
            alerts.append({
                'severity': 'CRITICAL',
                'message': f"Found {self.findings_critical} critical security findings on {self.hostname}",
                'metric': 'findings_critical',
                'value': str(self.findings_critical)
            })
        
        # High risk score alert
        if self.risk_score >= 75:
            alerts.append({
                'severity': 'HIGH',
                'message': f"Risk score {self.risk_score}/100 on {self.hostname}",
                'metric': 'risk_score',
                'value': str(self.risk_score)
            })
        
        # Collector failure alert
        if self.collectors_failed > 0:
            failure_rate = self.collectors_failed / self.collectors_total if self.collectors_total > 0 else 0
            if failure_rate > 0.1:  # >10% failure rate
                alerts.append({
                    'severity': 'WARNING',
                    'message': f"Collector failure rate {failure_rate:.1%} on {self.hostname}",
                    'metric': 'collectors_failed',
                    'value': str(self.collectors_failed)
                })
        
        # AI API error alert
        if self.ai_api_errors > 0 and self.ai_api_calls > 0:
            error_rate = self.ai_api_errors / self.ai_api_calls
            if error_rate > 0.05:  # >5% error rate
                alerts.append({
                    'severity': 'WARNING',
                    'message': f"AI API error rate {error_rate:.1%} on {self.hostname}",
                    'metric': 'ai_api_errors',
                    'value': str(self.ai_api_errors)
                })
        
        # Circuit breaker alert
        if self.circuit_breaker_opens > 0:
            alerts.append({
                'severity': 'WARNING',
                'message': f"Circuit breaker opened {self.circuit_breaker_opens} times on {self.hostname}",
                'metric': 'circuit_breaker_opens',
                'value': str(self.circuit_breaker_opens)
            })
        
        return alerts


class MetricsCollector:
    """
    Collects and aggregates metrics across multiple audit runs.
    Provides time-series analytics and trend detection.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.metrics_history: List[AuditMetrics] = []
        self.metric_store: Dict[str, Dict[str, Any]] = {}
        self._lock = None
    
    def record(self, name_or_metrics, value: Any = None, metric_type: Any = None, tags: Optional[Dict[str, Any]] = None):
        """
        Record metrics for an audit run or custom metric value (test compatibility).
        """
        if isinstance(name_or_metrics, AuditMetrics):
            metrics = name_or_metrics
            self.metrics_history.append(metrics)
            self.logger.info(f"Recorded metrics for audit {metrics.audit_id}")
            return

        # Custom metric path
        name = name_or_metrics
        metric_type = metric_type or MetricType.GAUGE
        if not isinstance(metric_type, MetricType):
            raise TypeError("metric_type must be MetricType")

        if self._lock is None:
            import threading
            self._lock = threading.Lock()

        with self._lock:
            entry = self.metric_store.get(name, {"type": metric_type})
            if metric_type == MetricType.COUNTER:
                current = entry.get("value", 0)
                self.metric_store[name] = {
                    "type": metric_type,
                    "value": current + (value or 0)
                }
            elif metric_type == MetricType.GAUGE:
                self.metric_store[name] = {
                    "type": metric_type,
                    "value": value
                }
            elif metric_type == MetricType.HISTOGRAM:
                values = list(entry.get("values", []))
                if value is not None:
                    values.append(value)
                self.metric_store[name] = {
                    "type": metric_type,
                    "values": values,
                    "count": len(values),
                    "min": min(values) if values else None,
                    "max": max(values) if values else None,
                    "avg": (sum(values) / len(values)) if values else None
                }
            else:
                self.metric_store[name] = {
                    "type": metric_type,
                    "value": value
                }
    
    def get_trends(self, hostname: Optional[str] = None, limit: int = 10) -> Dict[str, Any]:
        """
        Get trend analysis for recent audits.
        
        Args:
            hostname: Filter by hostname (optional)
            limit: Number of recent audits to analyze
            
        Returns:
            Dictionary with trend data
        """
        # Filter metrics
        metrics = self.metrics_history
        if hostname:
            metrics = [m for m in metrics if m.hostname == hostname]
        
        # Preserve insertion order but respect limit (use most recent entries)
        metrics = metrics[-limit:]
        
        if not metrics:
            return {
                'count': 0,
                'avg_risk_score': 0,
                'avg_findings': 0,
                'trend': 'UNKNOWN'
            }
        
        # Calculate averages
        avg_risk = sum(m.risk_score for m in metrics) / len(metrics)
        avg_findings = sum(m.findings_total for m in metrics) / len(metrics)
        
        # Detect trend using first vs last measurements (lower risk is better)
        if len(metrics) >= 2:
            risk_change = metrics[-1].risk_score - metrics[0].risk_score
            if risk_change <= -5:
                trend = 'IMPROVING'
            elif risk_change >= 5:
                trend = 'WORSENING'
            else:
                trend = 'STABLE'
        else:
            trend = 'INSUFFICIENT_DATA'
        
        return {
            'count': len(metrics),
            'avg_risk_score': round(avg_risk, 2),
            'avg_findings': round(avg_findings, 2),
            'avg_critical_findings': round(sum(m.findings_critical for m in metrics) / len(metrics), 2),
            'trend': trend,
            'time_range': {
                'start': metrics[-1].timestamp.isoformat(),
                'end': metrics[0].timestamp.isoformat()
            }
        }
    
    def export_all(self, format: str = "json") -> str:
        """
        Export all collected metrics.
        
        Args:
            format: Export format ('json', 'prometheus', 'cloudwatch')
            
        Returns:
            Exported metrics string
        """
        if format == "json":
            return json.dumps(
                [m.to_dict() for m in self.metrics_history],
                indent=2,
                default=str
            )
        elif format == "prometheus":
            return "\n\n".join(m.to_prometheus() for m in self.metrics_history)
        elif format == "cloudwatch":
            all_metrics = []
            for m in self.metrics_history:
                all_metrics.extend(m.to_cloudwatch())
            return json.dumps(all_metrics, indent=2, default=str)
        else:
            raise ValueError(f"Unknown export format: {format}")

    def get_stats(self) -> Dict[str, Any]:
        """Return collected custom metrics (counters, gauges, histograms)."""
        return dict(self.metric_store)
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics across all recorded audits"""
        if not self.metrics_history:
            return {'total_audits': 0}
        
        return {
            'total_audits': len(self.metrics_history),
            'unique_hosts': len(set(m.hostname for m in self.metrics_history)),
            'total_findings': sum(m.findings_total for m in self.metrics_history),
            'total_critical': sum(m.findings_critical for m in self.metrics_history),
            'avg_risk_score': round(
                sum(m.risk_score for m in self.metrics_history) / len(self.metrics_history),
                2
            ),
            'avg_duration_seconds': round(
                sum(m.duration_seconds for m in self.metrics_history) / len(self.metrics_history),
                2
            ),
            'total_ai_calls': sum(m.ai_api_calls for m in self.metrics_history),
            'total_ai_errors': sum(m.ai_api_errors for m in self.metrics_history),
        }

    def export_prometheus(self) -> str:
        """Export custom metrics in Prometheus text format."""
        lines: List[str] = []
        for name, data in self.metric_store.items():
            mtype = data.get("type", MetricType.GAUGE)
            prom_type = "gauge" if mtype == MetricType.GAUGE else "counter"
            value = data.get("value")
            if mtype == MetricType.HISTOGRAM:
                value = data.get("avg") if data.get("avg") is not None else 0
            if value is None:
                value = 0
            lines.append(f"# TYPE {name} {prom_type}")
            lines.append(f"{name} {value}")
        return "\n".join(lines)

    def export_cloudwatch(self) -> List[Dict[str, Any]]:
        """Export custom metrics as CloudWatch-compatible datapoints."""
        now = datetime.utcnow()
        cw_metrics: List[Dict[str, Any]] = []
        for name, data in self.metric_store.items():
            mtype = data.get("type", MetricType.GAUGE)
            value = data.get("value")
            unit = "Count" if mtype in (MetricType.COUNTER, MetricType.HISTOGRAM) else "None"
            if mtype == MetricType.HISTOGRAM:
                value = data.get("avg") if data.get("avg") is not None else 0
            if value is None:
                value = 0
            cw_metrics.append({
                "MetricName": name,
                "Dimensions": [],
                "Timestamp": now,
                "Value": value,
                "Unit": unit
            })
        return cw_metrics

    def reset(self):
        """Reset collected metrics and history."""
        self.metric_store.clear()
        self.metrics_history.clear()
