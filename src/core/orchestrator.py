from datetime import datetime
from typing import Any, Dict, List, Optional

import asyncio
import platform
import time
import psutil
import uuid

from .config import AuditConfig
from .logger import AuditLogger
from .metrics import AuditMetrics, MetricsCollector
from ..collectors.base_collector import BaseCollector, CollectorStatus
from ..analyzers.ai_analyzer import AIAnalyzer
from ..database.repository import AuditRepository


class AuditOrchestrator:
    """
    Coordinates complete system audit workflow with database persistence and metrics.
    Implements Facade pattern for simplified audit execution.
    """
    
    def __init__(self, config: AuditConfig):
        self.config = config
        self.logger = AuditLogger.get_logger(
            level=config.log_level,
            log_file=config.log_file
        )
        self.collectors: List[BaseCollector] = []
        self.ai_analyzer = AIAnalyzer(config.ai)
        
        # Initialize database repository
        self.repository: Optional[AuditRepository] = None
        if config.database_enabled:
            try:
                self.repository = AuditRepository(database_url=config.database_url)
                self.logger.info(f"Database initialized: {config.database_url}")
            except Exception as e:
                self.logger.error(f"Failed to initialize database: {e}")
                self.repository = None
        
        # Initialize metrics collector
        self.metrics_collector: Optional[MetricsCollector] = None
        if config.metrics_enabled:
            self.metrics_collector = MetricsCollector()
        
        # Audit results structure
        self.audit_results: Dict[str, Any] = self._init_audit_results()
        
        # Execution tracking
        self.start_time: Optional[float] = None
        self.execution_metrics: Optional[AuditMetrics] = None
    
    def register_collector(self, collector: BaseCollector):
        """Register a data collector"""
        self.collectors.append(collector)
        self.logger.info(f"Registered: {collector.__class__.__name__}")
    
    def run_audit(self) -> Dict[str, Any]:
        """Synchronous wrapper for async audit execution (test-friendly)."""
        return self._run_coro(self.run_audit_async())

    @staticmethod
    def _run_coro(coro):
        """Run coroutine safely regardless of existing event loop."""
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        if running_loop and running_loop.is_running():
            new_loop = asyncio.new_event_loop()
            try:
                return new_loop.run_until_complete(coro)
            finally:
                new_loop.close()
        return asyncio.run(coro)

    def _generate_audit_id(self) -> str:
        """Generate a unique audit identifier."""
        timestamp_part = datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')
        suffix = uuid.uuid4().hex[:6]
        return f"{timestamp_part}_{suffix}"

    def _init_audit_results(self) -> Dict[str, Any]:
        """Create a fresh audit results container with a unique ID."""
        return {
            'audit_id': self._generate_audit_id(),
            'timestamp': datetime.utcnow().isoformat(),
            'platform': platform.system(),
            'hostname': platform.node(),
            'platform_version': platform.version(),
            'collector_results': {},
            'all_findings': [],
            'ai_analysis': {},
            'remediation_scripts': {},
            'ai_config': {
                'provider': self.config.ai.provider,
                'model': self.config.ai.model
            }
        }

    async def run_audit_async(self) -> Dict[str, Any]:
        """
        Execute complete audit workflow:
        1. Run all collectors (parallel if configured)
        2. Aggregate findings
        3. AI-powered analysis
        4. Generate remediation scripts
        5. Save to database
        6. Collect metrics
        7. Return comprehensive results
        """
        # Reset state for each run
        self.audit_results = self._init_audit_results()
        self.execution_metrics = None
        self.start_time = time.time()
        
        self.logger.info(f"Starting audit {self.audit_results['audit_id']}")
        self.logger.info(f"Platform: {self.audit_results['platform']}")
        self.logger.info(f"Registered collectors: {len(self.collectors)}")
        
        # Initialize metrics
        if self.config.metrics_enabled:
            self.execution_metrics = self._init_metrics()
        
        try:
            # Phase 1: Data Collection
            await self._run_collectors()
            
            # Phase 2: Aggregate findings
            self._aggregate_findings()
            
            # Phase 3: AI Analysis
            if self.audit_results['all_findings']:
                if self.ai_analyzer.client:
                    self.logger.info(f"Running AI analysis on {len(self.audit_results['all_findings'])} findings")
                else:
                    self.logger.info("AI analysis disabled; using fallback analysis")

                self.audit_results['ai_analysis'] = await self.ai_analyzer.analyze_findings(
                    audit_data=self.audit_results,
                    findings=self.audit_results['all_findings']
                )
            else:
                self.logger.info("No findings detected - system healthy")
                self.audit_results['ai_analysis'] = {
                    'risk_score': 0,
                    'executive_summary': 'No security or configuration issues detected.',
                    'critical_issues': [],
                    'recommendations': ['Continue regular monitoring and updates']
                }
            
            # Phase 4: Generate Remediation Scripts
            if self.config.generate_remediation and self.audit_results['all_findings']:
                await self._generate_remediation_scripts()
            
            # Phase 5: Finalize metrics
            if self.execution_metrics:
                self._finalize_metrics()
            
            # Phase 6: Save to database
            if self.repository:
                try:
                    execution_time = time.time() - self.start_time
                    self.repository.save_audit_run(
                        self.audit_results,
                        executed_by=platform.node(),  # Could be enhanced with actual user
                        execution_time_seconds=execution_time
                    )
                    self.logger.info("Audit results saved to database")
                except Exception as e:
                    self.logger.error(f"Failed to save audit to database: {e}")
            
            # Phase 7: Record metrics
            if self.metrics_collector and self.execution_metrics:
                self.metrics_collector.record(self.execution_metrics)
                self.logger.info("Metrics recorded")
            
            risk_score = self.audit_results['ai_analysis'].get('risk_score', 0)
            self.logger.info(f"Audit complete - Risk Score: {risk_score}/100")
            
            return self.audit_results
            
        except Exception as e:
            self.logger.error(f"Audit execution failed: {e}", exc_info=True)
            raise
    
    def _init_metrics(self) -> AuditMetrics:
        """Initialize metrics object"""
        return AuditMetrics(
            audit_id=self.audit_results['audit_id'],
            timestamp=datetime.fromisoformat(self.audit_results['timestamp']),
            hostname=self.audit_results['hostname'],
            platform=self.audit_results['platform'],
            collectors_total=len(self.collectors),
            ai_provider=self.config.ai.provider,
            ai_model=self.config.ai.model
        )
    
    def _finalize_metrics(self):
        """Finalize metrics after audit completion"""
        if not self.execution_metrics:
            return
        
        # Update execution metrics
        self.execution_metrics.duration_seconds = time.time() - self.start_time
        
        # Update finding counts
        for finding in self.audit_results['all_findings']:
            severity = finding['severity']
            if severity == 'CRITICAL':
                self.execution_metrics.findings_critical += 1
            elif severity == 'HIGH':
                self.execution_metrics.findings_high += 1
            elif severity == 'MEDIUM':
                self.execution_metrics.findings_medium += 1
            elif severity == 'LOW':
                self.execution_metrics.findings_low += 1
            elif severity == 'INFO':
                self.execution_metrics.findings_info += 1
        
        self.execution_metrics.findings_total = len(self.audit_results['all_findings'])
        
        # Update risk assessment
        self.execution_metrics.risk_score = self.audit_results['ai_analysis'].get('risk_score', 0)
        risk_score = self.execution_metrics.risk_score
        if risk_score >= 75:
            self.execution_metrics.risk_level = 'CRITICAL'
        elif risk_score >= 50:
            self.execution_metrics.risk_level = 'HIGH'
        elif risk_score >= 25:
            self.execution_metrics.risk_level = 'MEDIUM'
        else:
            self.execution_metrics.risk_level = 'LOW'
        
        # Update AI metrics
        ai_metrics = self.ai_analyzer.get_metrics()
        self.execution_metrics.ai_api_calls = ai_metrics['total_api_calls']
        self.execution_metrics.ai_api_errors = ai_metrics['total_api_errors']
        self.execution_metrics.ai_api_latency_ms = ai_metrics['avg_latency_ms']
        
        # Update rate limiter metrics
        rate_limiter_stats = ai_metrics.get('rate_limiter_stats', {})
        self.execution_metrics.rate_limit_hits = rate_limiter_stats.get('total_rate_limited', 0)
        self.execution_metrics.circuit_breaker_opens = rate_limiter_stats.get('total_circuit_opens', 0)
        
        # Update remediation count
        self.execution_metrics.remediation_scripts_generated = len(
            self.audit_results.get('remediation_scripts', {})
        )
        
        # Get system resource usage
        try:
            process = psutil.Process()
            self.execution_metrics.memory_used_mb = process.memory_info().rss / (1024 * 1024)
            self.execution_metrics.cpu_percent = process.cpu_percent(interval=0.1)
        except:
            pass
    
    async def _run_collectors(self):
        """Execute all registered collectors"""
        if self.config.parallel_execution:
            # Run collectors in parallel
            tasks = [collector.safe_collect() for collector in self.collectors]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            # Run collectors sequentially
            results = []
            for collector in self.collectors:
                result = await collector.safe_collect()
                results.append(result)
        
        # Store results and update metrics
        for collector, result in zip(self.collectors, results):
            if isinstance(result, Exception):
                self.logger.error(f"{collector.__class__.__name__} raised exception: {result}")
                if self.execution_metrics:
                    self.execution_metrics.collectors_failed += 1
                    self.execution_metrics.errors.append(str(result))
                continue
            
            collector_name = getattr(collector, "name", collector.__class__.__name__)
            self.audit_results['collector_results'][collector_name] = {
                'status': result.status.value,
                'data': result.data,
                'findings': result.findings,
                'errors': result.errors,
                'warnings': result.warnings,
                'execution_time_ms': result.execution_time_ms
            }

            # Log permission or error context once
            if result.status == CollectorStatus.SKIPPED and result.warnings:
                self.logger.warning(f"{collector_name} skipped: {result.warnings[0]}")
            elif result.errors:
                self.logger.error(f"{collector_name} errors: {'; '.join(result.errors)}")
            
            # Update metrics
            if self.execution_metrics:
                self.execution_metrics.collectors_executed += 1
                if result.status == CollectorStatus.FAILED:
                    self.execution_metrics.collectors_failed += 1
                elif result.status == CollectorStatus.SKIPPED:
                    self.execution_metrics.collectors_skipped += 1
                
                # Track errors and warnings
                self.execution_metrics.errors.extend(result.errors)
                self.execution_metrics.warnings.extend(result.warnings)
            
            exec_time = (
                f"{result.execution_time_ms:.2f}ms"
                if result.execution_time_ms is not None
                else "N/A"
            )
            self.logger.info(
                f"{collector_name}: {result.status.value} "
                f"({len(result.findings)} findings, {exec_time})"
            )
    
    def _aggregate_findings(self):
        """Aggregate all findings from collectors"""
        for collector_name, result in self.audit_results['collector_results'].items():
            for finding in result['findings']:
                # Add collector name to finding
                finding['collector_name'] = collector_name
                self.audit_results['all_findings'].append(finding)
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        self.audit_results['all_findings'].sort(
            key=lambda x: severity_order.get(x['severity'], 999)
        )
    
    async def _generate_remediation_scripts(self):
        """Generate remediation scripts for findings"""
        self.logger.info("Generating remediation scripts...")
        
        # Generate scripts for CRITICAL and HIGH findings only (cost optimization)
        priority_findings = [
            f for f in self.audit_results['all_findings']
            if f['severity'] in ['CRITICAL', 'HIGH']
        ]
        
        for finding in priority_findings[:10]:  # Limit to top 10 to control API costs
            try:
                script = await self.ai_analyzer.generate_remediation_script(
                    finding=finding,
                    platform=self.audit_results['platform']
                )
                
                script_filename = f"remediate_{finding['check_id']}.{'ps1' if self.audit_results['platform'] == 'Windows' else 'sh'}"
                self.audit_results['remediation_scripts'][finding['check_id']] = {
                    'filename': script_filename,
                    'content': script,
                    'finding': finding
                }
            except Exception as e:
                self.logger.error(f"Failed to generate script for {finding['check_id']}: {e}")
        
        self.logger.info(f"Generated {len(self.audit_results['remediation_scripts'])} remediation scripts")
    
    def get_metrics_summary(self) -> Optional[Dict[str, Any]]:
        """Get metrics summary for current audit"""
        if not self.execution_metrics:
            return None
        
        return self.execution_metrics.to_dict()
    
    def export_metrics(self, format: str = 'json') -> Optional[str]:
        """Export metrics in specified format"""
        if not self.execution_metrics:
            return None
        
        if format == 'json':
            return self.execution_metrics.to_json()
        elif format == 'prometheus':
            return self.execution_metrics.to_prometheus()
        elif format == 'cloudwatch':
            import json
            return json.dumps(self.execution_metrics.to_cloudwatch(), indent=2, default=str)
        else:
            raise ValueError(f"Unknown export format: {format}")
