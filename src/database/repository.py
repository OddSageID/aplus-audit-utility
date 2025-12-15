"""
Repository pattern for database operations.
Provides clean abstraction over SQLAlchemy ORM.
"""
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy import create_engine, func, desc
from sqlalchemy.orm import sessionmaker, Session, selectinload
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import NullPool
import hashlib
import json
import logging

from .models import Base, AuditRun, AuditFinding, RemediationExecution, SeverityLevel, ApprovalState


class AuditRepository:
    """
    Repository for audit data persistence and retrieval.
    Implements data access patterns with transaction management.
    """
    
    def __init__(self, database_url: str = "sqlite:///./audit_history.db"):
        """
        Initialize repository with database connection.
        
        Args:
            database_url: SQLAlchemy connection string
                - SQLite: "sqlite:///./audit_history.db"
                - PostgreSQL: "postgresql://user:pass@localhost/audit_db"
        """
        self.logger = logging.getLogger(__name__)
        self.engine = create_engine(
            database_url,
            echo=False,
            pool_pre_ping=True,  # Verify connections before use
            pool_recycle=3600,   # Recycle connections after 1 hour
            poolclass=NullPool,  # Avoid holding SQLite file locks across tests
        )
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
            bind=self.engine
        )
        
        # Create tables if they don't exist
        Base.metadata.create_all(bind=self.engine)
        self.logger.info(f"Database initialized: {database_url}")
    
    def _get_session(self) -> Session:
        """Get database session"""
        return self.SessionLocal()
    
    @staticmethod
    def _generate_results_hash(results: Dict[str, Any]) -> str:
        """Generate SHA-256 hash of results for integrity verification"""
        content = json.dumps(results, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()

    def _build_integrity_payload(self, audit_run: AuditRun, raw_results: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Build canonical payload used for integrity hashing."""
        return {
            "audit_id": audit_run.audit_id,
            "timestamp": audit_run.timestamp.isoformat() if audit_run.timestamp else None,
            "platform": audit_run.platform,
            "hostname": audit_run.hostname,
            "platform_version": audit_run.platform_version,
            "risk_score": audit_run.risk_score,
            "risk_level": audit_run.risk_level,
            "total_findings": audit_run.total_findings,
            "critical_count": audit_run.critical_count,
            "high_count": audit_run.high_count,
            "medium_count": audit_run.medium_count,
            "low_count": audit_run.low_count,
            "collectors_executed": audit_run.collectors_executed,
            "collectors_failed": audit_run.collectors_failed,
            "raw_results": raw_results if raw_results is not None else audit_run.raw_results,
        }
    
    def save_audit_run(
        self,
        audit_results: Dict[str, Any],
        executed_by: Optional[str] = None,
        execution_time_seconds: Optional[float] = None
    ) -> AuditRun:
        """
        Save complete audit run to database.
        
        Args:
            audit_results: Complete audit results dictionary
            executed_by: Username/identifier of executor
            execution_time_seconds: Total execution time
            
        Returns:
            Saved AuditRun object
        """
        session = self._get_session()
        
        try:
            # Calculate severity counts
            findings = audit_results.get('all_findings', [])
            severity_counts = {
                'critical': sum(1 for f in findings if f['severity'] == 'CRITICAL'),
                'high': sum(1 for f in findings if f['severity'] == 'HIGH'),
                'medium': sum(1 for f in findings if f['severity'] == 'MEDIUM'),
                'low': sum(1 for f in findings if f['severity'] == 'LOW'),
            }
            
            # Determine risk level
            risk_score = audit_results.get('ai_analysis', {}).get('risk_score', 0)
            if risk_score >= 75:
                risk_level = 'CRITICAL'
            elif risk_score >= 50:
                risk_level = 'HIGH'
            elif risk_score >= 25:
                risk_level = 'MEDIUM'
            else:
                risk_level = 'LOW'
            
            # Create audit run record
            audit_run = AuditRun(
                audit_id=audit_results['audit_id'],
                timestamp=datetime.fromisoformat(audit_results['timestamp'].replace('Z', '+00:00')),
                platform=audit_results['platform'],
                hostname=audit_results['hostname'],
                platform_version=audit_results.get('platform_version'),
                risk_score=risk_score,
                risk_level=risk_level,
                total_findings=len(findings),
                critical_count=severity_counts['critical'],
                high_count=severity_counts['high'],
                medium_count=severity_counts['medium'],
                low_count=severity_counts['low'],
                executed_by=executed_by,
                execution_time_seconds=execution_time_seconds,
                collectors_executed=len(audit_results.get('collector_results', {})),
                collectors_failed=sum(
                    1 for r in audit_results.get('collector_results', {}).values()
                    if r.get('status') == 'failed'
                ),
                ai_provider=audit_results.get('ai_config', {}).get('provider'),
                ai_model=audit_results.get('ai_config', {}).get('model'),
                raw_results=audit_results,
            )
            audit_run.results_hash = self._generate_results_hash(
                self._build_integrity_payload(audit_run, audit_results)
            )
            
            session.add(audit_run)
            
            # Save individual findings
            for finding_data in findings:
                finding = AuditFinding(
                    audit_id=audit_results['audit_id'],
                    check_id=finding_data['check_id'],
                    severity=SeverityLevel(finding_data['severity']),
                    description=finding_data['description'],
                    current_value=str(finding_data.get('current_value', '')),
                    expected_value=str(finding_data.get('expected_value', '')),
                    remediation_hint=finding_data.get('remediation_hint'),
                    collector_name=finding_data.get('collector_name')
                )
                audit_run.findings.append(finding)
            
            # Save remediation scripts
            for script_id, script_data in audit_results.get('remediation_scripts', {}).items():
                remediation = RemediationExecution(
                    audit_id=audit_results['audit_id'],
                    script_id=script_id,
                    check_id=script_data.get('finding', {}).get('check_id', ''),
                    script_filename=script_data.get('filename'),
                    script_content=script_data.get('content'),
                    approval_state=ApprovalState.PENDING
                )
                audit_run.remediations.append(remediation)
            
            session.commit()
            self.logger.info(f"Saved audit run: {audit_run.audit_id}")
            # Reload with relationships eager loaded so the object is usable after session close
            loaded = session.query(AuditRun).options(
                selectinload(AuditRun.findings),
                selectinload(AuditRun.remediations)
            ).filter(AuditRun.audit_id == audit_run.audit_id).first()
            return loaded
            
        except SQLAlchemyError as e:
            session.rollback()
            self.logger.error(f"Failed to save audit run: {e}")
            raise
        finally:
            session.close()
    
    def get_audit_run(self, audit_id: str) -> Optional[AuditRun]:
        """Retrieve specific audit run by ID"""
        session = self._get_session()
        try:
            return session.query(AuditRun).options(
                selectinload(AuditRun.findings),
                selectinload(AuditRun.remediations)
            ).filter(AuditRun.audit_id == audit_id).first()
        finally:
            session.close()
    
    def get_recent_audits(self, limit: int = 10, hostname: Optional[str] = None) -> List[AuditRun]:
        """
        Get most recent audit runs.
        
        Args:
            limit: Maximum number of results
            hostname: Filter by hostname (optional)
        """
        session = self._get_session()
        try:
            query = session.query(AuditRun).options(
                selectinload(AuditRun.findings),
                selectinload(AuditRun.remediations)
            ).order_by(desc(AuditRun.timestamp))
            
            if hostname:
                query = query.filter(AuditRun.hostname == hostname)
            
            return query.limit(limit).all()
        finally:
            session.close()
    
    def get_audit_trends(
        self,
        hostname: Optional[str] = None,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Get audit trends over time for analytics.
        
        Returns:
            Dictionary with trend data including:
            - risk_scores: List of (date, score) tuples
            - finding_counts: List of (date, count) tuples
            - severity_trends: Breakdown by severity over time
        """
        session = self._get_session()
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            query = session.query(AuditRun).filter(AuditRun.timestamp >= cutoff_date)
            
            if hostname:
                query = query.filter(AuditRun.hostname == hostname)
            
            audits = query.order_by(AuditRun.timestamp).all()
            
            return {
                'risk_scores': [(a.timestamp, a.risk_score) for a in audits],
                'finding_counts': [(a.timestamp, a.total_findings) for a in audits],
                'critical_counts': [(a.timestamp, a.critical_count) for a in audits],
                'high_counts': [(a.timestamp, a.high_count) for a in audits],
            }
        finally:
            session.close()
    
    def get_unresolved_findings(
        self,
        severity: Optional[SeverityLevel] = None,
        limit: int = 100
    ) -> List[AuditFinding]:
        """Get unresolved findings across all audits"""
        session = self._get_session()
        try:
            query = session.query(AuditFinding).filter(AuditFinding.resolved == False)
            
            if severity:
                query = query.filter(AuditFinding.severity == severity)
            
            return query.order_by(desc(AuditFinding.detected_at)).limit(limit).all()
        finally:
            session.close()
    
    def mark_finding_resolved(
        self,
        finding_id: int,
        resolution_notes: Optional[str] = None
    ) -> bool:
        """Mark a finding as resolved"""
        session = self._get_session()
        try:
            finding = session.query(AuditFinding).filter(AuditFinding.id == finding_id).first()
            if finding:
                finding.resolved = True
                finding.resolved_at = datetime.utcnow()
                finding.resolution_notes = resolution_notes
                session.commit()
                self.logger.info(f"Marked finding {finding_id} as resolved")
                return True
            return False
        except SQLAlchemyError as e:
            session.rollback()
            self.logger.error(f"Failed to mark finding resolved: {e}")
            return False
        finally:
            session.close()
    
    def get_remediation_by_id(self, remediation_id: int) -> Optional[RemediationExecution]:
        """Get remediation execution record"""
        session = self._get_session()
        try:
            return session.query(RemediationExecution).filter(
                RemediationExecution.id == remediation_id
            ).first()
        finally:
            session.close()
    
    def update_remediation_approval(
        self,
        remediation_id: int,
        state: ApprovalState,
        approved_by: Optional[str] = None
    ) -> bool:
        """Update remediation approval state"""
        session = self._get_session()
        try:
            remediation = session.query(RemediationExecution).filter(
                RemediationExecution.id == remediation_id
            ).first()
            
            if remediation:
                remediation.approval_state = state
                remediation.approved_by = approved_by
                remediation.approved_at = datetime.utcnow()
                session.commit()
                self.logger.info(f"Updated remediation {remediation_id} to {state}")
                return True
            return False
        except SQLAlchemyError as e:
            session.rollback()
            self.logger.error(f"Failed to update remediation approval: {e}")
            return False
        finally:
            session.close()
    
    def record_remediation_execution(
        self,
        remediation_id: int,
        success: bool,
        executed_by: str,
        execution_log: str,
        duration_seconds: float,
        pre_state: Optional[Dict] = None,
        post_state: Optional[Dict] = None
    ) -> bool:
        """Record remediation script execution"""
        session = self._get_session()
        try:
            remediation = session.query(RemediationExecution).filter(
                RemediationExecution.id == remediation_id
            ).first()
            
            if remediation:
                remediation.executed_at = datetime.utcnow()
                remediation.executed_by = executed_by
                remediation.execution_success = success
                remediation.execution_log = execution_log
                remediation.execution_duration_seconds = duration_seconds
                remediation.pre_execution_state = pre_state
                remediation.post_execution_state = post_state
                remediation.approval_state = ApprovalState.EXECUTED if success else ApprovalState.FAILED
                session.commit()
                self.logger.info(f"Recorded execution for remediation {remediation_id}: {'success' if success else 'failed'}")
                return True
            return False
        except SQLAlchemyError as e:
            session.rollback()
            self.logger.error(f"Failed to record remediation execution: {e}")
            return False
        finally:
            session.close()
    
    def get_statistics(self, hostname: Optional[str] = None) -> Dict[str, Any]:
        """Get overall audit statistics"""
        session = self._get_session()
        try:
            query = session.query(AuditRun)
            if hostname:
                query = query.filter(AuditRun.hostname == hostname)
            
            total_audits = query.count()
            
            if total_audits == 0:
                return {
                    'total_audits': 0,
                    'avg_risk_score': 0,
                    'total_findings': 0,
                    'critical_findings': 0,
                    'high_findings': 0
                }
            
            avg_risk_score = session.query(func.avg(AuditRun.risk_score)).filter(
                AuditRun.hostname == hostname if hostname else True
            ).scalar() or 0
            
            total_findings = session.query(func.sum(AuditRun.total_findings)).filter(
                AuditRun.hostname == hostname if hostname else True
            ).scalar() or 0
            
            critical_findings = session.query(func.sum(AuditRun.critical_count)).filter(
                AuditRun.hostname == hostname if hostname else True
            ).scalar() or 0
            
            high_findings = session.query(func.sum(AuditRun.high_count)).filter(
                AuditRun.hostname == hostname if hostname else True
            ).scalar() or 0
            
            return {
                'total_audits': total_audits,
                'avg_risk_score': round(float(avg_risk_score), 2),
                'total_findings': int(total_findings),
                'critical_findings': int(critical_findings),
                'high_findings': int(high_findings)
            }
        finally:
            session.close()
    
    def verify_integrity(self, audit_id: str) -> bool:
        """Verify integrity of audit results using stored hash"""
        session = self._get_session()
        try:
            audit = session.query(AuditRun).filter(AuditRun.audit_id == audit_id).first()
            if not audit or not audit.raw_results:
                return False
            payload = self._build_integrity_payload(audit)
            current_hash = self._generate_results_hash(payload)
            return current_hash == audit.results_hash
        finally:
            session.close()
