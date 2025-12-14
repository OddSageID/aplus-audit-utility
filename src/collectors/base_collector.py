from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import platform
from datetime import datetime
import logging

class CollectorStatus(Enum):
    """Collector execution status"""
    SUCCESS = "success"
    PARTIAL = "partial"  # Some checks failed but others succeeded
    FAILED = "failed"
    SKIPPED = "skipped"  # Missing permissions

@dataclass
class CollectorResult:
    """Standardized result from a collector"""
    collector_name: str
    status: CollectorStatus
    data: Dict[str, Any] = field(default_factory=dict)
    findings: list[Dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    execution_time_ms: Optional[float] = None
    
    def add_finding(self, 
                   check_id: str,
                   severity: str,
                   description: str,
                   current_value: Any,
                   expected_value: Any,
                   remediation_hint: Optional[str] = None):
        """Add a security finding"""
        self.findings.append({
            'check_id': check_id,
            'severity': severity,  # CRITICAL, HIGH, MEDIUM, LOW, INFO
            'description': description,
            'current_value': current_value,
            'expected_value': expected_value,
            'remediation_hint': remediation_hint
        })

class BaseCollector(ABC):
    """
    Abstract base class for all system data collectors.
    Implements Template Method pattern.
    """
    
    def __init__(self, config: 'AuditConfig'):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.platform = platform.system()
    
    @abstractmethod
    async def collect(self) -> CollectorResult:
        """
        Collect system data and perform checks.
        Must be implemented by subclasses.
        """
        pass
    
    @abstractmethod
    def requires_admin(self) -> bool:
        """Return True if this collector requires admin/root privileges"""
        pass
    
    @abstractmethod
    def supported_platforms(self) -> list[str]:
        """Return list of supported platforms: ['Windows', 'Linux', 'Darwin']"""
        pass
    
    def is_supported(self) -> bool:
        """Check if current platform is supported"""
        return self.platform in self.supported_platforms()
    
    def has_required_permissions(self) -> bool:
        """Check if we have required permissions"""
        if not self.requires_admin():
            return True
        
        import os
        if self.platform == "Windows":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        else:
            return os.geteuid() == 0
    
    async def safe_collect(self) -> CollectorResult:
        """
        Execute collection with error handling and graceful degradation.
        This is the public interface that orchestrator calls.
        """
        result = CollectorResult(
            collector_name=self.__class__.__name__,
            status=CollectorStatus.SKIPPED
        )
        
        # Platform check
        if not self.is_supported():
            msg = f"Platform {self.platform} not supported"
            self.logger.warning(msg)
            result.warnings.append(msg)
            return result
        
        # Permission check (graceful degradation)
        if self.requires_admin() and not self.has_required_permissions():
            if self.config.require_admin:
                msg = f"Requires admin/root privileges (run with sudo/admin)"
                self.logger.error(msg)
                result.errors.append(msg)
                result.status = CollectorStatus.FAILED
                return result
            else:
                msg = f"Running with limited permissions - some checks may be skipped"
                self.logger.warning(msg)
                result.warnings.append(msg)
        
        # Execute collection
        import time
        start_time = time.time()
        try:
            result = await self.collect()
            result.execution_time_ms = (time.time() - start_time) * 1000
        except Exception as e:
            self.logger.error(f"Collection failed: {str(e)}", exc_info=True)
            result.errors.append(str(e))
            result.status = CollectorStatus.FAILED
        
        return result
