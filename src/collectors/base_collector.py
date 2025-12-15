from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import asyncio
import logging
import platform
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from src.core.config import AuditConfig


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
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    execution_time_ms: Optional[float] = None

    def add_finding(
        self,
        check_id: str,
        severity: str,
        description: str,
        current_value: Any,
        expected_value: Any,
        remediation_hint: Optional[str] = None,
    ):
        """Add a security finding"""
        self.findings.append(
            {
                "check_id": check_id,
                "severity": severity,  # CRITICAL, HIGH, MEDIUM, LOW, INFO
                "description": description,
                "current_value": current_value,
                "expected_value": expected_value,
                "remediation_hint": remediation_hint,
            }
        )


class BaseCollector(ABC):
    """
    Abstract base class for all system data collectors.
    Implements Template Method pattern.
    """

    name: str
    COLLECTOR_NAME: str = ""

    def __init__(self, config: Optional["AuditConfig"] = None):
        # Lazy import to avoid circular import at module load time
        if config is None:
            from src.core.config import AuditConfig  # type: ignore

            config = AuditConfig()
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.platform = platform.system()
        self.name = self.COLLECTOR_NAME or self.__class__.__name__

    @abstractmethod
    async def _collect(self) -> CollectorResult:
        """Collect system data and perform checks (async implementation)."""
        raise NotImplementedError

    async def collect_async(self) -> CollectorResult:
        """Async entrypoint (backwards compatible)."""
        return await self.safe_collect()

    def collect(self) -> CollectorResult:
        """Synchronous wrapper; raises if called from an active event loop."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.safe_collect())
        raise RuntimeError(
            "collect() cannot be called from a running event loop; use collect_async()"
        )

    @abstractmethod
    def requires_admin(self) -> bool:
        """Return True if this collector requires admin/root privileges"""
        pass

    @abstractmethod
    def supported_platforms(self) -> List[str]:
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

                return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
            except Exception:
                return False
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0  # type: ignore[attr-defined]
        return False

    async def safe_collect(self) -> CollectorResult:
        """
        Execute collection with error handling and graceful degradation.
        This is the public interface that orchestrator calls.
        """
        start_time = time.time()
        result = CollectorResult(collector_name=self.name, status=CollectorStatus.SKIPPED)

        # Platform check
        if not self.is_supported():
            msg = f"Platform {self.platform} not supported"
            result.warnings.append(msg)
            result.execution_time_ms = (time.time() - start_time) * 1000.0
            return result

        # Permission check (graceful degradation)
        if self.requires_admin() and not self.has_required_permissions():
            if self.config.require_admin:
                msg = "Requires admin/root privileges (run with sudo/admin)"
                result.errors.append(msg)
                result.status = CollectorStatus.FAILED
                result.execution_time_ms = (time.time() - start_time) * 1000.0
                return result

            msg = "Insufficient privileges; skipping checks for this collector"
            result.warnings.append(msg)
            result.status = CollectorStatus.SKIPPED
            result.execution_time_ms = (time.time() - start_time) * 1000.0
            return result

        # Execute collection
        start_time = time.time()
        try:
            result = await self._collect()
            duration_ms = (time.time() - start_time) * 1000.0
            if result is None:
                result = CollectorResult(
                    collector_name=self.name,
                    status=CollectorStatus.FAILED,
                    errors=["Collector returned no result"],
                )
            if result.execution_time_ms is None:
                result.execution_time_ms = duration_ms
        except Exception as e:
            self.logger.error(f"Collection failed: {str(e)}", exc_info=True)
            result.errors.append(str(e))
            result.status = CollectorStatus.FAILED
            result.execution_time_ms = (time.time() - start_time) * 1000.0
        finally:
            if result.execution_time_ms is None:
                result.execution_time_ms = (time.time() - start_time) * 1000.0

        return result
