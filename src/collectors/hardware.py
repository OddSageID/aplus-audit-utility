import platform
from typing import List

import cpuinfo
import psutil

from .base_collector import BaseCollector, CollectorResult, CollectorStatus

# Compatibility: some platforms ship psutil without cpu_freq. Provide a stub.
if not hasattr(psutil, "cpu_freq"):

    def _cpu_freq_stub():
        return None

    psutil.cpu_freq = _cpu_freq_stub  # type: ignore[attr-defined]


class HardwareCollector(BaseCollector):
    """Collects hardware inventory and configuration"""

    COLLECTOR_NAME = "hardware"

    def requires_admin(self) -> bool:
        return False

    def supported_platforms(self) -> List[str]:
        return ["Windows", "Linux", "Darwin"]

    async def _collect(self) -> CollectorResult:
        result = CollectorResult(collector_name=self.name, status=CollectorStatus.SUCCESS)

        try:
            # CPU Information
            cpu_info = cpuinfo.get_cpu_info()
            cpu_freq_fn = getattr(psutil, "cpu_freq", None)
            cpu_freq = None
            try:
                if cpu_freq_fn is not None:
                    freq_obj = cpu_freq_fn()
                    cpu_freq = freq_obj.current if freq_obj else None
            except Exception as e:  # pylint: disable=broad-exception-caught
                # Permission errors or missing API should not break collection
                result.errors.append(f"CPU frequency unavailable: {e}")
                cpu_freq = None

            result.data["cpu"] = {
                "brand": cpu_info.get("brand_raw", "Unknown"),
                "architecture": cpu_info.get("arch", "Unknown"),
                "bits": cpu_info.get("bits", 0),
                "count": psutil.cpu_count(logical=False),
                "threads": psutil.cpu_count(logical=True),
                "frequency_mhz": cpu_freq,
                "current_usage_percent": psutil.cpu_percent(interval=1),
            }

            # Memory Information
            mem = psutil.virtual_memory()
            mem_used = getattr(mem, "used", mem.total - mem.available)
            mem_percent = getattr(mem, "percent", None)
            if mem_percent is None and mem.total:
                mem_percent = round((mem_used / mem.total) * 100, 2)
            result.data["memory"] = {
                "total_gb": round(mem.total / (1024**3), 2),
                "available_gb": round(mem.available / (1024**3), 2),
                "used_percent": mem_percent,
                "percent": mem_percent,
                "swap_total_gb": round(psutil.swap_memory().total / (1024**3), 2),
            }

            # Storage Information
            disks = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    usage_percent = getattr(usage, "percent", None)
                    if usage_percent is None and usage.total:
                        usage_percent = round((usage.used / usage.total) * 100, 2)
                    disks.append(
                        {
                            "device": partition.device,
                            "mountpoint": partition.mountpoint,
                            "fstype": partition.fstype,
                            "total_gb": round(usage.total / (1024**3), 2),
                            "used_gb": round(usage.used / (1024**3), 2),
                            "free_gb": round(usage.free / (1024**3), 2),
                            "used_percent": usage_percent,
                            "percent": usage_percent,
                        }
                    )
                except PermissionError:
                    continue
            result.data["storage"] = disks
            # Expose a shorter alias expected by some consumers/tests
            result.data["disk"] = disks

            # System Information
            result.data["system"] = {
                "platform": platform.system(),
                "platform_release": platform.release(),
                "platform_version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "hostname": platform.node(),
            }

            # Findings - Best Practice Checks
            mem_gb = result.data["memory"]["total_gb"]
            if mem_gb < 4:
                result.add_finding(
                    check_id="HW-001",
                    severity="MEDIUM",
                    description="System RAM below recommended minimum",
                    current_value=f"{mem_gb} GB",
                    expected_value="4 GB minimum (8 GB recommended)",
                    remediation_hint="Consider RAM upgrade for optimal performance",
                )

            for disk in result.data["storage"]:
                if disk["used_percent"] > 90:
                    result.add_finding(
                        check_id="HW-002",
                        severity="HIGH",
                        description=f"Critical disk space on {disk['mountpoint']}",
                        current_value=f"{disk['used_percent']}% used",
                        expected_value="<80% used",
                        remediation_hint="Run Disk Cleanup or expand storage",
                    )

            cpu_usage = result.data["cpu"]["current_usage_percent"]
            if cpu_usage > 90:
                result.add_finding(
                    check_id="HW-003",
                    severity="MEDIUM",
                    description="High CPU utilization detected",
                    current_value=f"{cpu_usage}%",
                    expected_value="<80% average",
                    remediation_hint="Check Task Manager for resource-intensive processes",
                )

        except Exception as e:  # pylint: disable=broad-exception-caught
            result.errors.append(f"Hardware collection error: {str(e)}")
            result.status = CollectorStatus.PARTIAL

        return result
