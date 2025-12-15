import subprocess
import json
import subprocess
from typing import List

from .base_collector import BaseCollector, CollectorResult, CollectorStatus
# Collectors should capture errors without failing execution.
# pylint: disable=broad-exception-caught


class SecurityCollector(BaseCollector):
    """Security posture checks - CIS Level 1 + A+ best practices"""

    COLLECTOR_NAME = "security"

    def requires_admin(self) -> bool:
        return True

    def supported_platforms(self) -> List[str]:
        return ["Windows", "Linux", "Darwin"]

    async def _collect(self) -> CollectorResult:
        result = CollectorResult(collector_name=self.name, status=CollectorStatus.SUCCESS)

        try:
            if self.platform == "Windows":
                self._check_windows_security(result)
            elif self.platform == "Linux":
                self._check_linux_security(result)
            elif self.platform == "Darwin":
                self._check_macos_security(result)
        except Exception as e:
            result.errors.append(f"Security collection error: {str(e)}")
            result.status = CollectorStatus.PARTIAL

        return result

    def _check_windows_security(self, result: CollectorResult):
        """Windows security checks"""
        # Check Windows Defender
        try:
            cmd = [
                "powershell.exe",
                "-Command",
                "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled | ConvertTo-Json",
            ]
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
            if output.returncode == 0:
                import json

                status = json.loads(output.stdout)
                if not status.get("RealTimeProtectionEnabled", False):
                    result.add_finding(
                        check_id="CIS-10.1-001",
                        severity="CRITICAL",
                        description="Windows Defender Real-time Protection disabled",
                        current_value="Disabled",
                        expected_value="Enabled",
                        remediation_hint="Enable via Windows Security settings",
                    )
        except Exception:
            result.warnings.append("Could not check Windows Defender status")

        # Check Firewall
        try:
            cmd = [
                "powershell.exe",
                "-Command",
                "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json",
            ]
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
            if output.returncode == 0:
                import json

                profiles = json.loads(output.stdout)
                if isinstance(profiles, dict):
                    profiles = [profiles]
                for profile in profiles:
                    if not profile.get("Enabled", False):
                        result.add_finding(
                            check_id="CIS-9.1-001",
                            severity="CRITICAL",
                            description=f"Windows Firewall {profile.get('Name')} disabled",
                            current_value="Disabled",
                            expected_value="Enabled",
                            remediation_hint=f"Enable {profile.get('Name')} firewall",
                        )
        except Exception:
            result.warnings.append("Could not check Windows Firewall")

        # Check UAC
        try:
            cmd = [
                "powershell.exe",
                "-Command",
                (
                    r'Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" '
                    r'-Name EnableLUA | Select-Object -ExpandProperty EnableLUA'
                ),
            ]
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
            if output.returncode == 0 and output.stdout.strip() != "1":
                result.add_finding(
                    check_id="CIS-2.3.17.1",
                    severity="CRITICAL",
                    description="User Account Control (UAC) disabled",
                    current_value="Disabled",
                    expected_value="Enabled",
                    remediation_hint="Enable UAC via Local Security Policy",
                )
        except Exception:
            result.warnings.append("Could not check UAC status")

    def _check_linux_security(self, result: CollectorResult):
        """Linux security checks"""
        # Check firewall
        try:
            ufw_output = subprocess.run(
                ["ufw", "status"], capture_output=True, text=True, timeout=5, check=False
            )
            if ufw_output.returncode == 0 and "Status: active" not in ufw_output.stdout:
                result.add_finding(
                    check_id="CIS-3.5.1-001",
                    severity="CRITICAL",
                    description="UFW firewall not active",
                    current_value="inactive",
                    expected_value="active",
                    remediation_hint="Run: sudo ufw enable",
                )
        except Exception:
            result.warnings.append("Could not check firewall status")

        # Check SSH config
        try:
            with open("/etc/ssh/sshd_config", "r", encoding="utf-8") as f:
                ssh_config = f.read()
                if "PermitRootLogin yes" in ssh_config:
                    result.add_finding(
                        check_id="CIS-5.2.10",
                        severity="HIGH",
                        description="SSH permits root login",
                        current_value="PermitRootLogin yes",
                        expected_value="PermitRootLogin no",
                        remediation_hint="Edit /etc/ssh/sshd_config",
                    )
        except Exception:
            result.warnings.append("Could not check SSH config")

    def _check_macos_security(self, result: CollectorResult):
        """macOS security checks"""
        # Check Firewall
        try:
            cmd = [
                "/usr/libexec/ApplicationFirewall/socketfilterfw",
                "--getglobalstate",
            ]
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
            if output.returncode == 0 and "enabled" not in output.stdout.lower():
                result.add_finding(
                    check_id="MAC-FW-001",
                    severity="HIGH",
                    description="macOS Application Firewall disabled",
                    current_value="Disabled",
                    expected_value="Enabled",
                    remediation_hint="Enable via System Preferences",
                )
        except Exception:
            result.warnings.append("Could not check macOS firewall")
