import platform
import subprocess
import psutil
from typing import Dict, Any
from .base_collector import BaseCollector, CollectorResult, CollectorStatus

class SecurityCollector(BaseCollector):
    """Security posture checks - CIS Level 1 + A+ best practices"""
    
    def requires_admin(self) -> bool:
        return True
    
    def supported_platforms(self) -> list[str]:
        return ["Windows", "Linux", "Darwin"]
    
    async def collect(self) -> CollectorResult:
        result = CollectorResult(
            collector_name=self.__class__.__name__,
            status=CollectorStatus.SUCCESS
        )
        
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
            cmd = ['powershell.exe', '-Command',
                   'Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled | ConvertTo-Json']
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if output.returncode == 0:
                import json
                status = json.loads(output.stdout)
                if not status.get('RealTimeProtectionEnabled', False):
                    result.add_finding(
                        check_id="CIS-10.1-001",
                        severity="CRITICAL",
                        description="Windows Defender Real-time Protection disabled",
                        current_value="Disabled",
                        expected_value="Enabled",
                        remediation_hint="Enable via Windows Security settings"
                    )
        except subprocess.TimeoutExpired:
            result.warnings.append("Windows Defender check timed out after 10 seconds")
        except FileNotFoundError:
            result.warnings.append("PowerShell not found - unable to check Windows Defender status")
        except json.JSONDecodeError as e:
            result.warnings.append(f"Invalid JSON from Windows Defender check: {str(e)}")
        except Exception as e:
            result.warnings.append(f"Could not check Windows Defender status: {str(e)}")
        
        # Check Firewall
        try:
            cmd = ['powershell.exe', '-Command',
                   'Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json']
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if output.returncode == 0:
                import json
                profiles = json.loads(output.stdout)
                if isinstance(profiles, dict):
                    profiles = [profiles]
                for profile in profiles:
                    if not profile.get('Enabled', False):
                        result.add_finding(
                            check_id="CIS-9.1-001",
                            severity="CRITICAL",
                            description=f"Windows Firewall {profile.get('Name')} disabled",
                            current_value="Disabled",
                            expected_value="Enabled",
                            remediation_hint=f"Enable {profile.get('Name')} firewall"
                        )
        except subprocess.TimeoutExpired:
            result.warnings.append("Windows Firewall check timed out after 10 seconds")
        except FileNotFoundError:
            result.warnings.append("PowerShell not found - unable to check Windows Firewall")
        except json.JSONDecodeError as e:
            result.warnings.append(f"Invalid JSON from Windows Firewall check: {str(e)}")
        except Exception as e:
            result.warnings.append(f"Could not check Windows Firewall: {str(e)}")
        
        # Check UAC
        try:
            cmd = ['powershell.exe', '-Command',
                   r'Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA | Select-Object -ExpandProperty EnableLUA']
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if output.returncode == 0 and output.stdout.strip() != '1':
                result.add_finding(
                    check_id="CIS-2.3.17.1",
                    severity="CRITICAL",
                    description="User Account Control (UAC) disabled",
                    current_value="Disabled",
                    expected_value="Enabled",
                    remediation_hint="Enable UAC via Local Security Policy"
                )
        except subprocess.TimeoutExpired:
            result.warnings.append("UAC check timed out after 10 seconds")
        except FileNotFoundError:
            result.warnings.append("PowerShell not found - unable to check UAC status")
        except Exception as e:
            result.warnings.append(f"Could not check UAC status: {str(e)}")
    
    def _check_linux_security(self, result: CollectorResult):
        """Linux security checks"""
        # Check firewall
        try:
            ufw_output = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=5)
            if ufw_output.returncode == 0 and 'Status: active' not in ufw_output.stdout:
                result.add_finding(
                    check_id="CIS-3.5.1-001",
                    severity="CRITICAL",
                    description="UFW firewall not active",
                    current_value="inactive",
                    expected_value="active",
                    remediation_hint="Run: sudo ufw enable"
                )
        except subprocess.TimeoutExpired:
            result.warnings.append("UFW firewall check timed out after 5 seconds")
        except FileNotFoundError:
            result.warnings.append("UFW firewall not installed or not in PATH")
        except Exception as e:
            result.warnings.append(f"Could not check firewall status: {str(e)}")

        # Check SSH config
        try:
            with open('/etc/ssh/sshd_config', 'r', encoding='utf-8') as f:
                ssh_config = f.read()
                if 'PermitRootLogin yes' in ssh_config:
                    result.add_finding(
                        check_id="CIS-5.2.10",
                        severity="HIGH",
                        description="SSH permits root login",
                        current_value="PermitRootLogin yes",
                        expected_value="PermitRootLogin no",
                        remediation_hint="Edit /etc/ssh/sshd_config"
                    )
        except FileNotFoundError:
            result.warnings.append("SSH config file /etc/ssh/sshd_config not found")
        except PermissionError:
            result.warnings.append("Permission denied reading /etc/ssh/sshd_config - run with elevated privileges")
        except UnicodeDecodeError as e:
            result.warnings.append(f"SSH config file encoding error: {str(e)}")
        except IOError as e:
            result.warnings.append(f"Error reading SSH config file: {str(e)}")
        except Exception as e:
            result.warnings.append(f"Could not check SSH config: {str(e)}")
    
    def _check_macos_security(self, result: CollectorResult):
        """macOS security checks"""
        # Check Firewall
        try:
            cmd = ['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate']
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if output.returncode == 0 and 'enabled' not in output.stdout.lower():
                result.add_finding(
                    check_id="MAC-FW-001",
                    severity="HIGH",
                    description="macOS Application Firewall disabled",
                    current_value="Disabled",
                    expected_value="Enabled",
                    remediation_hint="Enable via System Preferences"
                )
        except subprocess.TimeoutExpired:
            result.warnings.append("macOS firewall check timed out after 5 seconds")
        except FileNotFoundError:
            result.warnings.append("macOS firewall command not found")
        except PermissionError:
            result.warnings.append("Permission denied checking macOS firewall - run with elevated privileges")
        except Exception as e:
            result.warnings.append(f"Could not check macOS firewall: {str(e)}")
