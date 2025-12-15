import platform
import subprocess
from typing import List

from .base_collector import BaseCollector, CollectorResult, CollectorStatus

class OSConfigCollector(BaseCollector):
    """OS configuration checks - users, services, startup"""
    
    def requires_admin(self) -> bool:
        return True
    
    def supported_platforms(self) -> List[str]:
        return ["Windows", "Linux", "Darwin"]
    
    async def collect(self) -> CollectorResult:
        result = CollectorResult(
            collector_name=self.__class__.__name__,
            status=CollectorStatus.SUCCESS
        )
        
        try:
            result.data['os_info'] = {
                'platform': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'hostname': platform.node()
            }
            
            if self.platform == "Windows":
                self._check_windows_config(result)
            elif self.platform == "Linux":
                self._check_linux_config(result)
            elif self.platform == "Darwin":
                self._check_macos_config(result)
        except Exception as e:
            result.errors.append(f"OS config error: {str(e)}")
            result.status = CollectorStatus.PARTIAL
        
        return result
    
    def _check_windows_config(self, result: CollectorResult):
        """Windows configuration checks"""
        try:
            cmd = [
                'powershell.exe',
                '-Command',
                (
                    'Get-LocalUser | Where-Object {$_.Name -eq "Guest" -and $_.Enabled -eq $true} '
                    '| Measure-Object | Select-Object -ExpandProperty Count'
                )
            ]
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if output.returncode == 0 and output.stdout.strip() != '0':
                result.add_finding(
                    check_id="CIS-2.2.1-001",
                    severity="HIGH",
                    description="Guest account is enabled",
                    current_value="Enabled",
                    expected_value="Disabled",
                    remediation_hint="net user guest /active:no"
                )
        except:
            result.warnings.append("Could not check user accounts")
    
    def _check_linux_config(self, result: CollectorResult):
        """Linux configuration checks"""
        try:
            with open('/etc/passwd', 'r') as f:
                users = [line.split(':')[0] for line in f.readlines()]
                result.data['users'] = {'count': len(users)}
        except:
            result.warnings.append("Could not read /etc/passwd")
    
    def _check_macos_config(self, result: CollectorResult):
        """macOS configuration checks"""
        try:
            cmd = ['dscl', '.', 'list', '/Users']
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if output.returncode == 0:
                users = output.stdout.strip().split('\n')
                result.data['users'] = {'count': len(users)}
        except:
            result.warnings.append("Could not enumerate users")
