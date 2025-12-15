import psutil
import socket
import subprocess
from typing import List
from .base_collector import BaseCollector, CollectorResult, CollectorStatus

class NetworkCollector(BaseCollector):
    """Network configuration and connectivity checks"""
    
    def requires_admin(self) -> bool:
        return False

    def supported_platforms(self) -> List[str]:
        return ["Windows", "Linux", "Darwin"]
    
    async def collect(self) -> CollectorResult:
        result = CollectorResult(
            collector_name=self.__class__.__name__,
            status=CollectorStatus.SUCCESS
        )
        
        try:
            # Network interfaces with error handling
            try:
                interfaces = psutil.net_if_addrs()
                result.data['interfaces'] = {}
                for iface, addrs in interfaces.items():
                    result.data['interfaces'][iface] = [
                        {'type': 'IPv4' if addr.family == socket.AF_INET else 'IPv6',
                         'address': addr.address}
                        for addr in addrs if addr.family in [socket.AF_INET, socket.AF_INET6]
                    ]
            except PermissionError:
                result.warnings.append("Permission denied enumerating network interfaces - run with elevated privileges")
                result.data['interfaces'] = {}
            except OSError as e:
                result.warnings.append(f"Error enumerating network interfaces: {str(e)}")
                result.data['interfaces'] = {}

            # Active connections with error handling
            try:
                connections = psutil.net_connections(kind='inet')
                result.data['active_connections'] = len(connections)

                # Listening ports
                listening = [c for c in connections if c.status == 'LISTEN']
                result.data['listening_ports'] = len(listening)
            except PermissionError:
                result.warnings.append("Permission denied accessing network connections - run with elevated privileges for full audit")
                connections = []
                listening = []
                result.data['active_connections'] = 0
                result.data['listening_ports'] = 0
            except OSError as e:
                result.warnings.append(f"Error accessing network connections: {str(e)}")
                connections = []
                listening = []
                result.data['active_connections'] = 0
                result.data['listening_ports'] = 0
            
            # Check for risky ports
            risky_ports = {21: 'FTP', 23: 'Telnet', 139: 'NetBIOS', 445: 'SMB'}
            for conn in listening:
                if conn.laddr.port in risky_ports:
                    result.add_finding(
                        check_id=f"NET-PORT-{conn.laddr.port}",
                        severity="MEDIUM",
                        description=f"Risky service exposed: {risky_ports[conn.laddr.port]}",
                        current_value=f"Port {conn.laddr.port} listening",
                        expected_value="Service disabled or firewalled",
                        remediation_hint=f"Review {risky_ports[conn.laddr.port]} necessity"
                    )
            
            # Test DNS with timeout and specific error handling
            try:
                socket.setdefaulttimeout(5)  # Set 5 second timeout for DNS queries
                socket.getaddrinfo('www.google.com', 80)
                result.data['dns_working'] = True
            except socket.timeout:
                result.add_finding(
                    check_id="NET-DNS-001",
                    severity="CRITICAL",
                    description="DNS resolution timeout - DNS server not responding",
                    current_value="DNS queries timing out after 5 seconds",
                    expected_value="DNS working",
                    remediation_hint="Check DNS server configuration and network connectivity"
                )
                result.data['dns_working'] = False
            except socket.gaierror as e:
                result.add_finding(
                    check_id="NET-DNS-001",
                    severity="CRITICAL",
                    description=f"DNS resolution failing: {str(e)}",
                    current_value="Cannot resolve hostnames",
                    expected_value="DNS working",
                    remediation_hint="Check DNS server configuration in network settings"
                )
                result.data['dns_working'] = False
            except OSError as e:
                result.add_finding(
                    check_id="NET-DNS-001",
                    severity="CRITICAL",
                    description=f"Network error during DNS check: {str(e)}",
                    current_value="Network unavailable",
                    expected_value="DNS working",
                    remediation_hint="Check network connectivity and DNS configuration"
                )
                result.data['dns_working'] = False
            except Exception as e:
                result.warnings.append(f"Unexpected error during DNS check: {str(e)}")
                result.data['dns_working'] = False
            finally:
                socket.setdefaulttimeout(None)  # Reset timeout to default
        except Exception as e:
            result.errors.append(f"Network collection error: {str(e)}")
            result.status = CollectorStatus.PARTIAL
        
        return result
