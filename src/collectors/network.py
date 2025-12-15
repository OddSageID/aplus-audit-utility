import socket
from typing import List

import psutil

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
            # Network interfaces
            interfaces = psutil.net_if_addrs()
            result.data['interfaces'] = {}
            for iface, addrs in interfaces.items():
                result.data['interfaces'][iface] = [
                    {'type': 'IPv4' if addr.family == socket.AF_INET else 'IPv6',
                     'address': addr.address}
                    for addr in addrs if addr.family in [socket.AF_INET, socket.AF_INET6]
                ]
            
            # Active connections
            connections = psutil.net_connections(kind='inet')
            result.data['active_connections'] = len(connections)
            
            # Listening ports
            listening = [c for c in connections if c.status == 'LISTEN']
            result.data['listening_ports'] = len(listening)
            
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
            
            # Test DNS
            try:
                socket.getaddrinfo('www.google.com', 80)
                result.data['dns_working'] = True
            except:
                result.add_finding(
                    check_id="NET-DNS-001",
                    severity="CRITICAL",
                    description="DNS resolution failing",
                    current_value="Cannot resolve hostnames",
                    expected_value="DNS working",
                    remediation_hint="Check DNS server configuration"
                )
                result.data['dns_working'] = False
        except Exception as e:
            result.errors.append(f"Network collection error: {str(e)}")
            result.status = CollectorStatus.PARTIAL
        
        return result
