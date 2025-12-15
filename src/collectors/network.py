import socket
from typing import List

import psutil

from .base_collector import BaseCollector, CollectorResult, CollectorStatus

class NetworkCollector(BaseCollector):
    """Network configuration and connectivity checks"""
    COLLECTOR_NAME = "network"
    
    def requires_admin(self) -> bool:
        return False
    
    def supported_platforms(self) -> List[str]:
        return ["Windows", "Linux", "Darwin"]
    
    async def _collect(self) -> CollectorResult:
        result = CollectorResult(
            collector_name=self.name,
            status=CollectorStatus.SUCCESS
        )
        
        try:
            interfaces = psutil.net_if_addrs()
        except Exception as e:
            result.errors.append(f"Interface collection failed: {e}")
            result.status = CollectorStatus.PARTIAL
            return result

        # Network interfaces (core data)
        result.data['interfaces'] = {}
        for iface, addrs in interfaces.items():
            result.data['interfaces'][iface] = [
                {'type': 'IPv4' if addr.family == socket.AF_INET else 'IPv6',
                 'address': addr.address}
                for addr in addrs if addr.family in [socket.AF_INET, socket.AF_INET6]
            ]
        
        # Active connections
        try:
            connections = psutil.net_connections(kind='inet')
            result.data['active_connections'] = len(connections)
            listening = [c for c in connections if c.status == 'LISTEN']
            result.data['listening_ports'] = len(listening)
        except Exception as e:
            result.warnings.append(f"Connection stats unavailable: {e}")
            connections = []
            listening = []
        
        # Check for risky ports
        risky_ports = {21: 'FTP', 23: 'Telnet', 139: 'NetBIOS', 445: 'SMB'}
        for conn in listening:
            if getattr(conn, "laddr", None) and conn.laddr.port in risky_ports:
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
        except Exception as e:
            result.warnings.append(f"DNS check failed: {e}")
            result.data['dns_working'] = False
        
        return result
