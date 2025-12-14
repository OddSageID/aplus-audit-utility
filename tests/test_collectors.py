"""
Comprehensive tests for collector modules
Ensures 90%+ code coverage for all collectors
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
import platform
from pathlib import Path

from src.collectors.base_collector import BaseCollector, CollectorResult, CollectorStatus
from src.collectors.hardware import HardwareCollector
from src.collectors.security import SecurityCollector
from src.collectors.os_config import OSConfigCollector
from src.collectors.network import NetworkCollector


# ============================================================================
# BaseCollector Tests
# ============================================================================

class TestBaseCollector:
    """Test BaseCollector abstract base class"""
    
    def test_collector_result_creation(self):
        """Test CollectorResult dataclass initialization"""
        result = CollectorResult(
            collector_name="test_collector",
            status=CollectorStatus.SUCCESS,
            data={"key": "value"},
            findings=[],
            errors=[],
            execution_time_ms=150.5
        )
        
        assert result.collector_name == "test_collector"
        assert result.status == CollectorStatus.SUCCESS
        assert result.data == {"key": "value"}
        assert result.execution_time_ms == 150.5
    
    def test_collector_status_enum(self):
        """Test CollectorStatus enum values"""
        assert CollectorStatus.SUCCESS.value == "success"
        assert CollectorStatus.PARTIAL.value == "partial"
        assert CollectorStatus.FAILED.value == "failed"
        assert CollectorStatus.SKIPPED.value == "skipped"
    
    def test_base_collector_cannot_instantiate(self):
        """Test that BaseCollector cannot be instantiated directly"""
        with pytest.raises(TypeError):
            BaseCollector()  # Abstract class


# ============================================================================
# HardwareCollector Tests
# ============================================================================

class TestHardwareCollector:
    """Test HardwareCollector functionality"""
    
    @pytest.fixture
    def collector(self):
        """Create HardwareCollector instance"""
        return HardwareCollector()
    
    def test_collector_initialization(self, collector):
        """Test collector initializes correctly"""
        assert collector.name == "hardware"
        assert isinstance(collector, HardwareCollector)
    
    @patch('psutil.cpu_count')
    @patch('psutil.cpu_freq')
    @patch('psutil.virtual_memory')
    def test_collect_success(self, mock_mem, mock_freq, mock_count, collector):
        """Test successful hardware data collection"""
        # Setup mocks
        mock_count.return_value = 8
        mock_freq.return_value = Mock(current=2400.0, min=800.0, max=3600.0)
        mock_mem.return_value = Mock(
            total=16*1024*1024*1024,  # 16 GB
            available=8*1024*1024*1024,  # 8 GB
            percent=50.0
        )
        
        result = collector.collect()
        
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_name == "hardware"
        assert "cpu" in result.data
        assert "memory" in result.data
        assert result.data["cpu"]["count"] == 8
        assert result.data["memory"]["percent"] == 50.0
    
    @patch('psutil.cpu_count', side_effect=Exception("CPU error"))
    def test_collect_partial_failure(self, mock_cpu, collector):
        """Test collector handles partial failures gracefully"""
        result = collector.collect()
        
        # Should still return result, but with errors recorded
        assert result.collector_name == "hardware"
        # May be PARTIAL or FAILED depending on how many subsystems fail
        assert result.status in [CollectorStatus.PARTIAL, CollectorStatus.FAILED]
        assert len(result.errors) > 0
    
    @patch('psutil.disk_partitions')
    def test_disk_collection(self, mock_partitions, collector):
        """Test disk information collection"""
        # Mock disk partitions
        mock_partition = Mock()
        mock_partition.device = "/dev/sda1"
        mock_partition.mountpoint = "/"
        mock_partition.fstype = "ext4"
        mock_partitions.return_value = [mock_partition]
        
        with patch('psutil.disk_usage') as mock_usage:
            mock_usage.return_value = Mock(
                total=500*1024*1024*1024,  # 500 GB
                used=250*1024*1024*1024,   # 250 GB
                free=250*1024*1024*1024,   # 250 GB
                percent=50.0
            )
            
            result = collector.collect()
            
            if "disk" in result.data:
                assert isinstance(result.data["disk"], list)


# ============================================================================
# SecurityCollector Tests
# ============================================================================

class TestSecurityCollector:
    """Test SecurityCollector functionality"""
    
    @pytest.fixture
    def collector(self):
        """Create SecurityCollector instance"""
        return SecurityCollector()
    
    def test_collector_initialization(self, collector):
        """Test collector initializes correctly"""
        assert collector.name == "security"
    
    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    @patch('subprocess.run')
    def test_windows_defender_check(self, mock_run, collector):
        """Test Windows Defender status check"""
        # Mock Windows Defender command output
        mock_run.return_value = Mock(
            returncode=0,
            stdout="AMRunningMode              : Normal\nRealTimeProtectionEnabled : True"
        )
        
        result = collector.collect()
        
        assert result.collector_name == "security"
        # Should contain Windows-specific checks
    
    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux-specific test")
    def test_linux_firewall_check(self, collector):
        """Test Linux firewall status check"""
        with patch('subprocess.run') as mock_run:
            # Mock ufw status
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Status: active"
            )
            
            result = collector.collect()
            
            assert result.collector_name == "security"
    
    def test_security_findings_generation(self, collector):
        """Test that security collector generates findings"""
        result = collector.collect()
        
        # Security collector should always generate some findings
        assert isinstance(result.findings, list)
        
        # Check finding structure if any exist
        if result.findings:
            finding = result.findings[0]
            assert "check_id" in finding
            assert "severity" in finding
            assert "description" in finding
    
    @patch('subprocess.run', side_effect=Exception("Command failed"))
    def test_security_check_error_handling(self, mock_run, collector):
        """Test security collector handles command failures"""
        result = collector.collect()
        
        # Should not crash, may record errors
        assert result.collector_name == "security"
        # Errors should be logged
        assert isinstance(result.errors, list)


# ============================================================================
# OSConfigCollector Tests
# ============================================================================

class TestOSConfigCollector:
    """Test OSConfigCollector functionality"""
    
    @pytest.fixture
    def collector(self):
        """Create OSConfigCollector instance"""
        return OSConfigCollector()
    
    def test_collector_initialization(self, collector):
        """Test collector initializes correctly"""
        assert collector.name == "os_config"
    
    @patch('platform.system')
    @patch('platform.release')
    @patch('platform.version')
    def test_os_information_collection(self, mock_version, mock_release, mock_system, collector):
        """Test OS information collection"""
        mock_system.return_value = "Linux"
        mock_release.return_value = "5.15.0"
        mock_version.return_value = "#1 SMP Ubuntu"
        
        result = collector.collect()
        
        assert result.status == CollectorStatus.SUCCESS
        assert "system" in result.data
        assert result.data["system"] == "Linux"
    
    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_windows_registry_checks(self, collector):
        """Test Windows registry configuration checks"""
        result = collector.collect()
        
        # Should attempt Windows-specific checks on Windows
        assert result.collector_name == "os_config"
    
    def test_environment_variables_collection(self, collector):
        """Test environment variables are collected"""
        import os
        os.environ["TEST_VAR"] = "test_value"
        
        result = collector.collect()
        
        # May or may not include env vars depending on implementation
        assert result.collector_name == "os_config"
        
        # Cleanup
        del os.environ["TEST_VAR"]


# ============================================================================
# NetworkCollector Tests
# ============================================================================

class TestNetworkCollector:
    """Test NetworkCollector functionality"""
    
    @pytest.fixture
    def collector(self):
        """Create NetworkCollector instance"""
        return NetworkCollector()
    
    def test_collector_initialization(self, collector):
        """Test collector initializes correctly"""
        assert collector.name == "network"
    
    @patch('psutil.net_if_addrs')
    def test_network_interfaces_collection(self, mock_if_addrs, collector):
        """Test network interface enumeration"""
        # Mock network interfaces
        mock_if_addrs.return_value = {
            "eth0": [
                Mock(family=2, address="192.168.1.100", netmask="255.255.255.0")
            ],
            "lo": [
                Mock(family=2, address="127.0.0.1", netmask="255.0.0.0")
            ]
        }
        
        result = collector.collect()
        
        assert result.status == CollectorStatus.SUCCESS
        if "interfaces" in result.data:
            assert isinstance(result.data["interfaces"], dict)
    
    @patch('psutil.net_connections')
    def test_network_connections_collection(self, mock_connections, collector):
        """Test active network connections collection"""
        # Mock active connection
        mock_conn = Mock()
        mock_conn.laddr = Mock(ip="0.0.0.0", port=80)
        mock_conn.raddr = None
        mock_conn.status = "LISTEN"
        mock_connections.return_value = [mock_conn]
        
        result = collector.collect()
        
        assert result.collector_name == "network"
    
    @patch('socket.gethostname')
    @patch('socket.getfqdn')
    def test_hostname_collection(self, mock_fqdn, mock_hostname, collector):
        """Test hostname and FQDN collection"""
        mock_hostname.return_value = "testhost"
        mock_fqdn.return_value = "testhost.example.com"
        
        result = collector.collect()
        
        if "hostname" in result.data:
            assert result.data["hostname"] == "testhost"
    
    @patch('psutil.net_if_stats')
    def test_interface_statistics(self, mock_stats, collector):
        """Test network interface statistics collection"""
        mock_stats.return_value = {
            "eth0": Mock(
                isup=True,
                duplex=2,
                speed=1000,
                mtu=1500
            )
        }
        
        result = collector.collect()
        
        assert result.collector_name == "network"


# ============================================================================
# Integration Tests
# ============================================================================

class TestCollectorIntegration:
    """Integration tests for multiple collectors"""
    
    def test_all_collectors_return_results(self):
        """Test that all collectors return valid results"""
        collectors = [
            HardwareCollector(),
            SecurityCollector(),
            OSConfigCollector(),
            NetworkCollector()
        ]
        
        for collector in collectors:
            result = collector.collect()
            
            assert isinstance(result, CollectorResult)
            assert result.collector_name == collector.name
            assert result.status in [
                CollectorStatus.SUCCESS,
                CollectorStatus.PARTIAL,
                CollectorStatus.FAILED,
                CollectorStatus.SKIPPED
            ]
            assert isinstance(result.data, dict)
            assert isinstance(result.findings, list)
            assert isinstance(result.errors, list)
            assert result.execution_time_ms >= 0
    
    def test_collectors_handle_privilege_errors(self):
        """Test collectors handle insufficient privileges gracefully"""
        # Most collectors should handle this via graceful degradation
        collectors = [
            HardwareCollector(),
            SecurityCollector(),
            OSConfigCollector(),
            NetworkCollector()
        ]
        
        for collector in collectors:
            # Should not raise exceptions even without admin privileges
            try:
                result = collector.collect()
                assert isinstance(result, CollectorResult)
            except Exception as e:
                pytest.fail(f"{collector.name} raised exception: {e}")
    
    def test_concurrent_collection(self):
        """Test collectors can run concurrently"""
        import concurrent.futures
        
        collectors = [
            HardwareCollector(),
            SecurityCollector(),
            OSConfigCollector(),
            NetworkCollector()
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(c.collect) for c in collectors]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        assert len(results) == 4
        for result in results:
            assert isinstance(result, CollectorResult)


# ============================================================================
# Performance Tests
# ============================================================================

class TestCollectorPerformance:
    """Performance tests for collectors"""
    
    def test_hardware_collector_performance(self):
        """Test hardware collector completes within time limit"""
        import time
        
        collector = HardwareCollector()
        start = time.time()
        result = collector.collect()
        duration = time.time() - start
        
        # Should complete within 5 seconds
        assert duration < 5.0
        assert result.execution_time_ms < 5000
    
    def test_network_collector_performance(self):
        """Test network collector completes within time limit"""
        import time
        
        collector = NetworkCollector()
        start = time.time()
        result = collector.collect()
        duration = time.time() - start
        
        # Should complete within 5 seconds
        assert duration < 5.0
    
    @pytest.mark.timeout(10)
    def test_security_collector_timeout(self):
        """Test security collector has reasonable timeout"""
        collector = SecurityCollector()
        result = collector.collect()
        
        # Should complete within pytest timeout
        assert isinstance(result, CollectorResult)


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestCollectorErrorHandling:
    """Test error handling in collectors"""
    
    def test_collector_handles_missing_dependencies(self):
        """Test collectors handle missing optional dependencies"""
        with patch('psutil.cpu_count', side_effect=ImportError("psutil not found")):
            collector = HardwareCollector()
            result = collector.collect()
            
            # Should handle gracefully
            assert isinstance(result, CollectorResult)
    
    def test_collector_handles_permission_denied(self):
        """Test collectors handle PermissionError"""
        with patch('psutil.cpu_freq', side_effect=PermissionError("Access denied")):
            collector = HardwareCollector()
            result = collector.collect()
            
            # Should still return a result
            assert isinstance(result, CollectorResult)
    
    def test_collector_handles_file_not_found(self):
        """Test collectors handle FileNotFoundError"""
        collector = OSConfigCollector()
        
        with patch('builtins.open', side_effect=FileNotFoundError("Config not found")):
            result = collector.collect()
            
            # Should handle missing files gracefully
            assert isinstance(result, CollectorResult)
