"""
Shared pytest fixtures for all tests.
Provides common test configuration and mocks.
"""
import pytest
from unittest.mock import Mock, patch
from pathlib import Path
import os
import asyncio

from src.core.config import AuditConfig, AIConfig


def run_async(coro):
    """
    Helper function to run async functions synchronously in tests.
    Useful for tests that don't need to be async themselves.
    """
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(coro)


@pytest.fixture(autouse=True)
def mock_api_keys(monkeypatch):
    """
    Automatically mock API keys for all tests.
    This prevents tests from failing due to missing API keys.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key-12345")
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key-12345")


@pytest.fixture
def test_audit_config(tmp_path):
    """
    Create a test AuditConfig with safe defaults.
    Uses tmp_path for all file operations.
    """
    config = AuditConfig(
        require_admin=False,  # Don't require admin for tests
        timeout_seconds=60,
        parallel_execution=True,
        output_dir=tmp_path / "test_output",
        log_file=tmp_path / "logs" / "test.log",
        log_level="DEBUG",
        database_enabled=False,  # Disable database for most tests
        generate_remediation=False,  # Disable AI remediation for speed
    )
    return config


@pytest.fixture
def test_ai_config():
    """
    Create a test AIConfig with mocked API key.
    """
    config = AIConfig(
        provider="anthropic",
        model="claude-3-5-haiku-20241022",
        api_key="test-key-12345",
        max_tokens=1000,
        temperature=0.3
    )
    return config


@pytest.fixture
def sample_audit_results():
    """
    Sample audit results for testing reports and database.
    """
    return {
        "audit_id": "test-audit-123",
        "timestamp": "2024-01-01T00:00:00",
        "platform": "Linux",
        "hostname": "testhost",
        "platform_version": "5.15.0",
        "all_findings": [
            {
                "check_id": "TEST-001",
                "severity": "CRITICAL",
                "description": "Test finding",
                "current_value": "bad",
                "expected_value": "good",
                "remediation_hint": "Fix it",
                "collector_name": "test_collector"
            }
        ],
        "collector_results": {
            "hardware": {
                "status": "success",
                "data": {"cpu": {"count": 4}},
                "findings": []
            }
        },
        "ai_analysis": {
            "risk_score": 75,
            "executive_summary": "Test summary",
            "critical_issues": ["Issue 1"],
            "recommendations": ["Recommendation 1"]
        },
        "ai_config": {
            "provider": "anthropic",
            "model": "claude-3-5-haiku-20241022"
        }
    }


@pytest.fixture
def mock_collector_result():
    """
    Create a mock CollectorResult for testing.
    """
    from src.collectors.base_collector import CollectorResult, CollectorStatus

    result = CollectorResult(
        collector_name="test_collector",
        status=CollectorStatus.SUCCESS,
        data={"test_key": "test_value"},
        findings=[],
        errors=[],
        warnings=[],
        execution_time_ms=100.0
    )
    return result


@pytest.fixture
def mock_subprocess_success():
    """
    Mock subprocess.run for successful command execution.
    """
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = Mock(
            returncode=0,
            stdout="success output",
            stderr=""
        )
        yield mock_run


@pytest.fixture
def mock_psutil_system():
    """
    Mock psutil system information functions.
    """
    with patch('psutil.cpu_count') as mock_cpu, \
         patch('psutil.cpu_freq') as mock_freq, \
         patch('psutil.virtual_memory') as mock_mem, \
         patch('psutil.disk_partitions') as mock_disk, \
         patch('psutil.net_if_addrs') as mock_net:

        # Setup realistic mock values
        mock_cpu.return_value = 8
        mock_freq.return_value = Mock(current=2400.0, min=800.0, max=3600.0)
        mock_mem.return_value = Mock(
            total=16*1024*1024*1024,
            available=8*1024*1024*1024,
            percent=50.0
        )
        mock_disk.return_value = []
        mock_net.return_value = {
            "eth0": [Mock(family=2, address="192.168.1.100")]
        }

        yield {
            'cpu_count': mock_cpu,
            'cpu_freq': mock_freq,
            'virtual_memory': mock_mem,
            'disk_partitions': mock_disk,
            'net_if_addrs': mock_net
        }
