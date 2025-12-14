import pytest
from src.core.config import AuditConfig

def test_config():
    config = AuditConfig()
    assert config.timeout_seconds == 300

def test_imports():
    from src.collectors import HardwareCollector
    assert HardwareCollector is not None
