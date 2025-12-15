import argparse
from pathlib import Path

import pytest

from src.analyzers.ai_analyzer import AIAnalyzer
from src.core.config import AIConfig
from main import validate_and_normalize_args


def test_ai_analyzer_normalizes_orchestrator_output():
    analyzer = AIAnalyzer(AIConfig(provider="none"))
    orchestrator_style_results = {
        "collector_results": {
            "hardware": {
                "findings": [
                    {
                        "check_id": "HW-TEST-001",
                        "severity": "HIGH",
                        "description": "Test issue",
                        "current_value": "bad",
                        "expected_value": "good",
                    }
                ]
            }
        },
        "platform": "Windows",
        "hostname": "HOST123",
    }

    analysis = analyzer.analyze(orchestrator_style_results)
    assert analysis["risk_score"] == 25  # HIGH severity fallback weight
    assert analysis["critical_issues"]  # Finding was actually processed


def test_cli_validation_rejects_system_paths(tmp_path):
    args = argparse.Namespace(
        quick=False,
        no_admin=False,
        no_remediation=False,
        verbose=False,
        ai="anthropic",
        collectors=["all"],
        formats=["all"],
        model=None,
        output=Path("C:/Windows/System32"),
        ascii=False,
    )

    with pytest.raises(Exception):
        validate_and_normalize_args(args)

    # Valid safe path passes
    safe_args = argparse.Namespace(**{**args.__dict__, "output": tmp_path / "out"})
    normalized = validate_and_normalize_args(safe_args)
    assert normalized.output == tmp_path / "out"
