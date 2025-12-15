import os
import json
import builtins
import tempfile
from pathlib import Path
import pytest

import setup_check


def test_run_checks_json_success(monkeypatch, capsys):
    # Stub checks to simulate all passing
    monkeypatch.setattr(setup_check, "check_dependencies", lambda: (True, []))
    monkeypatch.setattr(setup_check, "check_env_file", lambda: True)
    monkeypatch.setattr(setup_check, "check_permissions", lambda: True)
    monkeypatch.setattr(setup_check, "check_database", lambda: True)

    results = setup_check.run_checks(output_format="json")
    assert results["status"] == "pass"
    assert results["checks"]["Dependencies"] is True


def test_run_checks_json_missing_dep(monkeypatch, capsys):
    # Simulate missing dependency
    monkeypatch.setattr(setup_check, "check_dependencies", lambda: (False, ["psutil"]))
    monkeypatch.setattr(setup_check, "check_env_file", lambda: True)
    monkeypatch.setattr(setup_check, "check_permissions", lambda: True)
    monkeypatch.setattr(setup_check, "check_database", lambda: True)

    results = setup_check.run_checks(output_format="json")
    assert results["status"] == "fail"
    assert "psutil" in results["missing_packages"]


def test_main_exit_codes(monkeypatch):
    monkeypatch.setattr(setup_check, "run_checks", lambda output_format: {"status": "pass"})
    assert setup_check.main(["--format", "json"]) == 0

    monkeypatch.setattr(setup_check, "run_checks", lambda output_format: {"status": "fail"})
    assert setup_check.main(["--format", "json"]) == 1


def test_main_ci_flag(monkeypatch):
    # CI flag should set JSON output
    captured = {}
    def fake_run(*args, **kwargs):
        # Accept positional or keyword for compatibility
        captured['format'] = kwargs.get('output_format') or (args[0] if args else None)
        return {"status": "pass"}

    monkeypatch.setattr(setup_check, "run_checks", fake_run)
    assert setup_check.main(["--ci"]) == 0
    assert captured['format'] == 'json'


def test_check_env_file_detects_placeholder(tmp_path, monkeypatch):
    cwd = Path.cwd()
    try:
        # Change into a temp directory to avoid affecting repo files
        monkeypatch.chdir(tmp_path)
        # Write an example .env and a .env with placeholder
        (tmp_path / ".env.example").write_text("ANTHROPIC_API_KEY=your_anthropic_api_key_here\n")
        (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=your_anthropic_api_key_here\n")

        assert setup_check.check_env_file() is False

        # Now write a valid-looking key and assert True
        (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=sk-ant-0123456789abcdef\n")
        assert setup_check.check_env_file() is True
    finally:
        monkeypatch.chdir(cwd)
