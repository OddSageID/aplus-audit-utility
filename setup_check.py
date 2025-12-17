#!/usr/bin/env python3
"""
Pre-flight validation script for A+ System Audit Utility
Checks dependencies, permissions, and configuration before running audits

Author: Kevin Hormaza
GitHub: https://github.com/OddSageID
Course: Technical Support Fundamentals - Final Project
"""

import sys
from pathlib import Path
from typing import Tuple, List, Dict, Any, Optional
import argparse
import json


def _supports_unicode() -> bool:
    """Return True if stdout encoding can render common Unicode characters."""
    encoding = sys.stdout.encoding
    if not encoding:
        return False
    try:
        "✓→".encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


USE_ASCII = not _supports_unicode()
if USE_ASCII and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")


def print_header():
    """Print script header"""
    print("\n" + "=" * 70)
    if USE_ASCII:
        print("A+ SYSTEM AUDIT UTILITY - SETUP VALIDATION")
    else:
        print("🔍 A+ SYSTEM AUDIT UTILITY - SETUP VALIDATION")
    print("=" * 70 + "\n")


def check_python_version() -> bool:
    """Verify Python 3.8+ is installed"""
    print("📌 Checking Python version...")

    version = sys.version_info
    if version < (3, 8):
        print(f"   ❌ Python 3.8+ required (found {version.major}.{version.minor})")
        print("   → Download from: https://www.python.org/downloads/")
        return False

    print(f"   ✅ Python {version.major}.{version.minor}.{version.micro}")
    return True


def check_dependencies() -> Tuple[bool, List[str]]:
    """Verify required packages are installed"""
    print("\n📌 Checking dependencies...")

    required = {
        "psutil": "System monitoring",
        "pydantic": "Input validation",
        "sqlalchemy": "Database support",
        "anthropic": "AI analysis (Claude)",
        "jinja2": "Report generation",
        "dotenv": "Environment configuration",
    }

    missing = []

    for pkg, description in required.items():
        try:
            # Special handling for python-dotenv
            if pkg == "dotenv":
                __import__("dotenv")
            else:
                __import__(pkg)
            print(f"   ✅ {pkg:15} - {description}")
        except ImportError:
            print(f"   ❌ {pkg:15} - {description} (NOT INSTALLED)")
            missing.append(pkg)

    return len(missing) == 0, missing


def check_optional_dependencies() -> None:
    """Check optional packages"""
    print("\n📌 Checking optional dependencies...")

    optional = {
        "openai": "Alternative AI provider",
        "pytest": "Testing framework",
        "alembic": "Database migrations",
    }

    for pkg, description in optional.items():
        try:
            __import__(pkg)
            print(f"   ✅ {pkg:15} - {description}")
        except ImportError:
            print(f"   ⚠️  {pkg:15} - {description} (optional)")


def check_env_file() -> bool:
    """Verify .env configuration exists and appears valid"""
    print("\n📌 Checking configuration...")

    env_file = Path(".env")
    env_example = Path(".env.example")

    if not env_example.exists():
        print("   ⚠️  .env.example not found (expected in project root)")

    if not env_file.exists():
        print("   ❌ .env file not found")
        print("   → Copy .env.example to .env and configure")
        if env_example.exists():
            print("   → Run: cp .env.example .env")
        return False

    print("   ✅ .env file exists")

    # Check for API key configuration
    try:
        with open(env_file, encoding="utf-8") as f:
            content = f.read()

            # Check if placeholder values are still present
            if "your_anthropic_api_key_here" in content or "your_openai_api_key_here" in content:
                print("   ⚠️  API key appears to be placeholder")
                print("   → Update ANTHROPIC_API_KEY or OPENAI_API_KEY in .env")
                return False

            if "xxxxxxxxxxxxxxxxxxxxx" in content:
                print("   ⚠️  API key appears to be placeholder")
                print("   → Update ANTHROPIC_API_KEY or OPENAI_API_KEY in .env")
                return False

            # Check if at least one API key is configured
            has_anthropic = "ANTHROPIC_API_KEY=" in content and "sk-ant-" in content
            has_openai = "OPENAI_API_KEY=" in content and "sk-" in content

            if not (has_anthropic or has_openai):
                print("   ⚠️  No valid API key detected")
                print("   → Add ANTHROPIC_API_KEY or OPENAI_API_KEY to .env")
                print("   → Note: You can run with --quick flag to skip AI analysis")
                return False

            print("   ✅ API key configured")

    except Exception as e:
        print(f"   ⚠️  Error reading .env: {e}")
        return False

    return True


def check_permissions() -> bool:
    """Verify write permissions for output directory"""
    print("\n📌 Checking permissions...")

    output_dir = Path("./audit_results")

    try:
        # Create output directory if it doesn't exist
        output_dir.mkdir(exist_ok=True)

        # Test write permissions
        test_file = output_dir / ".write_test"
        test_file.write_text("test")
        test_file.unlink()

        print(f"   ✅ Output directory writable ({output_dir.absolute()})")
        return True

    except PermissionError:
        print(f"   ❌ Cannot write to output directory: {output_dir.absolute()}")
        print("   → Check directory permissions")
        return False
    except Exception as e:
        print(f"   ❌ Error testing permissions: {e}")
        return False


def check_database() -> bool:
    """Check if database can be created"""
    print("\n📌 Checking database...")

    try:
        import sqlalchemy

        _ = sqlalchemy

        # Test SQLite connection
        db_file = Path("./audit_history.db")
        if db_file.exists():
            print(f"   ✅ Database file exists ({db_file.absolute()})")
        else:
            print("   ✅ Database will be created on first run")

        return True

    except Exception as e:
        print(f"   ⚠️  Database check failed: {e}")
        return False


def check_platform_specifics() -> None:
    """Check platform-specific requirements"""
    print("\n📌 Checking platform requirements...")

    platform = sys.platform

    if platform == "win32":
        print("   ℹ️  Platform: Windows")

        # Check for WMI
        try:
            import wmi

            _ = wmi
            print("   ✅ WMI available (Windows Management Instrumentation)")
        except ImportError:
            print("   ⚠️  WMI not installed (optional, improves Windows checks)")
            print("   → Install: pip install wmi")

        # Check for pywin32
        try:
            import win32api

            _ = win32api
            print("   ✅ pywin32 available (Windows API access)")
        except ImportError:
            print("   ⚠️  pywin32 not installed (optional, improves Windows checks)")
            print("   → Install: pip install pywin32")

    elif platform == "linux":
        print("   ℹ️  Platform: Linux")
        print("   ℹ️  Some security checks require root/sudo privileges")
        print("   → Run with --no-admin flag for testing without privileges")

    elif platform == "darwin":
        print("   ℹ️  Platform: macOS")
        print("   ℹ️  Some security checks require admin privileges")
        print("   → Run with --no-admin flag for testing without privileges")

    else:
        print(f"   ⚠️  Platform: {platform} (untested)")


def print_quick_start() -> None:
    """Print quick start instructions"""
    print("\n" + "=" * 70)
    if USE_ASCII:
        print("QUICK START COMMANDS")
    else:
        print("🚀 QUICK START COMMANDS")
    print("=" * 70)
    print("\nBasic usage:")
    print("  python main.py              # Full audit with AI analysis")
    print("  python main.py --quick      # Quick audit without AI")
    print("  python main.py --verbose    # Detailed logging")
    print("  python main.py --no-admin   # Run without admin privileges")
    print("\nAdvanced usage:")
    print("  python main.py --collectors security hardware")
    print("  python main.py --ai openai --model gpt-4o-mini")
    print("  python main.py --formats json")
    print("\nFor help:")
    print("  python main.py --help")
    print("\nDocumentation:")
    print("  README.md               - Comprehensive guide")
    print("  PROJECT_SUBMISSION.md   - Academic documentation")
    print()


def run_checks(output_format: str = "pretty") -> Dict[str, Any]:
    """Run validation checks and return a structured result.

    Args:
        output_format: 'pretty' or 'json' - controls printed output

    Returns:
        A dict summarizing the checks and status
    """
    print_header()

    checks = [
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("Configuration", check_env_file),
        ("Permissions", check_permissions),
        ("Database", check_database),
    ]

    results: Dict[str, Any] = {"checks": {}, "missing_packages": []}

    for name, check_fn in checks:
        if name == "Dependencies":
            success, missing = check_fn()
            results["checks"][name] = success
            results["missing_packages"] = missing
        else:
            results["checks"][name] = check_fn()

    # Additional non-blocking checks
    check_optional_dependencies()
    check_platform_specifics()

    overall = all(results["checks"].values())
    results["status"] = "pass" if overall else "fail"

    # Output formatting
    if output_format == "json":
        print(json.dumps(results, indent=2))
    else:
        # Pretty human-readable summary
        print("\n" + "=" * 70)
        print("📊 VALIDATION SUMMARY")
        print("=" * 70)

        if overall:
            print("\n✅ ALL CHECKS PASSED - READY TO RUN!")
            print_quick_start()
        else:
            print("\n❌ SOME CHECKS FAILED - FIX ISSUES ABOVE")
            if results["missing_packages"]:
                print("\n💡 To install missing dependencies:")
                print(f"   pip install {' '.join(results['missing_packages'])}")
                print("\n   Or install all requirements:")
                print("   pip install -r requirements.txt")
            print("\n📖 Refer to README.md for detailed setup instructions")

    return results


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for the setup checker."""
    parser = argparse.ArgumentParser(description="A+ audit setup validation")
    parser.add_argument(
        "--format",
        choices=["pretty", "json"],
        default="pretty",
        help="Output format for automation (json) or humans (pretty)",
    )
    parser.add_argument("--ci", action="store_true", help="Run in CI mode (implies --format json)")

    args = parser.parse_args(argv)

    if args.ci:
        output_format = "json"
    else:
        output_format = args.format

    results = run_checks(output_format=output_format)
    return 0 if results.get("status") == "pass" else 1


if __name__ == "__main__":
    try:
        EXIT_CODE = main()
        sys.exit(EXIT_CODE)
    except KeyboardInterrupt:
        print("\n\n⚠️  Validation interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n❌ Validation failed with error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
