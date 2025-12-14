#!/usr/bin/env python3
"""
Pre-flight validation script for A+ System Audit Utility
Checks dependencies, permissions, and configuration before running audits

Author: Kevin Hormaza
GitHub: https://github.com/OddSageID
Course: Technical Support Fundamentals - Final Project
"""

import sys
import subprocess
import os
from pathlib import Path
from typing import Tuple, List


def print_header():
    """Print script header"""
    print("\n" + "="*70)
    print("🔍 A+ SYSTEM AUDIT UTILITY - SETUP VALIDATION")
    print("="*70 + "\n")


def check_python_version() -> bool:
    """Verify Python 3.8+ is installed"""
    print("📌 Checking Python version...")
    
    version = sys.version_info
    if version < (3, 8):
        print(f"   ❌ Python 3.8+ required (found {version.major}.{version.minor})")
        print(f"   → Download from: https://www.python.org/downloads/")
        return False
    
    print(f"   ✅ Python {version.major}.{version.minor}.{version.micro}")
    return True


def check_dependencies() -> Tuple[bool, List[str]]:
    """Verify required packages are installed"""
    print("\n📌 Checking dependencies...")
    
    required = {
        'psutil': 'System monitoring',
        'pydantic': 'Input validation',
        'sqlalchemy': 'Database support',
        'anthropic': 'AI analysis (Claude)',
        'jinja2': 'Report generation',
        'dotenv': 'Environment configuration'
    }
    
    missing = []
    
    for pkg, description in required.items():
        try:
            # Special handling for python-dotenv
            if pkg == 'dotenv':
                __import__('dotenv')
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
        'openai': 'Alternative AI provider',
        'pytest': 'Testing framework',
        'alembic': 'Database migrations'
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
    
    env_file = Path('.env')
    env_example = Path('.env.example')
    
    if not env_example.exists():
        print(f"   ⚠️  .env.example not found (expected in project root)")
    
    if not env_file.exists():
        print(f"   ❌ .env file not found")
        print(f"   → Copy .env.example to .env and configure")
        if env_example.exists():
            print(f"   → Run: cp .env.example .env")
        return False
    
    print(f"   ✅ .env file exists")
    
    # Check for API key configuration
    try:
        with open(env_file) as f:
            content = f.read()
            
            # Check if placeholder values are still present
            if 'your_anthropic_api_key_here' in content or 'your_openai_api_key_here' in content:
                print(f"   ⚠️  API key appears to be placeholder")
                print(f"   → Update ANTHROPIC_API_KEY or OPENAI_API_KEY in .env")
                return False
            
            if 'xxxxxxxxxxxxxxxxxxxxx' in content:
                print(f"   ⚠️  API key appears to be placeholder")
                print(f"   → Update ANTHROPIC_API_KEY or OPENAI_API_KEY in .env")
                return False
            
            # Check if at least one API key is configured
            has_anthropic = 'ANTHROPIC_API_KEY=' in content and 'sk-ant-' in content
            has_openai = 'OPENAI_API_KEY=' in content and 'sk-' in content
            
            if not (has_anthropic or has_openai):
                print(f"   ⚠️  No valid API key detected")
                print(f"   → Add ANTHROPIC_API_KEY or OPENAI_API_KEY to .env")
                print(f"   → Note: You can run with --quick flag to skip AI analysis")
                return False
            
            print(f"   ✅ API key configured")
            
    except Exception as e:
        print(f"   ⚠️  Error reading .env: {e}")
        return False
    
    return True


def check_permissions() -> bool:
    """Verify write permissions for output directory"""
    print("\n📌 Checking permissions...")
    
    output_dir = Path('./audit_results')
    
    try:
        # Create output directory if it doesn't exist
        output_dir.mkdir(exist_ok=True)
        
        # Test write permissions
        test_file = output_dir / '.write_test'
        test_file.write_text('test')
        test_file.unlink()
        
        print(f"   ✅ Output directory writable ({output_dir.absolute()})")
        return True
        
    except PermissionError:
        print(f"   ❌ Cannot write to output directory: {output_dir.absolute()}")
        print(f"   → Check directory permissions")
        return False
    except Exception as e:
        print(f"   ❌ Error testing permissions: {e}")
        return False


def check_database() -> bool:
    """Check if database can be created"""
    print("\n📌 Checking database...")
    
    try:
        import sqlalchemy
        
        # Test SQLite connection
        db_file = Path('./audit_history.db')
        if db_file.exists():
            print(f"   ✅ Database file exists ({db_file.absolute()})")
        else:
            print(f"   ✅ Database will be created on first run")
        
        return True
        
    except Exception as e:
        print(f"   ⚠️  Database check failed: {e}")
        return False


def check_platform_specifics() -> None:
    """Check platform-specific requirements"""
    print("\n📌 Checking platform requirements...")
    
    platform = sys.platform
    
    if platform == 'win32':
        print(f"   ℹ️  Platform: Windows")
        
        # Check for WMI
        try:
            import wmi
            print(f"   ✅ WMI available (Windows Management Instrumentation)")
        except ImportError:
            print(f"   ⚠️  WMI not installed (optional, improves Windows checks)")
            print(f"   → Install: pip install wmi")
        
        # Check for pywin32
        try:
            import win32api
            print(f"   ✅ pywin32 available (Windows API access)")
        except ImportError:
            print(f"   ⚠️  pywin32 not installed (optional, improves Windows checks)")
            print(f"   → Install: pip install pywin32")
    
    elif platform == 'linux':
        print(f"   ℹ️  Platform: Linux")
        print(f"   ℹ️  Some security checks require root/sudo privileges")
        print(f"   → Run with --no-admin flag for testing without privileges")
    
    elif platform == 'darwin':
        print(f"   ℹ️  Platform: macOS")
        print(f"   ℹ️  Some security checks require admin privileges")
        print(f"   → Run with --no-admin flag for testing without privileges")
    
    else:
        print(f"   ⚠️  Platform: {platform} (untested)")


def print_quick_start() -> None:
    """Print quick start instructions"""
    print("\n" + "="*70)
    print("🚀 QUICK START COMMANDS")
    print("="*70)
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


def main():
    """Run all validation checks"""
    print_header()
    
    checks = [
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("Configuration", check_env_file),
        ("Permissions", check_permissions),
        ("Database", check_database),
    ]
    
    results = []
    missing_packages = []
    
    for name, check_fn in checks:
        if name == "Dependencies":
            success, missing = check_fn()
            results.append(success)
            missing_packages = missing
        else:
            results.append(check_fn())
    
    # Additional checks that don't affect pass/fail
    check_optional_dependencies()
    check_platform_specifics()
    
    # Summary
    print("\n" + "="*70)
    print("📊 VALIDATION SUMMARY")
    print("="*70)
    
    if all(results):
        print("\n✅ ALL CHECKS PASSED - READY TO RUN!")
        print_quick_start()
        sys.exit(0)
    else:
        print("\n❌ SOME CHECKS FAILED - FIX ISSUES ABOVE")
        
        if missing_packages:
            print("\n💡 To install missing dependencies:")
            print(f"   pip install {' '.join(missing_packages)}")
            print("\n   Or install all requirements:")
            print(f"   pip install -r requirements.txt")
        
        print("\n📖 Refer to README.md for detailed setup instructions")
        print()
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Validation interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n❌ Validation failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
