#!/usr/bin/env python3
"""
A+ System Audit Utility
AI-Assisted Security & Configuration Analysis

Author: Kevin (FLCC Cybersecurity & Networking)
Course: Technical Support Fundamentals - Final Project
"""

import asyncio
import sys
import argparse
from pathlib import Path
from datetime import datetime
import json

from src.core.config import AIConfig, AuditConfig
from src.core.orchestrator import AuditOrchestrator
from src.collectors import (
    HardwareCollector,
    SecurityCollector,
    OSConfigCollector,
    NetworkCollector,
)
from src.reporters.html_report import HTMLReportGenerator


def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║           A+ SYSTEM AUDIT UTILITY v1.0                       ║
║     AI-Assisted Security & Configuration Analysis            ║
║                                                              ║
║  Implements CIS Benchmarks Level 1 + A+ Best Practices       ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="A+ System Audit Utility - Comprehensive system security and configuration analysis"
    )

    parser.add_argument("--quick", action="store_true", help="Quick audit (skip AI)")
    parser.add_argument("--no-admin", action="store_true", help="Run without admin")
    parser.add_argument("--ai", choices=["anthropic", "openai", "none"], default="anthropic")
    parser.add_argument("--model", type=str, help="AI model to use")
    parser.add_argument("--no-remediation", action="store_true", help="Skip remediation")
    parser.add_argument(
        "--collectors",
        nargs="+",
        choices=["hardware", "security", "os", "network", "all"],
        default=["all"],
    )
    parser.add_argument("--output", "-o", type=Path, default=Path("./audit_results"))
    parser.add_argument("--formats", nargs="+", choices=["html", "json", "all"], default=["all"])
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument("--version", action="version", version="A+ System Audit Utility v1.0")

    return parser.parse_args()


def build_config(args):
    if "all" in args.formats:
        report_formats = ["html", "json"]
    else:
        report_formats = args.formats

    model_defaults = {"anthropic": "claude-3-5-haiku-20241022", "openai": "gpt-4o-mini"}
    if args.quick or args.ai == "none":
        ai_config = AIConfig(provider="none")
    else:
        ai_config = AIConfig(provider=args.ai, model=args.model or model_defaults[args.ai])

    return AuditConfig(
        require_admin=not args.no_admin,
        ai=ai_config,
        output_dir=args.output,
        generate_remediation=not args.no_remediation and not args.quick and args.ai != "none",
        report_formats=report_formats,
        log_level="DEBUG" if args.verbose else "INFO",
    )


def get_collectors(config, args):
    collector_map = {
        "hardware": HardwareCollector,
        "security": SecurityCollector,
        "os": OSConfigCollector,
        "network": NetworkCollector,
    }

    if "all" in args.collectors:
        selected = list(collector_map.keys())
    else:
        selected = args.collectors

    return [collector_map[name](config) for name in selected]


async def run_audit(config, collectors):
    orchestrator = AuditOrchestrator(config)

    print("• Registering collectors...")
    for collector in collectors:
        orchestrator.register_collector(collector)
        print(f"  ✓ {collector.__class__.__name__}")

    print("▶ Starting system audit...")
    results = await orchestrator.run_audit()
    return results


def print_summary(results):
    print("\n" + "=" * 70)
    print("AUDIT SUMMARY")
    print("=" * 70)
    print(f"\nAudit ID:  {results['audit_id']}")
    print(f"Platform:  {results['platform']}")
    print(f"Total Findings: {len(results['all_findings'])}")

    if results.get("ai_analysis", {}).get("risk_score") is not None:
        risk_score = results["ai_analysis"]["risk_score"]
        print(f"\nRisk Score: {risk_score}/100")
        print(f"\n{results['ai_analysis'].get('executive_summary', '')}")

    print("\n" + "=" * 70)


def save_results(results, config):
    output_files = []
    audit_id = results["audit_id"]

    if "json" in config.report_formats:
        json_file = config.output_dir / f"audit_{audit_id}.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        output_files.append(("JSON Report", json_file))

    if "html" in config.report_formats:
        html_gen = HTMLReportGenerator(config)
        html_file = html_gen.generate_report(results)
        output_files.append(("HTML Report", html_file))

    if results.get("remediation_scripts"):
        scripts_dir = config.output_dir / f"remediation_{audit_id}"
        scripts_dir.mkdir(exist_ok=True)

        for check_id, script_data in results["remediation_scripts"].items():
            script_file = scripts_dir / script_data["filename"]
            with open(script_file, "w") as f:
                f.write(script_data["content"])

        output_files.append(("Remediation Scripts", scripts_dir))

    return output_files


def main():
    args = parse_arguments()
    print_banner()

    try:
        config = build_config(args)
    except ValueError as e:
        print(f"\n❌ Configuration error: {e}")
        sys.exit(1)

    collectors = get_collectors(config, args)

    print("\n📋 Configuration:")
    print(f"   Collectors: {', '.join([c.__class__.__name__ for c in collectors])}")
    ai_enabled = config.ai.provider in {"anthropic", "openai"}
    print(f"   AI Analysis: {'Enabled' if ai_enabled else 'Disabled'}")

    try:
        print(f"\n🚀 Starting audit at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        results = asyncio.run(run_audit(config, collectors))
        print_summary(results)

        print("\n📁 Saving results...")
        output_files = save_results(results, config)

        print("\n✓ Audit complete!")
        print("\n📄 Output files:")
        for name, path in output_files:
            print(f"   {name}: {path}")

        sys.exit(0)

    except KeyboardInterrupt:
        print("\n\n⚠️  Audit interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n❌ Audit failed: {str(e)}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
