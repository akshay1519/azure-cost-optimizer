#!/usr/bin/env python3
"""
Azure Cost Optimizer - CLI Entry Point

Usage:
    python -m analyzer.cli scan --subscription-id <SUB_ID> [options]
    python -m analyzer.cli compliance --subscription-id <SUB_ID> [options]
    python -m analyzer.cli security --workspace-id <WORKSPACE_ID> [options]

Examples:
    # Scan for cost optimization opportunities
    python -m analyzer.cli scan -s "your-subscription-id" -o reports/ -f json html csv

    # Run compliance audit
    python -m analyzer.cli compliance -s "your-subscription-id" -o reports/

    # Run security scan
    python -m analyzer.cli security -w "your-workspace-id" -o reports/

    # Run all scans
    python -m analyzer.cli all -s "your-subscription-id" -w "your-workspace-id"
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path

from azure.identity import DefaultAzureCredential


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def cmd_scan(args):
    """Run cost optimization scan."""
    from .scanner import AzureScanner
    from .reporter import ReportGenerator

    credential = DefaultAzureCredential()
    scanner = AzureScanner(
        subscription_id=args.subscription_id,
        credential=credential,
        idle_cpu_threshold=args.idle_cpu_threshold,
        idle_days=args.idle_days,
        oversized_cpu_threshold=args.oversized_cpu_threshold,
        snapshot_age_days=args.snapshot_age_days,
    )

    print(f"\n  Scanning subscription: {args.subscription_id}")
    print(f"  Idle CPU threshold: {args.idle_cpu_threshold}%")
    print(f"  Idle period: {args.idle_days} days\n")

    result = scanner.scan_all()
    reporter = ReportGenerator(result)

    # Always print console report
    print(reporter.generate_console_report())

    # Save reports
    formats = args.formats or ["json", "html", "csv"]
    saved = reporter.save_report(output_dir=args.output_dir, formats=formats)
    for path in saved:
        print(f"  Saved: {path}")

    return result


def cmd_compliance(args):
    """Run compliance audit."""
    from .compliance import ComplianceScanner

    credential = DefaultAzureCredential()
    scanner = ComplianceScanner(
        subscription_id=args.subscription_id,
        credential=credential,
    )

    print(f"\n  Running compliance scan for: {args.subscription_id}\n")

    report = scanner.scan_compliance()

    # Generate reports
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    for fmt in (args.formats or ["json", "html"]):
        content = scanner.generate_audit_report(report, output_format=fmt)
        path = output_dir / f"compliance_report_{timestamp}.{fmt}"
        path.write_text(content)
        print(f"  Saved: {path}")

    # Print text summary
    print(scanner.generate_audit_report(report, output_format="text"))
    return report


def cmd_security(args):
    """Run security scan."""
    from .security import SecurityScanner

    credential = DefaultAzureCredential()
    scanner = SecurityScanner(
        workspace_id=args.workspace_id,
        credential=credential,
        lookback_days=args.lookback_days,
    )

    print(f"\n  Running security scan on workspace: {args.workspace_id}")
    print(f"  Lookback: {args.lookback_days} days\n")

    report = scanner.scan_all()

    # Generate reports
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    for fmt in (args.formats or ["json", "html"]):
        content = scanner.generate_report(report, output_format=fmt)
        path = output_dir / f"security_report_{timestamp}.{fmt}"
        path.write_text(content)
        print(f"  Saved: {path}")

    # Print text summary
    print(scanner.generate_report(report, output_format="text"))
    return report


def cmd_all(args):
    """Run all scans."""
    print("\n" + "=" * 60)
    print("  AZURE COST OPTIMIZER - FULL SCAN")
    print("=" * 60)

    if args.subscription_id:
        print("\n--- Cost Optimization Scan ---")
        cmd_scan(args)

        print("\n--- Compliance Audit ---")
        cmd_compliance(args)

    if args.workspace_id:
        print("\n--- Security Scan ---")
        cmd_security(args)

    if not args.subscription_id and not args.workspace_id:
        print("Error: Provide --subscription-id and/or --workspace-id")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Azure Cost Optimizer - Scan Azure for cost savings, compliance gaps, and security issues.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan -s "12345678-abcd-1234-efgh-123456789012"
  %(prog)s compliance -s "12345678-abcd-1234-efgh-123456789012" -o reports/
  %(prog)s security -w "workspace-id-here" --lookback-days 14
  %(prog)s all -s "sub-id" -w "workspace-id"
        """,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # --- Scan command ---
    scan_parser = subparsers.add_parser("scan", help="Scan for cost optimization opportunities")
    scan_parser.add_argument(
        "-s", "--subscription-id", required=True, help="Azure subscription ID"
    )
    scan_parser.add_argument(
        "-o", "--output-dir", default="reports", help="Output directory (default: reports/)"
    )
    scan_parser.add_argument(
        "-f", "--formats", nargs="+", choices=["json", "html", "csv", "console"],
        help="Report formats (default: json html csv)"
    )
    scan_parser.add_argument(
        "--idle-cpu-threshold", type=float, default=5.0,
        help="CPU %% threshold for idle VMs (default: 5.0)"
    )
    scan_parser.add_argument(
        "--idle-days", type=int, default=14, help="Days to check for idle VMs (default: 14)"
    )
    scan_parser.add_argument(
        "--oversized-cpu-threshold", type=float, default=10.0,
        help="CPU %% threshold for oversized VMs (default: 10.0)"
    )
    scan_parser.add_argument(
        "--snapshot-age-days", type=int, default=30,
        help="Snapshot age threshold in days (default: 30)"
    )

    # --- Compliance command ---
    comp_parser = subparsers.add_parser("compliance", help="Run compliance audit")
    comp_parser.add_argument(
        "-s", "--subscription-id", required=True, help="Azure subscription ID"
    )
    comp_parser.add_argument(
        "-o", "--output-dir", default="reports", help="Output directory"
    )
    comp_parser.add_argument(
        "-f", "--formats", nargs="+", choices=["json", "html", "text"],
        help="Report formats (default: json html)"
    )

    # --- Security command ---
    sec_parser = subparsers.add_parser("security", help="Run security anomaly scan")
    sec_parser.add_argument(
        "-w", "--workspace-id", required=True, help="Log Analytics workspace ID"
    )
    sec_parser.add_argument(
        "-o", "--output-dir", default="reports", help="Output directory"
    )
    sec_parser.add_argument(
        "-f", "--formats", nargs="+", choices=["json", "html", "text"],
        help="Report formats (default: json html)"
    )
    sec_parser.add_argument(
        "--lookback-days", type=int, default=7,
        help="Number of days to look back (default: 7)"
    )

    # --- All command ---
    all_parser = subparsers.add_parser("all", help="Run all scans")
    all_parser.add_argument("-s", "--subscription-id", help="Azure subscription ID")
    all_parser.add_argument("-w", "--workspace-id", help="Log Analytics workspace ID")
    all_parser.add_argument("-o", "--output-dir", default="reports", help="Output directory")
    all_parser.add_argument(
        "-f", "--formats", nargs="+", default=["json", "html"],
        help="Report formats"
    )
    all_parser.add_argument("--idle-cpu-threshold", type=float, default=5.0)
    all_parser.add_argument("--idle-days", type=int, default=14)
    all_parser.add_argument("--oversized-cpu-threshold", type=float, default=10.0)
    all_parser.add_argument("--snapshot-age-days", type=int, default=30)
    all_parser.add_argument("--lookback-days", type=int, default=7)

    args = parser.parse_args()
    setup_logging(args.verbose)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "scan": cmd_scan,
        "compliance": cmd_compliance,
        "security": cmd_security,
        "all": cmd_all,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
