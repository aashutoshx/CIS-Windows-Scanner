"""
CIS Benchmark Configuration Review Tool
Supports: Windows Endpoints & Windows Servers
"""

import sys
import os
import platform
import argparse
from datetime import datetime
from engine.scanner import Scanner
from reporting.excel_reporter import ExcelReporter

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║        CIS Benchmark Configuration Review Tool               ║
║        Windows Endpoint & Server Security Assessment         ║
╚══════════════════════════════════════════════════════════════╝
"""

SYSTEM_TYPES = {
    "1": "windows_endpoint",
    "2": "windows_server",
}

SCAN_DEPTHS = {
    "1": "essential",
    "2": "intermediate",
    "3": "deep",
}

DEPTH_DESCRIPTIONS = {
    "essential": "Critical controls only — fast scan, high-impact findings",
    "intermediate": "Moderate checks — balances coverage with scan time",
    "deep": "Full CIS Benchmark — comprehensive, thorough assessment",
}


def check_platform():
    if platform.system() != "Windows":
        print("\n[WARNING] This tool is designed to run on Windows systems.")
        print("          Some checks require Windows APIs and will be simulated.\n")


def prompt_system_type() -> str:
    print("\n[Step 1] Select Target System Type:")
    print("  1. Windows Endpoint  (Workstation / Desktop)")
    print("  2. Windows Server    (Server OS)")
    choice = input("\nEnter choice [1/2]: ").strip()
    if choice not in SYSTEM_TYPES:
        print("Invalid choice. Defaulting to Windows Endpoint.")
        return "windows_endpoint"
    return SYSTEM_TYPES[choice]


def prompt_scan_depth() -> str:
    print("\n[Step 2] Select Scan Depth:")
    for key, depth in SCAN_DEPTHS.items():
        print(f"  {key}. {depth.capitalize():15s} — {DEPTH_DESCRIPTIONS[depth]}")
    choice = input("\nEnter choice [1/2/3]: ").strip()
    if choice not in SCAN_DEPTHS:
        print("Invalid choice. Defaulting to Essential.")
        return "essential"
    return SCAN_DEPTHS[choice]


def prompt_output_path(system_type: str, depth: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_name = f"CIS_Report_{system_type}_{depth}_{timestamp}.xlsx"
    print(f"\n[Step 3] Output Report Path")
    print(f"  Default: ./{default_name}")
    user_input = input("  Enter path (or press Enter to use default): ").strip()
    return user_input if user_input else default_name


def run_interactive():
    print(BANNER)
    check_platform()

    system_type = prompt_system_type()
    depth = prompt_scan_depth()
    output_path = prompt_output_path(system_type, depth)

    print(f"\n{'─'*60}")
    print(f"  System Type : {system_type.replace('_', ' ').title()}")
    print(f"  Scan Depth  : {depth.capitalize()}")
    print(f"  Output File : {output_path}")
    print(f"{'─'*60}")
    confirm = input("\nProceed with scan? [Y/n]: ").strip().lower()
    if confirm == "n":
        print("Scan cancelled.")
        sys.exit(0)

    run_scan(system_type, depth, output_path)


def run_scan(system_type: str, depth: str, output_path: str):
    print(f"\n[*] Initialising scanner...")
    scanner = Scanner(system_type=system_type, depth=depth)

    print(f"[*] Loading checklist ({depth} / {system_type})...")
    scanner.load_checklist()

    print(f"[*] Running {len(scanner.controls)} checks...\n")
    results = scanner.run()

    compliant = sum(1 for r in results if r["Status"] == "Compliant")
    non_compliant = sum(1 for r in results if r["Status"] == "Non-Compliant")
    errors = sum(1 for r in results if r["Status"] == "Error")

    print(f"\n{'─'*60}")
    print(f"  Total Checks    : {len(results)}")
    print(f"  Compliant       : {compliant}")
    print(f"  Non-Compliant   : {non_compliant}")
    print(f"  Errors/Skipped  : {errors}")
    print(f"{'─'*60}")

    print(f"\n[*] Generating Excel report → {output_path}")
    reporter = ExcelReporter(
        results=results,
        system_type=system_type,
        depth=depth,
        output_path=output_path,
    )
    reporter.generate()
    print(f"[✓] Report saved: {os.path.abspath(output_path)}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="CIS Benchmark Configuration Review Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--system",
        choices=["windows_endpoint", "windows_server"],
        help="Target system type (skips interactive prompt)",
    )
    parser.add_argument(
        "--depth",
        choices=["essential", "intermediate", "deep"],
        default="essential",
        help="Scan depth (default: essential)",
    )
    parser.add_argument("--output", help="Output Excel file path")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.system:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = args.output or f"CIS_Report_{args.system}_{args.depth}_{timestamp}.xlsx"
        print(BANNER)
        check_platform()
        run_scan(args.system, args.depth, output)
    else:
        run_interactive()
