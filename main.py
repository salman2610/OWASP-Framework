#!/usr/bin/env python3

import argparse
import yaml
import webbrowser
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Import your scanners and utilities
from scanners.dast import zap_scan, api_fuzzer
from scanners.sast import bandit_scan
from scanners.dependency import dependency_check
from session_analysis import session_checker
from reports.generate_report import generate_report
from dashboard import dashboard_advanced as dashboard

# Load default config
with open("config/settings.yaml") as f:
    default_config = yaml.safe_load(f)

def run_scans(target_url, report_format):
    results = {}

    print(Fore.CYAN + f"[*] Starting OWASP scans on target: {target_url}")

    # SAST
    if "sast" in default_config.get("scan_types", []):
        print(Fore.YELLOW + "[SAST] Running Bandit scan...")
        results["sast"] = bandit_scan.run(target_url)
        print(Fore.GREEN + "[SAST ✅] Done")

    # DAST
    if "dast" in default_config.get("scan_types", []):
        print(Fore.YELLOW + "[DAST] Running ZAP scan...")
        results["dast"] = zap_scan.run(target_url)
        print(Fore.GREEN + "[DAST ✅] Done")

        print(Fore.YELLOW + "[DAST] Running API fuzzing...")
        results["api_fuzz"] = api_fuzzer.run(target_url)
        print(Fore.GREEN + "[API Fuzz ✅] Done")

    # Dependency
    if "dependency" in default_config.get("scan_types", []):
        print(Fore.YELLOW + "[Dependency] Checking dependencies...")
        results["dependency"] = dependency_check.run(target_url)
        print(Fore.GREEN + "[Dependency ✅] Done")

    # Session
    if default_config.get("session", {}).get("check_jwt"):
        print(Fore.YELLOW + "[Session] Checking session management...")
        results["session"] = session_checker.run(target_url)
        print(Fore.GREEN + "[Session ✅] Done")

    # Generate report
    print(Fore.CYAN + "[Report] Generating report...")
    # ensure report_format is a list to keep compatibility
    if isinstance(report_format, str):
        formats = [report_format.lower()]
    else:
        formats = report_format
    generate_report(results, formats)
    print(Fore.GREEN + f"[Report ✅] {', '.join([f.upper() for f in formats])} report generated")

    # Update dashboard
    try:
        dashboard.add_scan(results)
        dashboard.generate_dashboard()
        print(Fore.GREEN + "[Dashboard ✅] Advanced dashboard generated")
    except Exception as e:
        print(Fore.RED + f"[Dashboard ❌] Could not update dashboard: {e}")

    # Auto-open HTML report if HTML selected
    if "html" in formats:
        try:
            webbrowser.open("reports/latest_report.html")
        except Exception:
            pass

    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OWASP Top 10 Automated Scanning Framework")
    parser.add_argument("--target", type=str, help="Target URL to scan")
    parser.add_argument("--report", type=str, choices=["html", "json"], help="Report format", default=None)
    args = parser.parse_args()

    # determine final target and report format
    target = args.target if args.target else default_config.get("target_url")
    report_arg = args.report if args.report else default_config.get("report", {}).get("format", ["json"])

    # normalize report_arg so it's either 'html','json' or list of them
    if isinstance(report_arg, list):
        report_format = report_arg
    elif isinstance(report_arg, str):
        report_format = report_arg.lower()
    else:
        report_format = "json"

    run_scans(target, report_format)

