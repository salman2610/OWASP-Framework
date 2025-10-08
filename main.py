#!/usr/bin/env python3

import argparse
import yaml
import webbrowser
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Import scanners
from scanners.dast import zap_scan, api_fuzzer
from scanners.sast import bandit_scan
from scanners.dependency import dependency_check
from session_analysis import session_checker
from reports.generate_report import generate_report
from dashboard import dashboard_advanced as dashboard

# Load config
with open("config/settings.yaml") as f:
    default_config = yaml.safe_load(f)

# Helper: normalize scanner results
def normalize_results(results):
    normalized = {}
    for k, v in results.items():
        if isinstance(v, dict):
            # Ensure 'summary' key exists
            if "summary" not in v:
                v["summary"] = "No summary available"
            normalized[k] = v
        elif isinstance(v, list):
            normalized[k] = {"summary": f"{len(v)} items found", "details": v}
        else:
            normalized[k] = {"summary": str(v)}
    return normalized

def run_scans(target_url, report_format):
    results = {}

    print(Fore.CYAN + f"[*] Starting OWASP scans on target: {target_url}")

    # SAST
    if "sast" in default_config.get("scan_types", []):
        print(Fore.YELLOW + "[SAST] Running Bandit scan...")
        try:
            results["sast"] = bandit_scan.run(target_url)
        except Exception as e:
            results["sast"] = {"summary": f"Bandit scan failed: {e}"}
        print(Fore.GREEN + "[SAST ✅] Done")

    # DAST / ZAP
    if "dast" in default_config.get("scan_types", []):
        print(Fore.YELLOW + "[DAST] Running ZAP scan...")
        try:
            results["dast"] = zap_scan.run(target_url)
            print(Fore.GREEN + "[DAST ✅] Done")
        except Exception as e:
            results["dast"] = {"summary": f"ZAP scan failed: {e}"}
            print(Fore.RED + f"[DAST ❌] ZAP scan failed: {e}")

        print(Fore.YELLOW + "[DAST] Running API fuzzing...")
        try:
            results["api_fuzz"] = api_fuzzer.run(target_url)
            print(Fore.GREEN + "[API Fuzz ✅] Done")
        except Exception as e:
            results["api_fuzz"] = {"summary": f"API fuzzing failed: {e}"}
            print(Fore.RED + f"[API Fuzz ❌] {e}")

    # Dependency
    if "dependency" in default_config.get("scan_types", []):
        print(Fore.YELLOW + "[Dependency] Checking dependencies...")
        try:
            results["dependency"] = dependency_check.run(target_url)
            print(Fore.GREEN + "[Dependency ✅] Done")
        except Exception as e:
            results["dependency"] = {"summary": f"Dependency scan failed: {e}"}
            print(Fore.RED + f"[Dependency ❌] {e}")

    # Session
    if default_config.get("session", {}).get("check_jwt"):
        print(Fore.YELLOW + "[Session] Checking session management...")
        try:
            results["session"] = session_checker.run(target_url)
            print(Fore.GREEN + "[Session ✅] Done")
        except Exception as e:
            results["session"] = {"summary": f"Session check failed: {e}"}
            print(Fore.RED + f"[Session ❌] {e}")

    # Normalize all results
    results = normalize_results(results)

    # Generate report
    print(Fore.CYAN + "[Report] Generating report...")
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

    # Auto-open HTML report if requested
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

    target = args.target if args.target else default_config.get("target_url")
    report_arg = args.report if args.report else default_config.get("report", {}).get("format", ["json"])
    if isinstance(report_arg, str):
        report_format = report_arg.lower()
    else:
        report_format = report_arg

    run_scans(target, report_format)

