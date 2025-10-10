#!/usr/bin/env python3
"""
main.py - OWASP Top 10 Automated Scanning Framework runner
Usage:
  python3 main.py --target testphp.vulnweb.com --report html
"""

import argparse
import yaml
import json
import os
import sys
import webbrowser
from colorama import init, Fore
import requests

# initialize colorama
init(autoreset=True)

# Import scanners with safe fallbacks
from scanners.dast import zap_scan
try:
    from scanners.dast import nuclei_scan
except Exception:
    nuclei_scan = None
try:
    from scanners.dast import nmap_scan
except Exception:
    nmap_scan = None

from scanners.sast import bandit_scan
from scanners.dependency import dependency_check
from session_analysis import session_checker
from reports.generate_report import generate_report
from dashboard import dashboard_advanced as dashboard

# Load default config
CONFIG_PATH = "config/settings.yaml"
if not os.path.exists(CONFIG_PATH):
    print(Fore.YELLOW + f"[WARN] Config file {CONFIG_PATH} missing; creating default minimal config.")
    default_conf = {
        "target_url": "http://testphp.vulnweb.com",
        "scan_types": ["sast", "dast", "dependency", "nuclei", "nmap"],
        "report": {"format": ["json", "html"]},
        "session": {"check_jwt": True}
    }
    with open(CONFIG_PATH, "w") as fh:
        yaml.safe_dump(default_conf, fh)

with open(CONFIG_PATH) as f:
    default_config = yaml.safe_load(f)

def detect_reachable_scheme(host, timeout=4):
    """
    Try http then https for the given host (host may be 'example.com' or 'http://example.com').
    Returns a URL prefix like 'http://' or 'https://'
    """
    # extract hostname if URL passed
    h = host
    if host.startswith("http://") or host.startswith("https://"):
        h = host.split("://",1)[1].split("/",1)[0]
    # try http first
    for scheme in ("http://", "https://"):
        url = scheme + h
        try:
            r = requests.head(url, timeout=timeout, allow_redirects=True)
            # accept 2xx and 3xx and 4xx (server reachable)
            if r.status_code and int(r.status_code) < 600:
                return scheme
        except Exception:
            continue
    # fallback to http
    return "http://"

def normalize_results(results):
    """Normalize scanner outputs to {"summary":..., "details":[...]} structure."""
    normalized = {}
    for k, v in results.items():
        if isinstance(v, dict):
            # if keys already match expected
            if "summary" in v and "details" in v:
                normalized[k] = v
            else:
                # try common keys
                if "alerts" in v:
                    normalized[k] = {"summary": v.get("summary", ""), "details": v.get("alerts", [])}
                elif "vulnerabilities" in v:
                    normalized[k] = {"summary": v.get("summary", ""), "details": v.get("vulnerabilities", [])}
                elif "details" in v:
                    normalized[k] = {"summary": v.get("summary", ""), "details": v.get("details", [])}
                else:
                    # treat dict as a single item
                    normalized[k] = {"summary": v.get("summary", str(v)), "details": [v]}
        elif isinstance(v, list):
            normalized[k] = {"summary": f"{len(v)} items", "details": v}
        else:
            normalized[k] = {"summary": str(v), "details": []}
    return normalized

def run_scans(target, report_format):
    results = {}

    print(Fore.CYAN + f"[*] Starting OWASP scans on target: {target}")

    # Detect reachable scheme for DAST-type scanners (spider/zap/nuclei/nmap)
    scheme = detect_reachable_scheme(target)
    # Build final target_url (preserve path if provided)
    if target.startswith("http://") or target.startswith("https://"):
        final_target = target
    else:
        # keep only host if given
        final_target = scheme + target.split("://")[-1].split("/",1)[0]

    # SAST
    if "sast" in default_config.get("scan_types", []):
        print(Fore.YELLOW + "[SAST] Running Bandit scan...")
        try:
            results["sast"] = bandit_scan.run(final_target)
        except Exception as e:
            results["sast"] = {"summary": f"Bandit scan failed: {e}"}
        print(Fore.GREEN + "[SAST ✅] Done")

    # DAST - ZAP
    if "dast" in default_config.get("scan_types", []):
        print(Fore.YELLOW + "[DAST] Running ZAP scan...")
        try:
            results["dast"] = zap_scan.run(final_target)
        except Exception as e:
            results["dast"] = {"summary": f"ZAP scan failed: {e}", "alerts": []}
        print(Fore.GREEN + "[DAST ✅] Done")

        # Nuclei (if available)
        if nuclei_scan:
            print(Fore.YELLOW + "[DAST] Running Nuclei scan...")
            try:
                # pass templates if configured
                templates = default_config.get("nuclei", {}).get("templates", None)
                results["nuclei"] = nuclei_scan.run(final_target, output_dir="reports", templates=templates)
            except Exception as e:
                results["nuclei"] = {"vulnerabilities": [], "summary": f"Nuclei scan failed: {e}"}
            print(Fore.GREEN + "[Nuclei ✅] Done")
        else:
            results["nuclei"] = {"vulnerabilities": [], "summary": "Nuclei module not installed."}

        # Nmap (if available)
        if nmap_scan:
            print(Fore.YELLOW + "[DAST] Running Nmap (fast) scan...")
            try:
                results["nmap"] = nmap_scan.run(final_target, output_dir="reports")
            except Exception as e:
                results["nmap"] = {"vulnerabilities": [], "summary": f"Nmap scan failed: {e}"}
            print(Fore.GREEN + "[Nmap ✅] Done")
        else:
            results["nmap"] = {"vulnerabilities": [], "summary": "Nmap module not installed."}

    # Dependency scanner
    if "dependency" in default_config.get("scan_types", []):
        print(Fore.YELLOW + "[Dependency] Checking dependencies...")
        try:
            results["dependency"] = dependency_check.run(final_target)
        except Exception as e:
            results["dependency"] = {"summary": f"Dependency scan failed: {e}", "details": []}
        print(Fore.GREEN + "[Dependency ✅] Done")

    # Session
    if default_config.get("session", {}).get("check_jwt"):
        print(Fore.YELLOW + "[Session] Checking session management...")
        try:
            results["session"] = session_checker.run(final_target)
        except Exception as e:
            results["session"] = {"summary": f"Session check failed: {e}", "details": []}
        print(Fore.GREEN + "[Session ✅] Done")

    # Normalize results to feed report generator
    normalized = normalize_results(results)

    # Save debug dump for troubleshooting
    os.makedirs("reports", exist_ok=True)
    with open("reports/debug_scan_output.json", "w") as fh:
        json.dump(normalized, fh, indent=2)
    print(Fore.CYAN + "[DEBUG] wrote reports/debug_scan_output.json")

    # Generate report
    print(Fore.CYAN + "[Report] Generating report...")
    if isinstance(report_format, str):
        formats = [report_format.lower()]
    else:
        formats = [f.lower() for f in report_format]
    # call generate_report with normalized scanners dict
    try:
        generate_report(normalized, formats)
    except Exception as e:
        print(Fore.RED + f"[Report ❌] Report generation failed: {e}")
    else:
        print(Fore.GREEN + f"[Report ✅] {', '.join([f.upper() for f in formats])} report generated")

    # Open HTML report if asked
    if "html" in formats:
        html_path = os.path.abspath("reports/latest_report.html")
        try:
            webbrowser.open(f"file://{html_path}")
        except Exception:
            pass

    # Update dashboard - best-effort
    try:
        dashboard.add_scan(normalized)
        dashboard.generate_dashboard()
        print(Fore.GREEN + "[Dashboard ✅] Advanced dashboard generated")
    except Exception as e:
        print(Fore.RED + f"[Dashboard ❌] Could not update dashboard: {e}")

    return normalized


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OWASP Top 10 Automated Scanning Framework")
    parser.add_argument("--target", type=str, help="Target host or URL to scan (e.g. testphp.vulnweb.com or http://example.com)")
    parser.add_argument("--report", type=str, choices=["html", "json"], help="Report format", default=None)
    args = parser.parse_args()

    target_arg = args.target if args.target else default_config.get("target_url")
    report_arg = args.report if args.report else default_config.get("report", {}).get("format", ["json"])
    if isinstance(report_arg, list):
        report_format = report_arg
    else:
        report_format = report_arg.lower()

    run_scans(target_arg, report_format)
