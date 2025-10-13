#!/usr/bin/env python3
"""
Full, robust main runner for the OWASP Framework.

Features:
- Safe imports of scanners that may or may not exist.
- Ensures each scanner result has 'summary' and 'details' keys.
- Writes debug_scan_output.json to reports/.
- Calls generate_report(...) if available.
- Updates dashboard (dashboard.dashboard_advanced) if available (best-effort).
- CLI: --target, --report
"""

import argparse
import json
import os
import sys
import webbrowser
from datetime import datetime

# optional pretty console output
try:
    from colorama import init as _cinit, Fore, Style
    _cinit(autoreset=True)
except Exception:
    class _F: pass
    Fore = Style = _F()
    Fore.CYAN = Fore.YELLOW = Fore.GREEN = Fore.RED = ""
    Style.RESET_ALL = ""

# safe imports for scanners: try to import each; if missing set None
def safe_import(module_path, attr=None):
    try:
        mod = __import__(module_path, fromlist=[attr] if attr else [])
        return getattr(mod, attr) if attr else mod
    except Exception:
        return None

# Try common scanner modules in your repo layout (scanners/...)
nikto_scan = safe_import("scanners.sast.nikto_scan", "run") or safe_import("scanners.sast.nikto_scan")
bandit_scan = safe_import("scanners.sast.bandit_scan", "run") or safe_import("scanners.sast.bandit_scan")
zap_scan = safe_import("scanners.dast.zap_scan", "run") or safe_import("scanners.dast.zap_scan")
api_fuzzer = safe_import("scanners.dast.api_fuzzer", "run") or safe_import("scanners.dast.api_fuzzer")
nuclei_scan = safe_import("scanners.dast.nuclei_scan", "run") or safe_import("scanners.dast.nuclei_scan")
nmap_scan = safe_import("scanners.dast.nmap_scan", "run") or safe_import("scanners.dast.nmap_scan")
dependency_check = safe_import("scanners.dependency.dependency_check", "run") or safe_import("scanners.dependency.dependency_check")
session_checker = safe_import("session_analysis.session_checker", "run") or safe_import("session_analysis.session_checker")

# report generator and dashboard (best-effort)
generate_report = safe_import("reports.generate_report", "generate_report")
dashboard_mod = safe_import("dashboard.dashboard_advanced") or safe_import("dashboard.dashboard_advanced", None)

# config path
CONFIG_PATH = "config/settings.yaml"

# helper: ensure any scanner result has expected structure
def ensure_details(result):
    """
    Normalize a scanner result to a dict with keys:
    - summary (string)
    - details (list of dicts)
    """
    if result is None:
        return {"summary": "No result", "details": []}
    if not isinstance(result, dict):
        return {"summary": str(result), "details": []}
    # ensure summary
    if "summary" not in result or result["summary"] is None:
        # if there is an alerts/ vulnerabilities / details key, try to generate summary
        if "alerts" in result:
            result["summary"] = f"{len(result.get('alerts') or [])} alerts"
        elif "vulnerabilities" in result:
            result["summary"] = f"{len(result.get('vulnerabilities') or [])} vulnerabilities"
        else:
            result["summary"] = str(result)
    # ensure details
    if "details" not in result or result["details"] is None:
        # map common fields to details
        if "alerts" in result and isinstance(result["alerts"], list):
            # convert alerts to details list
            result["details"] = []
            for a in result["alerts"]:
                if isinstance(a, dict):
                    title = a.get("alert") or a.get("name") or a.get("title") or json.dumps(a)[:200]
                    severity = a.get("risk") or a.get("severity") or a.get("level") or "info"
                    result["details"].append({"title": title, "severity": str(severity)})
                else:
                    result["details"].append({"title": str(a), "severity": "info"})
        elif "vulnerabilities" in result and isinstance(result["vulnerabilities"], list):
            result["details"] = []
            for v in result["vulnerabilities"]:
                if isinstance(v, dict):
                    title = v.get("title") or v.get("message") or json.dumps(v)[:200]
                    severity = v.get("severity", "info")
                    result["details"].append({"title": title, "severity": str(severity)})
                else:
                    result["details"].append({"title": str(v), "severity": "info"})
        else:
            # fallback empty details
            result["details"] = []
    # ensure details is list
    if not isinstance(result["details"], list):
        result["details"] = [result["details"]]
    return result

def load_config():
    import yaml
    default = {
        "target_url": "http://testphp.vulnweb.com",
        "scan_types": ["sast", "dast", "dependency", "nuclei", "nmap"],
        "report": {"format": ["json", "html"]},
        "session": {"check_jwt": True},
        "nuclei": {"templates": None},
        "nmap": {"fast": True}
    }
    if not os.path.exists(CONFIG_PATH):
        try:
            os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        except Exception:
            pass
        with open(CONFIG_PATH, "w") as fh:
            yaml.safe_dump(default, fh)
        return default
    try:
        with open(CONFIG_PATH) as fh:
            cfg = yaml.safe_load(fh) or default
            # merge defaults for missing keys
            for k, v in default.items():
                if k not in cfg:
                    cfg[k] = v
            return cfg
    except Exception:
        return default

def detect_scheme(host, timeout=3):
    # simple check to prefer http or https; keep small timeout
    import requests
    h = host
    if host.startswith("http://") or host.startswith("https://"):
        return ""  # user already provided scheme; main will use target directly
    for scheme in ("https://", "http://"):
        try:
            r = requests.head(scheme + host, timeout=timeout, allow_redirects=True)
            if r.status_code and int(r.status_code) < 600:
                return scheme
        except Exception:
            continue
    return "http://"

def write_debug(normalized):
    os.makedirs("reports", exist_ok=True)
    path = os.path.join("reports", "debug_scan_output.json")
    with open(path, "w") as fh:
        json.dump(normalized, fh, indent=2)
    print(Fore.CYAN + f"[DEBUG] wrote {path}")
    return path

def try_generate_report(normalized, formats):
    # call generate_report if available
    if callable(generate_report):
        try:
            generate_report(normalized, formats)
            print(Fore.GREEN + "[Report ✅] Report generation complete")
        except Exception as e:
            print(Fore.RED + f"[Report ❌] generate_report failed: {e}")
    else:
        # fallback: simple JSON + HTML summary
        try:
            json_path = os.path.join("reports", "latest_report.json")
            with open(json_path, "w") as fh:
                json.dump(normalized, fh, indent=2)
            # simple HTML summary
            html_path = os.path.join("reports", "latest_report.html")
            with open(html_path, "w") as fh:
                fh.write("<html><body><h1>OWASP Framework Report</h1><pre>{}</pre></body></html>".format(
                    json.dumps(normalized, indent=2)))
            print(Fore.GREEN + "[Report ✅] Fallback JSON/HTML reports written")
        except Exception as e:
            print(Fore.RED + f"[Report ❌] Fallback report write failed: {e}")

def try_update_dashboard(normalized):
    if dashboard_mod:
        try:
            # some dashboard implementations expect a raw results dict; others expect a list of runs
            # we will call add_scan if present, passing the normalized results
            if hasattr(dashboard_mod, "add_scan"):
                dashboard_mod.add_scan(normalized)
            if hasattr(dashboard_mod, "generate_dashboard"):
                dashboard_mod.generate_dashboard()
            print(Fore.GREEN + "[Dashboard ✅] Advanced dashboard generated")
        except Exception as e:
            print(Fore.RED + f"[Dashboard ❌] Could not update dashboard: {e}")
    else:
        print(Fore.YELLOW + "[Dashboard] dashboard module not present; skipping dashboard update")

def main():
    cfg = load_config()

    parser = argparse.ArgumentParser(description="OWASP Top 10 Automated Scanning Framework")
    parser.add_argument("--target", type=str, help="Target host or URL to scan", default=cfg.get("target_url"))
    parser.add_argument("--report", type=str, choices=["html", "json"], help="Preferred report format", default=None)
    args = parser.parse_args()

    target_arg = args.target
    # if user didn't include scheme, detect
    if not target_arg.startswith(("http://", "https://")):
        scheme = detect_scheme(target_arg)
        target = scheme + target_arg
    else:
        target = target_arg

    formats = []
    if args.report:
        formats = [args.report.lower()]
    else:
        r = cfg.get("report", {}).get("format", ["json"])
        if isinstance(r, list):
            formats = [x.lower() for x in r]
        else:
            formats = [str(r).lower()]

    print(Fore.CYAN + f"[*] Starting OWASP scans on target: {target}")

    results = {}

    # SAST: prefer nikto if exists, otherwise bandit if present
    if "sast" in cfg.get("scan_types", []):
        print(Fore.YELLOW + "[SAST] Running SAST scanner...")
        if callable(nikto_scan):
            try:
                raw = nikto_scan(target, output_dir="reports") if nikto_scan.__code__.co_argcount > 1 else nikto_scan(target)
            except TypeError:
                # if imported module object rather than function
                try:
                    raw = nikto_scan.run(target, output_dir="reports")
                except Exception as e:
                    raw = {"summary": f"nikto_scan.run failed: {e}"}
        elif callable(bandit_scan):
            try:
                raw = bandit_scan(target) if bandit_scan.__code__.co_argcount == 1 else bandit_scan.run(target)
            except Exception:
                # fallback call patterns
                try:
                    raw = bandit_scan.run(target)
                except Exception as e:
                    raw = {"summary": f"bandit_scan.run failed: {e}"}
        else:
            raw = {"summary": "No SAST scanner installed", "details": []}
        results["sast"] = ensure_details(raw)
        print(Fore.GREEN + "[SAST ✅] Done")

    # DAST: ZAP + API fuzzing
    if "dast" in cfg.get("scan_types", []):
        # ZAP
        if callable(zap_scan):
            print(Fore.YELLOW + "[DAST] Running ZAP scan...")
            try:
                raw = zap_scan(target) if zap_scan.__code__.co_argcount == 1 else zap_scan.run(target)
            except Exception:
                try:
                    raw = zap_scan.run(target)
                except Exception as e:
                    raw = {"summary": f"ZAP scan failed: {e}"}
            results["dast"] = ensure_details(raw)
            print(Fore.GREEN + "[DAST ✅] Done")
        else:
            results["dast"] = {"summary": "ZAP module not installed", "details": []}

        # API fuzzer
        if callable(api_fuzzer):
            try:
                raw = api_fuzzer(target) if api_fuzzer.__code__.co_argcount == 1 else api_fuzzer.run(target)
            except Exception:
                try:
                    raw = api_fuzzer.run(target)
                except Exception as e:
                    raw = {"summary": f"API fuzzer failed: {e}"}
            results["api_fuzz"] = ensure_details(raw)
        else:
            results["api_fuzz"] = {"summary": "API fuzzer module not installed", "details": []}

        # Nuclei
        if callable(nuclei_scan):
            try:
                raw = nuclei_scan(target, output_dir="reports") if nuclei_scan.__code__.co_argcount > 1 else nuclei_scan(target)
            except Exception:
                try:
                    raw = nuclei_scan.run(target, output_dir="reports")
                except Exception as e:
                    raw = {"summary": f"Nuclei scan failed: {e}", "details": []}
            results["nuclei"] = ensure_details(raw)
        else:
            results["nuclei"] = {"summary": "Nuclei module not installed", "details": []}

        # Nmap
        if callable(nmap_scan):
            try:
                raw = nmap_scan(target, output_dir="reports") if nmap_scan.__code__.co_argcount > 1 else nmap_scan(target)
            except Exception:
                try:
                    raw = nmap_scan.run(target, output_dir="reports")
                except Exception as e:
                    raw = {"summary": f"Nmap scan failed: {e}", "details": []}
            results["nmap"] = ensure_details(raw)
        else:
            results["nmap"] = {"summary": "Nmap module not installed", "details": []}

    # Dependency checks
    if "dependency" in cfg.get("scan_types", []):
        if callable(dependency_check):
            try:
                raw = dependency_check(target) if dependency_check.__code__.co_argcount == 1 else dependency_check.run(target)
            except Exception:
                try:
                    raw = dependency_check.run(target)
                except Exception as e:
                    raw = {"summary": f"Dependency check failed: {e}", "details": []}
            results["dependency"] = ensure_details(raw)
        else:
            results["dependency"] = {"summary": "Dependency module not installed", "details": []}

    # Session checks
    if cfg.get("session", {}).get("check_jwt"):
        if callable(session_checker):
            try:
                raw = session_checker(target) if session_checker.__code__.co_argcount == 1 else session_checker.run(target)
            except Exception:
                try:
                    raw = session_checker.run(target)
                except Exception as e:
                    raw = {"summary": f"Session check failed: {e}", "details": []}
            results["session"] = ensure_details(raw)
        else:
            results["session"] = {"summary": "Session checker not installed", "details": []}

    # Final normalization: ensure all top-level scanner results have 'summary' and 'details'
    normalized = {}
    for k, v in results.items():
        normalized[k] = ensure_details(v)

    # Save debug JSON
    write_debug(normalized)

    # Generate report(s)
    try_generate_report(normalized, formats)

    # Attempt to open HTML if requested and exists
    if "html" in formats:
        possible = os.path.abspath(os.path.join("reports", "latest_report.html"))
        if os.path.exists(possible):
            try:
                webbrowser.open(f"file://{possible}")
            except Exception:
                pass

    # Update dashboard (best-effort)
    try_update_dashboard(normalized)

    print(Fore.CYAN + "[*] Scan run complete.")
    return normalized

if __name__ == "__main__":
    main()
