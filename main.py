#!/usr/bin/env python3
"""
main.py — Central execution pipeline for the OWASP Framework.

Fixes applied:
1. Dashboard import wrapped in try/except — no longer crashes after scan completes.
2. safe_import() now logs exceptions so scanner bugs aren't silently swallowed.
3. Replaced fragile __code__.co_argcount introspection with inspect.signature().
4. detect_scheme() is now skipped if the target already has a scheme (avoids delay).
5. nuclei and nmap have their own scan_types entries ('nuclei', 'nmap') respected
   independently of 'dast', matching what settings.yaml documents.
6. debug_scan_output.json write is gated behind a --debug flag.
7. dashboard import moved inside try/except with clear error messaging.
"""

import argparse
import inspect
import json
import logging
import os
import sys
import webbrowser
from datetime import datetime

# Optional pretty console output
try:
    from colorama import init as _cinit, Fore, Style
    _cinit(autoreset=True)
except ImportError:
    class _Stub:
        def __getattr__(self, _):
            return ""
    Fore = Style = _Stub()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("owasp-framework")

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "settings.yaml")


# ---------------------------------------------------------------------------
# Safe import — logs failures instead of silently returning None
# ---------------------------------------------------------------------------

def safe_import(module_path: str, attr: str = None):
    """
    Attempt to import a module (or attribute from a module).
    Returns the object on success, None on failure.
    Logs a warning with the actual exception so bugs aren't silently hidden.
    """
    try:
        mod = __import__(module_path, fromlist=[attr] if attr else [])
        return getattr(mod, attr) if attr else mod
    except ImportError:
        # Module simply not installed — expected, low-noise log
        log.debug("Optional module not available: %s", module_path)
        return None
    except Exception as e:
        # Unexpected error (syntax error, name error in scanner code, etc.)
        log.warning("Failed to import %s.%s: %s: %s", module_path, attr or "", type(e).__name__, e)
        return None


# ---------------------------------------------------------------------------
# Scanner imports
# ---------------------------------------------------------------------------

nikto_scan       = safe_import("scanners.sast.nikto_scan",              "run")
bandit_scan      = safe_import("scanners.sast.bandit_scan",             "run")
zap_scan         = safe_import("scanners.dast.zap_scan",                "run")
api_fuzzer       = safe_import("scanners.dast.api_fuzzer",              "run")
nuclei_scan      = safe_import("scanners.dast.nuclei_scan",             "run")
nmap_scan        = safe_import("scanners.dast.nmap_scan",               "run")
dependency_check = safe_import("scanners.dependency.dependency_check",  "run")
session_checker  = safe_import("session_analysis.session_checker",      "run")
generate_report  = safe_import("reports.generate_report",               "generate_report")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def call_scanner(fn, *args, **kwargs):
    """
    Call a scanner function using inspect.signature() to determine which
    arguments it accepts. Falls back gracefully if introspection fails.

    Replaces the fragile __code__.co_argcount pattern which breaks on
    lambdas, functools.partial, class __call__, and built-ins.
    """
    if fn is None:
        return None
    try:
        sig = inspect.signature(fn)
        accepted = set(sig.parameters.keys())
        # Only pass kwargs the function actually declares
        safe_kwargs = {k: v for k, v in kwargs.items() if k in accepted}
        return fn(*args, **safe_kwargs)
    except Exception as e:
        log.warning("Scanner call failed for %s: %s", getattr(fn, "__name__", fn), e)
        return {"summary": f"Scanner error: {e}", "details": []}


def ensure_details(result) -> dict:
    """Normalise any scanner return value to {summary, details}."""
    if result is None:
        return {"summary": "No result returned", "details": []}
    if not isinstance(result, dict):
        return {"summary": str(result), "details": []}

    # Ensure summary
    if not result.get("summary"):
        if "alerts" in result:
            result["summary"] = f"{len(result.get('alerts') or [])} alerts"
        elif "vulnerabilities" in result:
            result["summary"] = f"{len(result.get('vulnerabilities') or [])} vulnerabilities"
        else:
            result["summary"] = "Scan completed"

    # Ensure details list
    if not isinstance(result.get("details"), list):
        raw = result.get("alerts") or result.get("vulnerabilities") or []
        details = []
        for item in raw:
            if isinstance(item, dict):
                title    = item.get("alert") or item.get("name") or item.get("title") or json.dumps(item)[:200]
                severity = item.get("risk")  or item.get("severity") or item.get("level") or "info"
                details.append({"title": title, "severity": str(severity).lower()})
            else:
                details.append({"title": str(item), "severity": "info"})
        result["details"] = details

    return result


def load_config() -> dict:
    """Load settings.yaml, creating a default file if it doesn't exist."""
    import yaml

    default = {
        "target_url": "http://testphp.vulnweb.com",
        "scan_types": ["sast", "dast", "nuclei", "nmap", "dependency"],
        "report":  {"format": ["json", "html"]},
        "session": {"check_jwt": True},
        "nuclei":  {"templates": None},
        "nmap":    {"fast": True},
    }

    if not os.path.exists(CONFIG_PATH):
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w") as fh:
            yaml.safe_dump(default, fh)
        log.info("Created default config at %s", CONFIG_PATH)
        return default

    try:
        with open(CONFIG_PATH) as fh:
            cfg = yaml.safe_load(fh) or {}
        # Back-fill any missing keys from defaults
        for k, v in default.items():
            cfg.setdefault(k, v)
        return cfg
    except Exception as e:
        log.warning("Failed to load config (%s), using defaults.", e)
        return default


def detect_scheme(host: str, timeout: int = 3) -> str:
    """
    Probe the host to determine whether it speaks HTTPS or HTTP.
    Only called when the target has no scheme prefix.
    """
    import requests
    for scheme in ("https://", "http://"):
        try:
            r = requests.head(scheme + host, timeout=timeout, allow_redirects=True)
            if r.status_code < 600:
                return scheme
        except Exception:
            continue
    log.warning("Could not reach %s on either scheme; defaulting to http://", host)
    return "http://"


def write_debug(normalized: dict) -> str:
    """Write debug_scan_output.json to reports/."""
    os.makedirs("reports", exist_ok=True)
    path = os.path.join("reports", "debug_scan_output.json")
    with open(path, "w") as fh:
        json.dump(normalized, fh, indent=2)
    log.debug("Debug output written to %s", path)
    return path


def try_generate_report(normalized: dict, formats: list) -> None:
    """Generate reports, falling back to a plain HTML dump if the module is unavailable."""
    if callable(generate_report):
        try:
            generate_report(normalized, formats)
            log.info("Report generation complete.")
        except Exception as e:
            log.error("generate_report() failed: %s", e)
    else:
        # Fallback: write plain JSON + minimal HTML
        try:
            os.makedirs("reports", exist_ok=True)
            with open("reports/latest_report.json", "w") as fh:
                json.dump(normalized, fh, indent=2)
            with open("reports/latest_report.html", "w") as fh:
                fh.write(
                    "<html><body><h1>OWASP Framework Report</h1><pre>{}</pre></body></html>".format(
                        json.dumps(normalized, indent=2)
                    )
                )
            log.info("Fallback JSON/HTML reports written.")
        except OSError as e:
            log.error("Fallback report write failed: %s", e)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def main():
    cfg = load_config()

    parser = argparse.ArgumentParser(description="OWASP Top 10 Automated Scanning Framework")
    parser.add_argument("--target", type=str, default=cfg.get("target_url"),
                        help="Target host or URL to scan")
    parser.add_argument("--report", type=str, choices=["html", "json"],
                        help="Preferred report format (overrides config)")
    parser.add_argument("--debug", action="store_true",
                        help="Write debug_scan_output.json with raw scanner output")
    args = parser.parse_args()

    # Resolve target URL
    target_arg = args.target or cfg.get("target_url", "")
    if not target_arg:
        log.error("No target specified. Use --target <url> or set target_url in config/settings.yaml")
        sys.exit(1)

    if target_arg.startswith(("http://", "https://")):
        target = target_arg
    else:
        log.info("No scheme detected; probing %s ...", target_arg)
        target = detect_scheme(target_arg) + target_arg

    # Resolve report formats
    if args.report:
        formats = [args.report.lower()]
    else:
        raw = cfg.get("report", {}).get("format", ["json", "html"])
        formats = [x.lower() for x in raw] if isinstance(raw, list) else [str(raw).lower()]

    scan_types = cfg.get("scan_types", [])
    log.info("Starting OWASP scans on: %s", target)
    log.info("Scan types: %s", scan_types)

    results = {}

    # ---- SAST ----
    if "sast" in scan_types:
        log.info("[SAST] Running...")
        if nikto_scan:
            raw = call_scanner(nikto_scan, target, output_dir="reports")
        elif bandit_scan:
            raw = call_scanner(bandit_scan, target)
        else:
            raw = {"summary": "No SAST scanner installed", "details": []}
        results["sast"] = ensure_details(raw)
        log.info("[SAST] Done — %s", results["sast"]["summary"])

    # ---- DAST (ZAP + API Fuzzer) ----
    if "dast" in scan_types:
        if zap_scan:
            log.info("[DAST/ZAP] Running...")
            results["dast"] = ensure_details(call_scanner(zap_scan, target))
            log.info("[DAST/ZAP] Done — %s", results["dast"]["summary"])
        else:
            results["dast"] = {"summary": "ZAP module not installed", "details": []}

        if api_fuzzer:
            log.info("[DAST/API Fuzzer] Running...")
            results["api_fuzz"] = ensure_details(call_scanner(api_fuzzer, target))
            log.info("[DAST/API Fuzzer] Done — %s", results["api_fuzz"]["summary"])
        else:
            results["api_fuzz"] = {"summary": "API fuzzer module not installed", "details": []}

    # ---- Nuclei (independent of 'dast') ----
    if "nuclei" in scan_types:
        if nuclei_scan:
            log.info("[Nuclei] Running...")
            results["nuclei"] = ensure_details(call_scanner(nuclei_scan, target, output_dir="reports"))
            log.info("[Nuclei] Done — %s", results["nuclei"]["summary"])
        else:
            results["nuclei"] = {"summary": "Nuclei module not installed", "details": []}

    # ---- Nmap (independent of 'dast') ----
    if "nmap" in scan_types:
        if nmap_scan:
            log.info("[Nmap] Running...")
            results["nmap"] = ensure_details(call_scanner(nmap_scan, target, output_dir="reports"))
            log.info("[Nmap] Done — %s", results["nmap"]["summary"])
        else:
            results["nmap"] = {"summary": "Nmap module not installed", "details": []}

    # ---- Dependency Check ----
    if "dependency" in scan_types:
        if dependency_check:
            log.info("[Dependency] Running...")
            results["dependency"] = ensure_details(call_scanner(dependency_check, target))
            log.info("[Dependency] Done — %s", results["dependency"]["summary"])
        else:
            results["dependency"] = {"summary": "Dependency module not installed", "details": []}

    # ---- Session Analysis ----
    if cfg.get("session", {}).get("check_jwt"):
        if session_checker:
            log.info("[Session] Running...")
            results["session"] = ensure_details(call_scanner(session_checker, target))
            log.info("[Session] Done — %s", results["session"]["summary"])
        else:
            results["session"] = {"summary": "Session checker not installed", "details": []}

    # ---- Normalise all results ----
    normalized = {k: ensure_details(v) for k, v in results.items()}

    # ---- Debug output (opt-in only) ----
    if args.debug:
        write_debug(normalized)

    # ---- Reports ----
    try_generate_report(normalized, formats)

    # ---- Dashboard ----
    # Wrapped in try/except so a dashboard failure never discards completed scan results
    try:
        import dashboard.dashboard_advanced as dashboard_adv
        dashboard_path = dashboard_adv.generate_dashboard(normalized)
        try:
            webbrowser.open(f"file://{os.path.abspath(dashboard_path)}")
        except Exception as e:
            log.warning("Could not open browser automatically: %s", e)
            log.info("Open manually: file://%s", os.path.abspath(dashboard_path))
    except ImportError:
        log.warning("dashboard.dashboard_advanced not available — skipping dashboard generation.")
    except Exception as e:
        log.error("Dashboard generation failed: %s", e)
        log.info("Scan results are still available in reports/")

    log.info("Scan complete. Results in reports/")
    return normalized


if __name__ == "__main__":
    main()
