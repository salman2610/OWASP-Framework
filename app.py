#!/usr/bin/env python3
"""
app.py — Flask dashboard for OWASP Framework scan results.

Fixes:
- Load scan history from dashboard/data/scans.json (not scanners/*.json — those are .py files)
- debug=True replaced with environment-controlled flag (never on by default)
- Dashboard route loads real persisted scan data
- Bind to 127.0.0.1 by default; warn loudly if exposed to 0.0.0.0
- Added basic secret-key configuration for session safety
"""

import json
import os
import sys
from datetime import datetime

from flask import Flask, render_template, abort

app = Flask(__name__)

# Secret key — override via environment variable in production
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))

# --------- Scanner & Severity Meta ---------

SCANNER_META = {
    "sast":       {"color": "blue",   "icon": "🔍"},
    "dast":       {"color": "yellow", "icon": "🌐"},
    "nuclei":     {"color": "green",  "icon": "⚡"},
    "nmap":       {"color": "purple", "icon": "🗺️"},
    "dependency": {"color": "pink",   "icon": "📦"},
    "session":    {"color": "teal",   "icon": "🔐"},
    "api_fuzz":   {"color": "orange", "icon": "🔧"},
}

SEVERITY_META = {
    "critical": "severity-critical",
    "high":     "severity-high",
    "medium":   "severity-medium",
    "low":      "severity-low",
    "info":     "severity-info",
}

# Path to persisted scan history written by dashboard_advanced.py
SCANS_JSON = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "dashboard", "data", "scans.json"
)

# Path to latest raw scan output written by main.py
DEBUG_JSON = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "reports", "debug_scan_output.json"
)


def load_latest_scans() -> dict:
    """
    Load scan results for the dashboard.
    Prefers debug_scan_output.json (most recent run) over scans.json (history).
    Returns an empty dict with a warning entry if neither file exists.
    """
    for path in (DEBUG_JSON, SCANS_JSON):
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
            except (json.JSONDecodeError, OSError) as e:
                app.logger.warning("Failed to load %s: %s", path, e)

    app.logger.warning("No scan results found. Run main.py first.")
    return {
        "_no_data": {
            "summary": "No scan results found. Run python3 main.py --target <url> first.",
            "details": [],
        }
    }


# --------- Routes ---------

@app.route("/")
def index():
    return dashboard()


@app.route("/dashboard")
def dashboard():
    scans = load_latest_scans()
    return render_template(
        "dashboard_advanced.html",
        scans=json.dumps(scans),
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        SCANNER_META=SCANNER_META,
        SEVERITY_META=SEVERITY_META,
    )


@app.route("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


# --------- Entry point ---------

if __name__ == "__main__":
    # Only enable debug mode when explicitly requested via environment variable
    debug_mode = os.environ.get("FLASK_DEBUG", "0").strip() == "1"

    # Determine bind host — default to localhost only
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))

    if host == "0.0.0.0":
        print(
            "[WARN] Binding to 0.0.0.0 exposes the dashboard to all network interfaces.\n"
            "[WARN] This dashboard has NO authentication. Do not expose it publicly.\n"
            "[WARN] Set FLASK_HOST=127.0.0.1 to restrict to localhost only."
        )

    if debug_mode:
        print("[WARN] Flask debug mode is ON. Disable in any non-development environment.")

    print(f"[*] Dashboard running at http://{host}:{port}/dashboard")
    app.run(host=host, port=port, debug=debug_mode)
