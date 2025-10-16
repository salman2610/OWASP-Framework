import json
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

# Paths used
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCAN_HISTORY_FILE = os.path.join(BASE_DIR, "data", "scans.json")
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
TEMPLATE_FILE = "dashboard_advanced.html"
OUTPUT_FILE = os.path.join(BASE_DIR, "..", "reports", "dashboard_rendered.html")

def load_history():
    if os.path.exists(SCAN_HISTORY_FILE):
        with open(SCAN_HISTORY_FILE, "r") as f:
            return json.load(f)
    return []

def save_history(history):
    os.makedirs(os.path.dirname(SCAN_HISTORY_FILE), exist_ok=True)
    with open(SCAN_HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)

def add_scan(results):
    history = load_history()
    history.append({
        "timestamp": datetime.utcnow().isoformat(),
        "results": results
    })
    save_history(history)

def normalize_for_dashboard(scan):
    normalized = {}
    for k, v in scan.items():
        if not isinstance(v, dict):
            normalized[k] = {"summary": str(v), "details": []}
            continue
        summary = v.get("summary", str(v))
        details = v.get("details", [])
        if details is None:
            details = []
        normalized[k] = {"summary": summary, "details": details}
    return normalized

def generate_dashboard(scan_results=None):
    """
    Generate dashboard HTML.

    If scan_results given, add to history first.
    """
    history = load_history()
    if scan_results:
        add_scan(scan_results)
        history = load_history()  # reload after add

    # Gather trend data for charts
    trend_data = []
    for scan in history:
        counts = {"high": 0, "medium": 0, "low": 0}
        normalized_results = normalize_for_dashboard(scan.get("results", {}))
        for _, data in normalized_results.items():
            for vuln in data.get("details", []):
                sev = vuln.get("severity", "low").lower() if isinstance(vuln, dict) else "low"
                if sev in counts:
                    counts[sev] += 1
        trend_data.append({
            "timestamp": scan.get("timestamp", ""),
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"]
        })

    # Compute categories coverage (e.g., OWASP)
    owasp_categories = {}
    for scan in history:
        normalized_results = normalize_for_dashboard(scan.get("results", {}))
        for category, data in normalized_results.items():
            owasp_categories[category] = owasp_categories.get(category, 0) + len(data.get("details", []))

    # Latest scan results for display
    latest_scan = normalize_for_dashboard(history[-1]["results"]) if history else {}

    # Setup Jinja2 environment and render
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template(TEMPLATE_FILE)
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    rendered_html = template.render(
        scans=latest_scan,
        history=history,
        trend_data=trend_data,
        owasp_categories=owasp_categories,
        timestamp=timestamp
    )

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        f.write(rendered_html)

    print(f"[Dashboard] Advanced dashboard generated at {OUTPUT_FILE}")
    return OUTPUT_FILE
