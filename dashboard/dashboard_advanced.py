import json
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

SCAN_HISTORY_FILE = "dashboard/data/scans.json"
TEMPLATE_FILE = "dashboard/templates/dashboard_advanced.html"
OUTPUT_FILE = "reports/dashboard_advanced.html"

def load_history():
    if os.path.exists(SCAN_HISTORY_FILE):
        with open(SCAN_HISTORY_FILE) as f:
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
    """Ensure every scanner result has 'summary' and 'details' keys."""
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

def generate_dashboard():
    history = load_history()

    trend_data = []
    for scan in history:
        counts = {"high":0, "medium":0, "low":0}
        normalized_results = normalize_for_dashboard(scan.get("results", {}))
        for scanner_name, data in normalized_results.items():
            for vuln in data.get("details", []):
                severity = vuln.get("severity", "low").lower() if isinstance(vuln, dict) else "low"
                if severity in counts:
                    counts[severity] += 1
        trend_data.append({
            "timestamp": scan.get("timestamp", ""),
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"]
        })

    # Compute OWASP Top 10 coverage
    owasp_categories = {}
    for scan in history:
        normalized_results = normalize_for_dashboard(scan.get("results", {}))
        for category, data in normalized_results.items():
            owasp_categories[category] = owasp_categories.get(category, 0) + len(data.get("details", []))

    # Load template
    env = Environment(loader=FileSystemLoader(os.path.dirname(TEMPLATE_FILE)))
    template = env.get_template(os.path.basename(TEMPLATE_FILE))

    # Render dashboard
    html = template.render(trend_data=trend_data, owasp_categories=owasp_categories, history=history)
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        f.write(html)

    print(f"[Dashboard] Advanced dashboard generated at {OUTPUT_FILE}")
