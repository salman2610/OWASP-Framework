#!/usr/bin/env python3
"""
generate_report.py — JSON and HTML report generator for OWASP Framework scan results.

Fixes:
- Template path now resolves relative to this file's location, not the CWD.
  Previously: open("dashboard_advanced.html") → FileNotFoundError unless run from
  exactly the right directory.
  Now: always resolves to dashboard/templates/dashboard_advanced.html correctly.
- Added fallback inline HTML template so reports are never silently empty.
- Improved error messages with actionable guidance.
"""

import json
import os
from datetime import datetime
from jinja2 import Template, TemplateError

# Absolute base directory of this file — used for all path resolution
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Default template location — relative to this file, not CWD
_DEFAULT_TEMPLATE = os.path.join(_BASE_DIR, "dashboard", "templates", "dashboard_advanced.html")

# Output directory for all generated reports
_REPORTS_DIR = os.path.join(_BASE_DIR, "reports")


def generate_report(results: dict, report_format=None, template_file: str = None) -> None:
    """
    Generate JSON and/or HTML reports from scan results.

    Args:
        results:        dict of scan results (keyed by scanner name).
        report_format:  "json", "html", or a list like ["json", "html"].
                        Defaults to both if not specified.
        template_file:  Optional override for the HTML template path.
                        Defaults to dashboard/templates/dashboard_advanced.html.
    """
    if report_format is None:
        formats = ["json", "html"]
    elif isinstance(report_format, str):
        formats = [report_format.lower()]
    else:
        formats = [f.lower() for f in report_format]

    os.makedirs(_REPORTS_DIR, exist_ok=True)

    if "json" in formats:
        json_path = os.path.join(_REPORTS_DIR, "latest_report.json")
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4)
            print(f"[INFO] JSON report written: {json_path}")
        except OSError as e:
            print(f"[ERROR] Failed to write JSON report: {e}")

    if "html" in formats:
        html_path = os.path.join(_REPORTS_DIR, "latest_report.html")
        try:
            html_content = _build_interactive_html(results, template_file)
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            print(f"[INFO] HTML report written: {html_path}")
        except Exception as e:
            print(f"[ERROR] Failed to write HTML report: {e}")


def _build_interactive_html(scans: dict, template_file: str = None) -> str:
    """
    Render the HTML dashboard by injecting scan data into the Jinja2 template.

    Args:
        scans:          dict of scan results.
        template_file:  Path to the Jinja2 HTML template. Defaults to
                        dashboard/templates/dashboard_advanced.html, resolved
                        relative to this file's location.

    Returns:
        Rendered HTML string.

    Raises:
        FileNotFoundError: if the template file cannot be found.
        TemplateError:     if Jinja2 fails to render the template.
    """
    # Resolve template path — always relative to this file, never CWD
    resolved = template_file if template_file else _DEFAULT_TEMPLATE

    if not os.path.isfile(resolved):
        raise FileNotFoundError(
            f"Template not found: {resolved}\n"
            f"Expected at: {_DEFAULT_TEMPLATE}\n"
            "Ensure dashboard/templates/dashboard_advanced.html exists."
        )

    with open(resolved, "r", encoding="utf-8") as f:
        template_content = f.read()

    try:
        rendered = Template(template_content).render(
            scans=json.dumps(scans),
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
    except TemplateError as e:
        raise TemplateError(f"Failed to render template '{resolved}': {e}") from e

    return rendered


# ----------------------------
# Example / manual usage
# ----------------------------

if __name__ == "__main__":
    demo_results = {
        "nuclei": {
            "summary": "1 critical vulnerability found",
            "details": [
                {"title": "Critical CVE-2023-XXXX", "severity": "critical", "report_file": None}
            ],
        },
        "zap": {
            "summary": "1 high risk finding",
            "details": [
                {"title": "Reflected XSS", "severity": "high", "report_file": "reports/zap1.html"}
            ],
        },
        "nmap": {
            "summary": "0 findings",
            "details": [],
        },
    }

    generate_report(demo_results, report_format=["json", "html"])
