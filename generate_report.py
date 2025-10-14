import json
import os
from datetime import datetime
from jinja2 import Template

def generate_report(results, report_format="html", template_file="dashboard_advanced.html"):
    """
    Generate JSON or interactive HTML reports from scan results.
    
    :param results: dict containing scan results
    :param report_format: "json", "html", or ["json","html"]
    :param template_file: HTML template file for dashboard
    """
    if isinstance(report_format, str):
        formats = [report_format]
    else:
        formats = report_format

    # Ensure reports folder exists
    os.makedirs("reports", exist_ok=True)

    # JSON report
    if "json" in [f.lower() for f in formats]:
        json_path = os.path.join("reports", "latest_report.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
        print(f"[INFO] JSON report generated: {json_path}")

    # HTML report
    if "html" in [f.lower() for f in formats]:
        html_path = os.path.join("reports", "latest_report.html")
        html_content = _build_interactive_html(results, template_file)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[INFO] HTML dashboard generated: {html_path}")


def _build_interactive_html(scans, template_file="dashboard_advanced.html"):
    """
    Generate HTML dashboard from a template and inject dynamic data.
    
    :param scans: dictionary of scan results
    :param template_file: path to HTML template
    :return: rendered HTML string
    """
    # Load HTML template
    if not os.path.exists(template_file):
        raise FileNotFoundError(f"Template file '{template_file}' not found.")
    
    with open(template_file, "r", encoding="utf-8") as f:
        template_content = f.read()

    # Convert scans dict to JSON string (for JS consumption)
    scans_json = json.dumps(scans)

    # Render template using Jinja2
    html = Template(template_content).render(
        scans=scans_json,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    return html


# ----------------------------
# Example usage
# ----------------------------
if __name__ == "__main__":
    demo_results = {
        "Nuclei": {"details":[{"title":"Critical Vulnerability","details":"Exploit found","severity":"Critical","report_file":None}]},
        "ZAP": {"details":[{"title":"High Risk XSS","details":"Reflected XSS found","severity":"High","report_file":"reports/zap1.html"}]},
        "Nmap": {"details":[]}
    }

    # Generate both JSON and HTML reports using template
    generate_report(demo_results, report_format=["json", "html"], template_file="dashboard_advanced.html")
