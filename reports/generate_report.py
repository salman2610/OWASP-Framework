import json
from datetime import datetime

def generate_report(results, report_format):
    """
    Generate JSON or HTML reports from scan results.
    """
    if isinstance(report_format, str):
        formats = [report_format]
    else:
        formats = report_format

    for fmt in formats:
        if fmt.lower() == "json":
            with open("reports/latest_report.json", "w") as f:
                json.dump(results, f, indent=4)
        elif fmt.lower() == "html":
            # generate simple HTML report
            with open("reports/latest_report.html", "w") as f:
                f.write("<html><body><h1>Scan Report</h1></body></html>")
