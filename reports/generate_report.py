import json

def generate_report(results, formats):
    """
    Generates security reports in JSON/HTML.
    """
    if "json" in formats:
        with open("reports/latest_report.json", "w") as f:
            json.dump(results, f, indent=4)
        print("[Report] JSON report generated at reports/latest_report.json")
    
    if "html" in formats:
        html_content = "<html><body><h1>Security Report (Stub)</h1><pre>{}</pre></body></html>".format(results)
        with open("reports/latest_report.html", "w") as f:
            f.write(html_content)
        print("[Report] HTML report generated at reports/latest_report.html")

