import json
import os

def generate_report(results, formats):
    """
    Generates security reports in JSON/HTML.
    """
    summary = {
        "target": None,
        "results": results
    }

    # attempt to extract target from any scanner summary if present
    # (stubs include target in summary)
    for k,v in results.items():
        s = v.get("summary")
        if s and " on " in s:
            # crude parse: last word after 'on '
            target = s.split(" on ",1)[1]
            summary["target"] = target
            break

    if "json" in formats:
        os.makedirs("reports", exist_ok=True)
        with open("reports/latest_report.json", "w") as f:
            json.dump(summary, f, indent=4)
        print("[Report] JSON report generated at reports/latest_report.json")
    
    if "html" in formats:
        os.makedirs("reports", exist_ok=True)
        html_content = "<html><body><h1>Security Report (Stub)</h1>"
        html_content += f"<p>Target: {summary.get('target')}</p><pre>{json.dumps(results, indent=4)}</pre></body></html>"
        with open("reports/latest_report.html", "w") as f:
            f.write(html_content)
        print("[Report] HTML report generated at reports/latest_report.html")
