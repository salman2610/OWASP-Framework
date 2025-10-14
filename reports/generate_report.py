import json
import os
from datetime import datetime

def generate_report(results, report_format="html"):
    """
    Generate JSON or interactive HTML reports from scan results.
    :param results: dict containing scan results
    :param report_format: "json", "html", or ["json","html"]
    """
    if isinstance(report_format, str):
        formats = [report_format]
    else:
        formats = report_format

    # Ensure reports folder exists
    os.makedirs("reports", exist_ok=True)

    # JSON report
    if "json" in [f.lower() for f in formats]:
        with open("reports/latest_report.json", "w") as f:
            json.dump(results, f, indent=4)

    # HTML report
    if "html" in [f.lower() for f in formats]:
        html = _build_interactive_html(results)
        with open("reports/latest_report.html", "w", encoding="utf-8") as f:
            f.write(html)

def _build_interactive_html(scans):
    """
    Returns a full interactive TailwindCSS HTML dashboard string
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html_start = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OWASP Security Dashboard</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@3.3.3/dist/tailwind.min.css" rel="stylesheet">
<style>
  body {{ font-family: 'Inter', sans-serif; background:#0a0e27; color:#e5e7eb; }}
  .glass-card {{ background: rgba(15,23,42,0.7); backdrop-filter: blur(20px); border:1px solid rgba(148,163,184,0.1); transition: all 0.4s ease; }}
  .stat-card {{ background: linear-gradient(135deg, rgba(15,23,42,0.9), rgba(30,41,59,0.9)); padding:1rem; border-radius:1rem; }}
  .stat-number {{ font-size:2rem; font-weight:800; background: linear-gradient(135deg,#6366f1,#8b5cf6); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }}
  .severity-badge {{ padding:0.25rem 0.75rem; border-radius:999px; font-size:0.75rem; font-weight:700; text-transform:uppercase; }}
  .severity-critical {{ background: rgba(239,68,68,0.2); color:#fca5a5; }}
  .severity-high {{ background: rgba(249,115,22,0.2); color:#fdba74; }}
  .severity-medium {{ background: rgba(234,179,8,0.2); color:#fde047; }}
  .severity-low {{ background: rgba(34,197,94,0.2); color:#86efac; }}
  .severity-info {{ background: rgba(59,130,246,0.2); color:#93c5fd; }}
  .finding-row {{ background: rgba(30,41,59,0.3); border:1px solid rgba(148,163,184,0.1); padding:1rem; border-radius:1rem; margin-bottom:0.75rem; display:flex; justify-content:space-between; align-items:center; }}
</style>
</head>
<body>
<div class="px-10 py-10">
<h1 class="text-4xl font-bold mb-4">OWASP Security Dashboard</h1>
<p class="text-gray-400 mb-6">Last Scan: {timestamp}</p>
<div class="grid grid-cols-2 md:grid-cols-3 gap-6 mb-12">
"""

    # Stat cards
    stat_cards_html = ""
    for scanner_name, result in scans.items():
        count = len(result.get("details", []))
        stat_cards_html += f"""
<div class="stat-card">
  <div class="text-gray-400 mb-2">{scanner_name}</div>
  <div class="stat-number counter" data-target="{count}">0</div>
  <div class="text-gray-400 text-sm">findings</div>
</div>
"""
    html_middle = "</div>"

    # Detailed results
    detailed_html = ""
    for scanner_name, result in scans.items():
        detailed_html += f"<div class='glass-card mb-8'><h2 class='text-2xl font-bold mb-4'>{scanner_name}</h2>"
        if result.get("details"):
            for item in result["details"]:
                sev = item.get("severity", "Info").lower()
                title = item.get("title", "Security Issue")
                desc = item.get("details", "")
                report_file = item.get("report_file")
                badge_class = f"severity-{sev}" if sev in ["critical","high","medium","low","info"] else "bg-gray-700 text-gray-300"
                detailed_html += f"""
<div class="finding-row">
  <div>
    <div class="font-semibold">{title}</div>
    <div class="text-gray-400 text-sm">{desc}</div>
  </div>
  <div><span class="severity-badge {badge_class}">{item.get("severity","N/A")}</span></div>
  <div>{f"<a href='{report_file}' target='_blank' class='px-4 py-2 rounded bg-indigo-600 text-white'>View</a>" if report_file else "No Report"}</div>
</div>
"""
        else:
            detailed_html += "<div class='text-gray-400 py-6'>No vulnerabilities detected</div>"
        detailed_html += "</div>"

    # JS counters
    js_counters = """
<script>
function animateNumber(element, target, duration = 2000) {
  let current = 0;
  const increment = target / (duration / 16);
  const timer = setInterval(() => {
    current += increment;
    if (current >= target) {
      element.textContent = target;
      clearInterval(timer);
    } else {
      element.textContent = Math.floor(current);
    }
  }, 16);
}
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.counter').forEach(el => {
    const target = parseInt(el.getAttribute('data-target'));
    animateNumber(el, target);
  });
});
</script>
</body>
</html>
"""
    return html_start + stat_cards_html + html_middle + detailed_html + js_counters

# Example usage
if __name__ == "__main__":
    demo_results = {
        "Nuclei": {"details":[{"title":"Critical Vulnerability","details":"Exploit found","severity":"Critical","report_file":None}]},
        "ZAP": {"details":[{"title":"High Risk XSS","details":"Reflected XSS found","severity":"High","report_file":"reports/zap1.html"}]},
        "Nmap": {"details":[]}
    }
    generate_report(demo_results, report_format=["json","html"])
    print("Reports generated in ./reports/")
