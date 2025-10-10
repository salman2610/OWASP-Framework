import json
import os
from datetime import datetime

def generate_report(results, report_format):
    """
    Generate JSON or interactive HTML reports from scan results.
    """
    if isinstance(report_format, str):
        formats = [report_format]
    else:
        formats = report_format

    # JSON report
    if "json" in [f.lower() for f in formats]:
        with open("reports/latest_report.json", "w") as f:
            json.dump(results, f, indent=4)

    # HTML report
    if "html" in [f.lower() for f in formats]:
        html = _build_interactive_html(results)
        with open("reports/latest_report.html", "w") as f:
            f.write(html)

def _build_interactive_html(results):
    """
    Returns a full interactive HTML string for the report
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>OWASP Framework Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; background: #f4f4f4; }}
h1 {{ text-align: center; }}
.collapsible {{ background-color: #eee; color: #444; cursor: pointer; padding: 10px; width: 100%; border: none; text-align: left; outline: none; font-size: 16px; }}
.active, .collapsible:hover {{ background-color: #ccc; }}
.content {{ padding: 0 15px; display: none; overflow: hidden; background-color: #f9f9f9; }}
.badge {{ padding: 3px 6px; border-radius: 4px; color: white; font-weight: bold; }}
.badge-Info {{ background: gray; }}
.badge-Low {{ background: green; }}
.badge-Medium {{ background: orange; }}
.badge-High {{ background: red; }}
table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px; }}
th {{ background-color: #333; color: white; }}
</style>
</head>
<body>
<h1>OWASP Framework Report</h1>
<p>Generated: {now}</p>
<input type="text" id="search" placeholder="Search vulnerabilities..." style="width:100%; padding:8px; margin-bottom:10px;">

"""

    # Function to generate table for a tool
    def _tool_section(name, items):
        sec = f'<button class="collapsible">{name} - {len(items) if isinstance(items, list) else 1} items</button><div class="content">'
        sec += "<table><thead><tr><th>Severity</th><th>Title / Description</th><th>Details</th></tr></thead><tbody>"
        if isinstance(items, dict):
            # If dict, wrap in list
            items = [items]
        for it in items:
            sev = it.get("severity", "Info") if isinstance(it, dict) else "Info"
            title = it.get("title", it.get("summary", "")) if isinstance(it, dict) else str(it)
            details = it.get("details", "") if isinstance(it, dict) else ""
            sec += f'<tr><td><span class="badge badge-{sev}">{sev}</span></td><td>{title}</td><td>{details}</td></tr>'
        sec += "</tbody></table></div>"
        return sec

    # Add sections for all scanners
    for tool in ["sast", "dast", "api_fuzz", "dependency", "session", "nuclei", "nmap"]:
        if tool in results:
            html += _tool_section(tool.upper(), results[tool].get("details", results[tool]))

    # JS for collapsible and search
    html += """
<script>
// Collapsible sections
document.querySelectorAll('.collapsible').forEach(btn=>{
    btn.addEventListener('click', ()=>{
        btn.classList.toggle('active');
        const content = btn.nextElementSibling;
        content.style.display = (content.style.display === 'block') ? 'none' : 'block';
    });
});

// Search/filter
document.getElementById('search').addEventListener('input', function(){
    const q = this.value.toLowerCase();
    document.querySelectorAll('table tbody').forEach(tbody=>{
        Array.from(tbody.rows).forEach(row=>{
            const text = row.innerText.toLowerCase();
            row.style.display = text.includes(q) ? '' : 'none';
        });
    });
});
</script>
</body>
</html>
"""
    return html
