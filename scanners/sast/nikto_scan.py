# scanners/sast/nikto_scan.py
import os
import datetime
import subprocess

def run(target, output_dir="reports"):
    """
    Run Nikto scan (single run, HTML output) and return dashboard-friendly results.
    Outputs: reports/nikto_<timestamp>.html
    Returns: {"summary": str, "details": [{"title":..., "severity":...}, ...]}
    """
    try:
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        html_output = os.path.join(output_dir, f"nikto_{timestamp}.html")

        print(f"[SAST → Nikto] Running Nikto HTML scan: {html_output}")
        cmd = ["nikto", "-h", target, "-o", html_output, "-Format", "html"]
        # run once (html)
        subprocess.run(cmd, check=False, capture_output=True, text=True)

        # Try to extract a short summary by checking the HTML file lines for common patterns.
        summary_lines = []
        try:
            if os.path.exists(html_output):
                with open(html_output, "r", errors="ignore") as fh:
                    for line in fh:
                        line = line.strip()
                        if line.startswith("+ "):
                            summary_lines.append(line)
                        if len(summary_lines) >= 10:
                            break
        except Exception:
            # ignore parsing errors; we still return the report link
            summary_lines = []

        if not summary_lines:
            summary_lines = [f"Nikto HTML output saved: {html_output}"]

        details = []
        for ln in summary_lines:
            # ln usually looks like "+ /path: something", strip leading "+ "
            text = ln[2:] if ln.startswith("+ ") else ln
            # choose severity heuristically
            lower = text.lower()
            if "not present" in lower or "missing" in lower:
                sev = "info"
            elif "found" in lower or "directory indexing" in lower:
                sev = "low"
            elif "vulnerab" in lower or "error" in lower or "exposed" in lower:
                sev = "medium"
            else:
                sev = "info"
            details.append({"title": text, "severity": sev})

        # Always include the HTML report link as last detail
        details.append({"title": f"Full HTML report: {html_output}", "severity": "info"})

        return {"summary": f"Nikto scan completed for {target}", "details": details}

    except Exception as e:
        return {"summary": f"Nikto scan failed: {e}", "details": [{"title": str(e), "severity": "error"}]}
