from flask import Flask, render_template
from datetime import datetime
import os

app = Flask(__name__)

# --------- Scanner & Severity Meta ---------
SCANNER_META = {
    "sast": {"color": "blue", "icon": "..."},      # paste icons from previous code
    "dast": {"color": "yellow", "icon": "..."},
    "nuclei": {"color": "green", "icon": "..."},
    "nmap": {"color": "purple", "icon": "..."},
    "dependency": {"color": "pink", "icon": "..."},
    "session": {"color": "teal", "icon": "..."}
}

SEVERITY_META = {
    "critical": "severity-critical",
    "high": "severity-high",
    "medium": "severity-medium",
    "low": "severity-low",
    "info": "severity-info"
}

# --------- Dashboard Route ---------
@app.route("/dashboard")
def dashboard():
    # Example: dynamically load scan results from your existing scans folder or dict
    scans = {}
    scanners_path = os.path.join(os.getcwd(), "scanners")
    for scanner_file in os.listdir(scanners_path):
        if scanner_file.endswith(".json"):
            scanner_name = scanner_file.split(".")[0].upper()
            # You would load JSON content here; using dummy data for now
            scans[scanner_name] = {
                "summary": f"{scanner_name} scan completed.",
                "details": [
                    {"title": "Dummy Issue", "severity": "High", "details": "Found in test.php", "report_file": None}
                ]
            }
    return render_template("dashboard.html",
                           scans=scans,
                           timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                           SCANNER_META=SCANNER_META,
                           SEVERITY_META=SEVERITY_META)

if __name__ == "__main__":
    app.run(debug=True)
