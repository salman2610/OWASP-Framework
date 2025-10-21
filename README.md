CyberDefense Hub — OWASP Automation Framework
A modular, automated vulnerability assessment and threat intelligence platform designed for continuous security monitoring, powered by Python and integrated visualization dashboards.

Overview
CyberDefense Hub automates security scanning, reporting, and visualization using multiple security tools and OWASP methodologies.
It consolidates scan data from Nikto, Nmap, Nuclei, and other modules into a rich dashboard visualized through TailwindCSS and Chart.js.

It’s built for:

Cybersecurity professionals

Red Team analysts

SOC operators

Threat hunters who need unified visibility of scan results and reports

✨ Features
Category	Description
Automated Scanning	Integrates Nikto, Nmap, Nuclei, and custom fuzzers to perform web and network scans.
Dynamic Dashboard	Real-time statistics, severity trends, and scan visualizations using Chart.js.
Modular Architecture	Add or remove scanning tools easily — plug-and-play design.
Report Generation	Generates PDF/HTML reports for audit, compliance, and export.
Threat Intelligence	Highlights top vulnerabilities, threat trends, and OWASP Top 10 mappings.
Interactive UI	Frontend built with TailwindCSS and FontAwesome icons for sleek usability.
🧠 Project Structure
bash
OWASP-Framework/
│
├── main.py                    # Main execution pipeline
├── dashboard/
│   ├── dashboard_advanced.py   # Jinja2 render logic
│   ├── templates/
│   │   └── dashboard_advanced.html  # Tailwind-based dashboard
│   └── data/
│       └── scans.json          # Stores previous scan records
│
├── scanners/
│   ├── nmap_scan.py
│   ├── nuclei_scan.py
│   ├── nikto_scan.py
│   └── api_fuzzer.py
│
├── reports/
│   ├── generate_report.py
│   ├── serve_reports.py
│   └── dashboard_rendered.html # Generated reporting dashboard
│
├── config/
│   └── settings.yaml           # Tool configuration (scopes, templates)
│
├── requirements.txt
└── README.md
⚙️ Installation & Setup
1. Clone Repository
bash
git clone https://github.com/<your-username>/OWASP-Framework.git
cd OWASP-Framework
2. Create Virtual Environment
bash
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
3. Install Dependencies
bash
pip install -r requirements.txt
4. Configure Targets
Edit config/settings.yaml to specify target URLs, scan types, and tools:

text
target_url: "http://testphp.vulnweb.com"
scan_types: ["sast", "dast", "dependency", "nuclei", "nmap"]
5. Run the Framework
bash
python3 main.py --target http://testphp.vulnweb.com --report html
📊 Dashboard Features
Vulnerability Overview
Displays counts for critical, high, medium, and low vulnerabilities.

Real data visualized via Chart.js pie and trend charts.

Quick Actions
Buttons that let you:

Start Scan — Refresh and trigger a new scan

Generate Report — Open the latest HTML report

Alert Settings — Customize notification thresholds (future)

Access Control — Manage user privileges (static placeholder for demo)

Live Charts
Charts are powered by backend dashboard_advanced.py:

Doughnut chart: Vulnerability severity distribution

Line chart: Threat trend data across scans

📁 Generated Files
File	Description
reports/latest_report.html	Auto-rendered vulnerability report
reports/dashboard_rendered.html	Interactive cyber dashboard
dashboard/data/scans.json	Scan history retained for trend analysis
🧩 Customization Guide
To modify the dashboard or scan integrations:

Edit HTML elements in:
dashboard/templates/dashboard_advanced.html

Update Python data logic in:
dashboard/dashboard_advanced.py

Update/add scanning modules under /scanners/.

🛡️ Security Tools Used
Tool	Purpose
Nikto	Web vulnerability scanner
Nmap	Network mapper & port analyzer
Nuclei	Template-based vulnerability scanner
API Fuzzer	REST API fuzzing and response analyzer
Dependency Checker	Software package vulnerability identification
🖥️ Example Usage
bash
# Run full OWASP pipeline with HTML dashboard generation
python3 main.py --target https://example.com --report html

# Open generated dashboard
open reports/dashboard_rendered.html
📘 Future Enhancements
Integration with Elasticsearch-dashboard (Kibana) for analytics

Automated Jira report filing for found vulnerabilities

Live REST API endpoint monitoring via async workers

Enhanced alert webhooks for Slack/Discord integrations

🧑‍💻 Contributors
Salmanul Faris — Architect & Developer

Cyber AI Labs R&D — Backend R&D and report automation

📝 License
This project is released under the MIT License — feel free to use, modify, and distribute with attribution.

Would you like me to include a Badges and Screenshots section (for GitHub presentation) as an additional part of the README?
It would show visual dashboard samples and shields.io badges (Python version, License, Framework, etc.).

```bash
source venv/bin/activate
'''
 /snap/bin/zaproxy -daemon -port 8090 -host 127.0.0.1 -config api.disablekey=true
