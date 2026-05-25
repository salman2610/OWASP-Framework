<div align="center">

<img src="https://img.shields.io/badge/OWASP-Top%2010-red?style=for-the-badge&logo=owasp&logoColor=white" />
<img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white" />
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
<img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" />
<img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge" />

<br/><br/>

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ███████╗███████╗███████╗███╗   ██╗███████╗███████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║███████╗█████╗  
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║╚════██║██╔══╝  
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝███████╗██║     ███████╗██║ ╚████║███████║███████╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

### 🛡️ **CyberDefense Hub** — Automated OWASP Vulnerability Assessment Framework

*Unified scanning · Rich dashboards · OWASP Top 10 mapped reports — all in one pipeline*

<br/>

[🚀 Quick Start](#-quick-start) · [✨ Features](#-features) · [🗂️ Architecture](#️-architecture) · [📊 Dashboard](#-dashboard) · [🔧 Configuration](#-configuration) · [🗺️ Roadmap](#️-roadmap)

</div>

---

## 🔍 What is CyberDefense Hub?

**CyberDefense Hub** is a modular, Python-based automated security scanning framework built around OWASP methodologies. It orchestrates multiple industry-standard tools — Nikto, Nmap, Nuclei, OWASP ZAP, Bandit, and a custom API Fuzzer — consolidating their findings into a single, rich HTML/JSON report with interactive Chart.js dashboards.

Designed for **cybersecurity professionals, red teamers, SOC operators**, and threat hunters who need unified visibility without stitching together ten different tools manually.

```
Target URL ──► [ SAST + DAST + Network + API + Session Scanners ]
                                    │
                          ┌─────────▼──────────┐
                          │  Normalized Results │
                          └─────────┬──────────┘
                   ┌────────────────┼────────────────┐
                   ▼                ▼                 ▼
             JSON Report      HTML Report      Live Dashboard
```

---

## ✨ Features

| Category | Details |
|---|---|
| 🔍 **Multi-Scanner Engine** | Nikto · Nmap · Nuclei · OWASP ZAP · Bandit · API Fuzzer · Dependency Checker |
| 📊 **Interactive Dashboard** | Real-time Chart.js doughnut + trend charts via Jinja2 rendered templates |
| 🧩 **Modular Architecture** | Plug-and-play scanner modules — add or remove tools with zero core changes |
| 📄 **Dual Report Formats** | Auto-generates both JSON and HTML reports per scan run |
| 🗺️ **OWASP Top 10 Mapping** | Every finding tagged and mapped to its OWASP category |
| 🔐 **Session Analysis** | JWT and session token inspection via dedicated `session_analysis` module |
| 🎨 **Polished UI** | TailwindCSS + FontAwesome frontend, dark-themed, production-grade |
| 🔁 **CI/CD Ready** | GitHub Actions workflow included for automated pipeline integration |
| 🌍 **Multi-language Docs** | README available in EN · ES · CN · JP · KR · PT-BR · ID |

---

## 🗂️ Architecture

```
OWASP-Framework/
│
├── 🚀 main.py                        # Central execution pipeline
├── ⚙️  app.py                         # Flask app entry point
├── 📋 generate_report.py             # Standalone report generator
├── 🌐 serve_reports.py               # Local HTTP server for reports
├── 📦 requirements.txt               # Python dependencies
│
├── 📡 scanners/
│   ├── sast/
│   │   ├── nikto_scan.py             # Web vulnerability scanner
│   │   └── bandit_scan.py            # Python SAST analysis
│   ├── dast/
│   │   ├── zap_scan.py               # OWASP ZAP active scan
│   │   ├── nuclei_scan.py            # Template-based vuln scanner
│   │   ├── nmap_scan.py              # Network & port scanner
│   │   └── api_fuzzer.py             # REST API fuzzer
│   └── dependency/
│       └── dependency_check.py       # Package vulnerability checker
│
├── 📊 dashboard/
│   ├── dashboard_advanced.py         # Jinja2 render pipeline
│   ├── templates/
│   │   └── dashboard_advanced.html   # TailwindCSS + Chart.js UI
│   └── data/
│       └── scans.json                # Persistent scan history
│
├── 📁 reports/                       # Generated outputs (gitignored)
│   ├── latest_report.json
│   ├── latest_report.html
│   ├── debug_scan_output.json
│   └── dashboard_rendered.html
│
├── ⚙️  config/
│   └── settings.yaml                 # Targets, scan types, tool config
│
├── 🔐 session_analysis/
│   └── session_checker.py            # JWT & session token analysis
│
├── 🔧 scripts/                       # Utility & helper scripts
├── 🔧 utils/                         # Shared utility modules
└── 🤖 .github/workflows/             # CI/CD automation
```

---

## 🚀 Quick Start

### Prerequisites

Make sure the following tools are installed and accessible in your `PATH`:

```bash
# Required external tools
nikto       # apt install nikto
nmap        # apt install nmap
nuclei      # go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
zaproxy     # https://www.zaproxy.org/download/

# Python 3.8+
python3 --version
```

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/salman2610/OWASP-Framework.git
cd OWASP-Framework

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Install Python dependencies
pip install -r requirements.txt
```

### Run Your First Scan

```bash
# Full OWASP scan with HTML dashboard output
python3 main.py --target http://testphp.vulnweb.com --report html

# JSON output only
python3 main.py --target https://example.com --report json

# Open the generated dashboard manually
open reports/dashboard_rendered.html          # macOS
xdg-open reports/dashboard_rendered.html      # Linux
```

> ⚠️ **Legal Notice:** Only scan targets you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## 🔧 Configuration

Edit `config/settings.yaml` before running to customize targets and scan behavior:

```yaml
target_url: "http://testphp.vulnweb.com"

scan_types:
  - sast           # Bandit / Nikto static analysis
  - dast           # ZAP, Nuclei, API Fuzzer
  - dependency     # Package vulnerability checks
  - nuclei         # Template-based scanning
  - nmap           # Network port mapping

report:
  format:
    - json
    - html

session:
  check_jwt: true   # Enable JWT token analysis

nuclei:
  templates: null   # null = use all default templates

nmap:
  fast: true        # -F flag for faster port scan
```

---

## 📊 Dashboard

The auto-generated dashboard (`reports/dashboard_rendered.html`) provides:

- **Severity Overview** — Critical / High / Medium / Low vulnerability counts at a glance
- **Doughnut Chart** — Visual severity distribution across all scanners
- **Trend Line Chart** — Vulnerability count changes across scan history (`dashboard/data/scans.json`)
- **Per-Scanner Breakdown** — SAST, DAST, Nmap, Nuclei, Session, Dependency results in expandable panels
- **Quick Actions** — Start Scan · Generate Report · Alert Settings

The dashboard is rendered via `dashboard/dashboard_advanced.py` using **Jinja2** templates and auto-opens in your browser after each scan run.

---

## 🧰 Scanner Modules

| Scanner | Type | What it detects |
|---|---|---|
| **Nikto** | SAST/Web | Web server misconfigurations, outdated software, XSS, injection |
| **Bandit** | SAST/Python | Insecure Python code patterns, hardcoded secrets, dangerous calls |
| **OWASP ZAP** | DAST | Active web vulnerabilities — SQLi, XSS, CSRF, auth flaws |
| **Nuclei** | DAST | CVE-based scanning via community templates |
| **Nmap** | Network | Open ports, service versions, OS fingerprinting |
| **API Fuzzer** | DAST | REST endpoint fuzzing, error leakage, unexpected responses |
| **Dependency Check** | SCA | Known CVEs in Python packages via `safety` |
| **Session Checker** | Auth | JWT weakness, session fixation, insecure token handling |

---

## 📦 Dependencies

```
bandit          # Python SAST
python-nmap     # Nmap bindings
python-owasp-zapv2  # ZAP API client
Jinja2          # Template rendering
PyYAML          # Config parsing
requests        # HTTP client
rich            # Terminal output formatting
colorama        # Cross-platform color output
safety          # Dependency CVE checker
tqdm            # Progress bars
pytest          # Test framework
```

Install all with: `pip install -r requirements.txt`

---

## 🗺️ Roadmap

- [ ] 🔌 **Elasticsearch + Kibana** integration for advanced analytics
- [ ] 📋 **Jira auto-filing** — create tickets for each finding automatically
- [ ] ⚡ **Async scan workers** — parallel execution for faster results
- [ ] 🔔 **Webhook alerts** — Slack / Discord / Teams notifications
- [ ] 🐳 **Docker support** — containerized one-command deployment
- [ ] 📱 **REST API** — expose scan triggers and results via Flask endpoints
- [ ] 🧠 **AI triage** — LLM-assisted severity classification and remediation advice

---

## 🤝 Contributing

Contributions are welcome! To add a new scanner module:

1. Create a new file under the appropriate `scanners/` subdirectory
2. Implement a `run(target, **kwargs)` function that returns `{"summary": str, "details": list}`
3. Register it in `main.py` using the existing `safe_import` pattern
4. Open a pull request with a brief description of the tool and what it detects

---

## 👥 Contributors

| Name | Role |
|---|---|
| **Salmanul Faris** | Architect & Lead Developer |
| **Cyber AI Labs R&D** | Backend R&D & Report Automation |

---

## 📝 License

Released under the **MIT License** — free to use, modify, and distribute with attribution.

See [`LICENSE.md`](./LICENSE.md) for full terms.

---

<div align="center">

**Built with ❤️ for the security community**

*If this project helped you, consider giving it a ⭐ on GitHub*

</div>
