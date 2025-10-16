# OWASP-Framework

Automated OWASP Top 10 testing framework with:

- SAST (Bandit)
- DAST (ZAP)
- API fuzzing
- Dependency checking
- Session analysis
- HTML + JSON report generation
- CI/CD integration via GitHub Actions

## Usage

Activate virtual environment:

```bash
source venv/bin/activate
'''
 /snap/bin/zaproxy -daemon -port 8090 -host 127.0.0.1 -config api.disablekey=true
