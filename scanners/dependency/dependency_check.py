# scanners/dependency/dependency_check.py
import subprocess
import json
import os

def run(target_path=None):
    """
    Run Safety against a requirements.txt file.
    If target_path is a folder, it will look for requirements.txt inside it.
    Returns dict with 'vulnerabilities' and 'summary'.
    """
    print("[Dependency] Checking dependencies...")
    try:
        req_file = "requirements.txt"
        if target_path and os.path.isdir(target_path):
            candidate = os.path.join(target_path, "requirements.txt")
            if os.path.exists(candidate):
                req_file = candidate

        if not os.path.exists(req_file):
            return {"vulnerabilities": [], "summary": f"No requirements.txt found at {req_file}; skipping Safety."}

        # Run safety check
        cmd = ["safety", "check", "--json", "--file", req_file]
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
        stdout = completed.stdout.strip()
        if not stdout:
            return {"vulnerabilities": [], "summary": "Safety completed (no JSON output).", "raw": completed.stderr}

        data = json.loads(stdout)
        # safety may return [] or list of vulns
        vulns = data if isinstance(data, list) else data.get("vulnerabilities", data)
        summary = f"Safety found {len(vulns)} issues." if vulns else "No dependency vulnerabilities found."
        return {"vulnerabilities": vulns, "summary": summary, "raw": data}
    except Exception as e:
        return {"vulnerabilities": [], "summary": f"Safety scan failed: {e}"}
