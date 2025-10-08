import subprocess
import json

def run(target_url):
    """
    Run Safety to check Python dependencies for known vulnerabilities.
    Assumes a requirements.txt exists in target_url folder.
    """
    print(f"[Dependency] Checking dependencies for {target_url}...")
    try:
        result = subprocess.run(
            ["safety", "check", "--json", "--file", f"{target_url}/requirements.txt"],
            capture_output=True, text=True, check=True
        )
        data = json.loads(result.stdout) if result.stdout else []
        summary = f"Safety found {len(data)} vulnerabilities."
        return {"vulnerabilities": data, "summary": summary}
    except Exception as e:
        return {"vulnerabilities": [], "summary": f"Safety scan failed: {e}"}

