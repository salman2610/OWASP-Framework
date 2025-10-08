import subprocess
import json

def run(target_url):
    """
    Run Bandit SAST scan on the given Python project (local folder or repo).
    """
    print(f"[SAST] Running Bandit scan on {target_url}...")
    try:
        # Run Bandit and get JSON output
        result = subprocess.run(
            ["bandit", "-r", target_url, "-f", "json"],
            capture_output=True, text=True, check=True
        )
        data = json.loads(result.stdout)
        summary = f"Bandit found {len(data.get('results', []))} issues."
        return {"vulnerabilities": data.get("results", []), "summary": summary}
    except Exception as e:
        return {"vulnerabilities": [], "summary": f"Bandit scan failed: {e}"}
