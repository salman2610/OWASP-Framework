# scanners/sast/bandit_scan.py
import subprocess
import json
import os
from datetime import datetime

def run(target_path):
    """
    Run Bandit recursively against a local Python project folder (target_path).
    Returns a dict with 'results' list and summary.
    """
    print(f"[SAST] Running Bandit scan on {target_path}...")
    try:
        # If target_path is a URL, Bandit won't scan it — expect local path
        if target_path.startswith("http://") or target_path.startswith("https://"):
            return {"results": [], "summary": "Bandit requires a local path; skipping for URL targets."}

        # Ensure target exists
        if not os.path.exists(target_path):
            return {"results": [], "summary": f"Target path {target_path} does not exist."}

        # Run bandit with JSON output
        cmd = ["bandit", "-r", target_path, "-f", "json"]
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
        stdout = completed.stdout.strip()

        if not stdout:
            # No output — maybe bandit finished with no issues
            return {"results": [], "summary": "Bandit completed (no output).", "raw": completed.stderr}

        data = json.loads(stdout)
        results = data.get("results", [])

        summary = f"Bandit found {len(results)} issues."
        return {"results": results, "summary": summary, "raw": data}
    except Exception as e:
        return {"results": [], "summary": f"Bandit failed: {e}"}
