import subprocess
import time
import os
from zapv2 import ZAPv2

ZAP_PATH = "/snap/bin/zaproxy"
ZAP_PORT = 8090
ZAP_START_TIMEOUT = 30
POLL_INTERVAL = 2

def _is_numeric(s):
    try:
        int(s)
        return True
    except Exception:
        return False

def _wait_for_zap_api(zap, timeout=ZAP_START_TIMEOUT):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _ = zap.core.version
            return True
        except Exception:
            time.sleep(1)
    return False

def _safe_status_int(zap, kind, scan_id):
    try:
        if kind == "spider":
            s = zap.spider.status(scan_id)
        else:
            s = zap.ascan.status(scan_id)
        if _is_numeric(s):
            return int(s)
        return None
    except Exception:
        return None

def wait_for_complete(zap, scan_type, scan_id, timeout=600):
    start = time.time()
    while time.time() - start < timeout:
        progress = _safe_status_int(zap, scan_type, scan_id)
        if progress is None:
            print(f"[DAST] Warning: {scan_type} status for id {scan_id} returned non-numeric value.")
            return False
        print(f"[DAST] {scan_type.capitalize()} progress: {progress}%", end="\r")
        if progress >= 100:
            print()
            return True
        time.sleep(POLL_INTERVAL)
    print()
    print(f"[DAST] {scan_type} timed out after {timeout} seconds")
    return False

def run(target_url):
    print(f"[DAST] Running ZAP scan on {target_url}...")
    alerts = []
    summary = ""
    zap_process = None
    try:
        if not os.path.exists(ZAP_PATH):
            raise FileNotFoundError(f"ZAP binary not found at {ZAP_PATH}")
        zap_process = subprocess.Popen([ZAP_PATH, "-daemon", "-port", str(ZAP_PORT), "-host", "127.0.0.1"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[DAST] ZAP daemon starting...")
        zap = ZAPv2(proxies={"http": f"http://127.0.0.1:{ZAP_PORT}", "https": f"http://127.0.0.1:{ZAP_PORT}"})
        if not _wait_for_zap_api(zap, timeout=ZAP_START_TIMEOUT):
            raise RuntimeError("ZAP API did not become ready within timeout")
        spider_id = zap.spider.scan(target_url)
        print("[DAST] Spidering target...")
        if not wait_for_complete(zap, "spider", spider_id):
            raise RuntimeError("Spider did not complete successfully or returned invalid status")
        ascan_id = zap.ascan.scan(target_url)
        print("[DAST] Running active scan...")
        if not wait_for_complete(zap, "ascan", ascan_id, timeout=1800):
            print("[DAST] Active scan did not complete cleanly")
            summary = "Active scan did not complete cleanly"
        alerts = zap.core.alerts(baseurl=target_url)
        summary = summary or f"ZAP found {len(alerts)} alerts"
        print(f"[DAST ✅] ZAP scan completed: {len(alerts)} alerts")
    except Exception as e:
        summary = f"ZAP scan failed: {e}"
        print(f"[DAST ❌] {summary}")
    finally:
        try:
            if zap_process:
                zap_process.terminate()
        except Exception:
            pass
    return {"vulnerabilities": alerts, "summary": summary}
