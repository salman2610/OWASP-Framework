import subprocess
import time
from zapv2 import ZAPv2

# Path to Snap-installed ZAP
ZAP_PATH = "/snap/bin/zaproxy"
ZAP_PORT = 8090  # default ZAP proxy port

def wait_for_complete(zap, scan_type, scan_id):
    """Wait until spider or active scan is finished."""
    while True:
        if scan_type == "spider":
            progress = int(zap.spider.status(scan_id))
            print(f"[DAST] Spider progress: {progress}%", end="\r")
            if progress >= 100:
                break
        elif scan_type == "ascan":
            progress = int(zap.ascan.status(scan_id))
            print(f"[DAST] Active scan progress: {progress}%", end="\r")
            if progress >= 100:
                break
        time.sleep(2)
    print()  # newline after progress

def run(target_url):
    print(f"[DAST] Running ZAP scan on {target_url}...")

    try:
        # Start ZAP in daemon mode
        subprocess.Popen([ZAP_PATH, "-daemon", "-port", str(ZAP_PORT)])
        print("[DAST] ZAP daemon starting...")
        time.sleep(10)  # initial wait for ZAP to fully start

        # Connect to ZAP API
        zap = ZAPv2(proxies={
            "http": f"http://127.0.0.1:{ZAP_PORT}",
            "https": f"http://127.0.0.1:{ZAP_PORT}"
        })

        # Spider the target
        spider_id = zap.spider.scan(target_url)
        print("[DAST] Spidering target...")
        wait_for_complete(zap, "spider", spider_id)

        # Active scan the target
        ascan_id = zap.ascan.scan(target_url)
        print("[DAST] Running active scan...")
        wait_for_complete(zap, "ascan", ascan_id)

        # Fetch alerts
        alerts = zap.core.alerts(baseurl=target_url)
        print(f"[DAST ✅] ZAP scan completed with {len(alerts)} alerts")

    except Exception as e:
        print(f"[DAST ❌] ZAP scan failed: {e}")
        alerts = []

    return {"alerts": alerts, "summary": f"ZAP scan completed on {target_url}"}

