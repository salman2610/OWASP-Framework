#!/usr/bin/env python3
"""
scanners/dast/zap_scan.py

Robust wrapper around OWASP ZAP API (python-owasp-zapv2).
- attempts to start local zap daemon if not already running (using /snap/bin/zaproxy)
- spider the target, then active-scan
- returns structured alerts list and a summary
Return shape:
{
  "alerts": [ { "alert":..., "risk":..., "url":..., ... }, ... ],
  "summary": "ZAP scan completed: N alerts",
}
"""
from shutil import which
import subprocess
import time
import os

ZAP_BIN = "/snap/bin/zaproxy"  # change if you prefer a different path
ZAP_API_ADDR = "127.0.0.1"
ZAP_API_PORT = 8090
ZAP_API_PROXY = f"http://{ZAP_API_ADDR}:{ZAP_API_PORT}"
ZAP_START_WAIT = 8  # seconds to wait after starting zap
ZAP_POLL_INTERVAL = 2
ZAP_SPIDER_TIMEOUT = 180
ZAP_ASCAN_TIMEOUT = 900

def _try_start_zap():
    """
    Try to start ZAP daemon if possible (non-blocking, best-effort).
    Returns True if a process was started or ZAP already present.
    """
    # If zap binary not present at snap path, skip starting
    if not os.path.exists(ZAP_BIN):
        return False

    # check if port is already listening by trying a curl
    try:
        import urllib.request
        urllib.request.urlopen(f"http://{ZAP_API_ADDR}:{ZAP_API_PORT}/", timeout=2)
        return True
    except Exception:
        pass

    # start zap in daemon mode
    try:
        subprocess.Popen([ZAP_BIN, "-daemon", "-port", str(ZAP_API_PORT), "-host", ZAP_API_ADDR, "-config", "api.disablekey=true"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(ZAP_START_WAIT)
        return True
    except Exception:
        return False

def run(target_url):
    """
    Run spider + active scan on target_url and return alerts list.
    """
    print(f"[DAST] Running ZAP scan on {target_url}...")

    # lazy import so module import doesn't fail if zapv2 not installed
    try:
        from zapv2 import ZAPv2
    except Exception as e:
        msg = f"python zap api (zapv2) not installed or import error: {e}"
        print(f"[DAST ❌] {msg}")
        return {"alerts": [], "summary": msg}

    # ensure zap is running / start it if possible
    _try_start_zap()

    # create zap api client
    try:
        zap = ZAPv2(proxies={"http": ZAP_API_PROXY, "https": ZAP_API_PROXY})
    except Exception as e:
        msg = f"Could not create ZAP client: {e}"
        print(f"[DAST ❌] {msg}")
        return {"alerts": [], "summary": msg}

    # sanity check API availability
    try:
        ver = zap.core.version
        print(f"[DAST] ZAP API version: {ver}")
    except Exception as e:
        msg = f"ZAP API not reachable at {ZAP_API_PROXY}: {e}"
        print(f"[DAST ❌] {msg}")
        return {"alerts": [], "summary": msg}

    alerts = []
    try:
        # Ensure target is visited by ZAP: open URL
        try:
            zap.urlopen(target_url)
            time.sleep(1)
        except Exception:
            pass

        # Spider
        print("[DAST] Spidering target...")
        try:
            sid = zap.spider.scan(target_url)
        except Exception as e:
            # older/newer versions might return differently
            try:
                sid = zap.spider.scan(target_url, maxChildren=None)
            except Exception as e2:
                print(f"[DAST] Spider start error: {e2}")
                sid = None

        # wait for spider to finish
        if sid is not None:
            t_start = time.time()
            while True:
                try:
                    status = zap.spider.status(sid)
                except Exception:
                    # sometimes status returns string or raises; try safe access
                    try:
                        status = zap.spider.status(sid)
                    except Exception:
                        status = "100"
                # status might be a string number
                try:
                    if str(status).isdigit() and int(status) >= 100:
                        break
                except Exception:
                    pass
                if time.time() - t_start > ZAP_SPIDER_TIMEOUT:
                    print("[DAST] Spider timeout reached")
                    break
                print(f"[DAST] Spider progress: {status}%")
                time.sleep(ZAP_POLL_INTERVAL)
        else:
            print("[DAST] Spider was not started (sid None)")

        # Active scan
        print("[DAST] Running active scan...")
        try:
            asid = zap.ascan.scan(target_url)
        except Exception as e:
            try:
                asid = zap.ascan.scan(target_url, recurse=True, inplace=False)
            except Exception as e2:
                print(f"[DAST] Active scan start error: {e2}")
                asid = None

        if asid is not None:
            t_start = time.time()
            while True:
                try:
                    astatus = zap.ascan.status(asid)
                except Exception:
                    try:
                        astatus = zap.ascan.status(asid)
                    except Exception:
                        astatus = "100"
                try:
                    if str(astatus).isdigit() and int(astatus) >= 100:
                        break
                except Exception:
                    pass
                if time.time() - t_start > ZAP_ASCAN_TIMEOUT:
                    print("[DAST] Active scan timeout reached")
                    break
                print(f"[DAST] Ascan progress: {astatus}%")
                time.sleep(ZAP_POLL_INTERVAL)
        else:
            print("[DAST] Active scan not started (asid None)")

        # gather alerts
        try:
            raw_alerts = zap.core.alerts(baseurl=target_url)
        except TypeError:
            # some versions have different signature
            raw_alerts = zap.core.alerts()
        except Exception as e:
            print(f"[DAST] Error fetching alerts: {e}")
            raw_alerts = []

        # Normalize each alert into a friendly dict
        for a in raw_alerts or []:
            try:
                alerts.append({
                    "alert": a.get("alert") or a.get("name") or "",
                    "risk": a.get("risk") or a.get("riskdesc") or "",
                    "confidence": a.get("confidence", ""),
                    "url": a.get("url", "") or a.get("uri", ""),
                    "param": a.get("param", ""),
                    "evidence": a.get("evidence", ""),
                    "cweid": a.get("cweid", ""),
                    "wascid": a.get("wascid", ""),
                    "solution": a.get("solution", ""),
                    "reference": a.get("reference", ""),
                    "pluginid": a.get("pluginId") or a.get("pluginid") or "",
                    "other": a
                })
            except Exception:
                # fallback: add raw item
                alerts.append({"raw": a})

    except Exception as e:
        print(f"[DAST ❌] ZAP scan failed: {e}")
        return {"alerts": [], "summary": f"ZAP scan failed: {e}"}

    summary = f"ZAP scan completed: {len(alerts)} alerts"
    print(f"[DAST ✅] {summary}")
    return {"alerts": alerts, "summary": summary}
