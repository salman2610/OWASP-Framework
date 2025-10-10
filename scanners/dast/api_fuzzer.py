# scanners/dast/api_fuzzer.py
import requests
import time

COMMON_ENDPOINTS = [
    "/login", "/admin", "/api/login", "/api/v1/login", "/register", "/search", "/product", "/item", "/user"
]

FUZZ_PAYLOADS = [
    "' OR '1'='1", "\" OR \"1\"=\"1", "'; --", "<script>alert(1)</script>", "../../etc/passwd", "%3Cscript%3Ealert(1)%3C/script%3E"
]

HEADERS = {"User-Agent": "OWASP-Framework-Fuzzer/1.0"}

def run(base_url):
    """
    Simple API fuzzing: GET requests to common endpoints, try payloads in query params.
    Returns list of results (dicts).
    """
    print(f"[DAST] Running API fuzzing on {base_url}...")
    results = []
    for ep in COMMON_ENDPOINTS:
        url = base_url.rstrip("/") + ep
        try:
            r = requests.get(url, headers=HEADERS, timeout=8, verify=False)
            results.append({"endpoint": ep, "status_code": r.status_code, "reason": r.reason})
        except Exception as e:
            results.append({"endpoint": ep, "error": str(e)})
        # Try payloads as ?q=payload
        for p in FUZZ_PAYLOADS:
            try:
                t = time.time()
                r = requests.get(url, params={"q": p}, headers=HEADERS, timeout=8, verify=False)
                latency = round((time.time() - t) * 1000)
                entry = {"endpoint": ep, "payload": p, "status_code": r.status_code, "latency_ms": latency}
                text = (r.text or "").lower()
                # heuristics for possible findings
                if "sql" in text or "mysql" in text or "syntax" in text or "error" in text or p in text:
                    entry["interesting"] = True
                if r.status_code >= 500:
                    entry["interesting"] = True
                results.append(entry)
            except Exception as e:
                results.append({"endpoint": ep, "payload": p, "error": str(e)})
    print("[API Fuzz ✅] Done")
    return results
