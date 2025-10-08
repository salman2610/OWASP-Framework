import requests

def run(target_url):
    print(f"[DAST] Running API fuzzing on {target_url}...")
    test_endpoints = ["/login", "/register", "/search"]
    fuzz_results = []

    for endpoint in test_endpoints:
        url = f"{target_url}{endpoint}"
        try:
            r = requests.get(url, timeout=5)
            fuzz_results.append({"endpoint": endpoint, "status_code": r.status_code})
        except Exception as e:
            fuzz_results.append({"endpoint": endpoint, "error": str(e)})

    print(f"[API Fuzz ✅] Done")
    return fuzz_results

