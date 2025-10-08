import requests

def run(target_url):
    print(f"[Session] Checking session management for {target_url}...")
    try:
        r = requests.get(target_url)
        cookies = r.cookies
        cookie_info = {
            c.name: {"secure": c.secure, "httponly": c.has_nonstandard_attr('HttpOnly')}
            for c in cookies
        }
    except Exception as e:
        cookie_info = {"error": str(e)}
    return cookie_info

