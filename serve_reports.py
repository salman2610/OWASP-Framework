#!/usr/bin/env python3
"""
serve_reports.py — Local HTTP server for generated scan reports.

Fixes:
- Corrected served filename from dashboard_advanced.html → dashboard_rendered.html
- Added graceful error if reports/ directory doesn't exist yet
- Added port conflict handling
- Server binds to localhost only (127.0.0.1) for safety
"""

import http.server
import socketserver
import os
import sys
import webbrowser

PORT = 8000
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")

# Guard: reports dir must exist before we try to serve from it
if not os.path.isdir(REPORTS_DIR):
    print(f"[ERROR] Reports directory not found: {REPORTS_DIR}")
    print("[INFO]  Run 'python3 main.py --target <url>' first to generate reports.")
    sys.exit(1)

os.chdir(REPORTS_DIR)


class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def log_message(self, format, *args):
        # Suppress per-request noise; only show startup message
        pass


# Bind to localhost only — never expose to the network
try:
    with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
        # Prefer the rendered dashboard; fall back to the latest HTML report
        if os.path.exists("dashboard_rendered.html"):
            target_file = "dashboard_rendered.html"
        elif os.path.exists("latest_report.html"):
            target_file = "latest_report.html"
        else:
            print("[WARN] No rendered report found. Serving directory listing.")
            target_file = ""

        url = f"http://127.0.0.1:{PORT}/{target_file}"
        print(f"[*] Serving reports at {url}")
        print("[*] Press Ctrl+C to stop.")
        webbrowser.open(url)
        httpd.serve_forever()
except OSError as e:
    print(f"[ERROR] Could not start server on port {PORT}: {e}")
    print(f"[INFO]  Try a different port: PORT={PORT+1} python3 serve_reports.py")
    sys.exit(1)
except KeyboardInterrupt:
    print("\n[*] Server stopped.")
