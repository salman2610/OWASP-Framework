#!/usr/bin/env python3
import http.server
import socketserver
import os
import webbrowser

PORT = 8000
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")

os.chdir(REPORTS_DIR)

class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()

# Start server
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    url = f"http://localhost:{PORT}/dashboard_advanced.html"
    print(f"Serving reports at {url}")
    webbrowser.open(url)
    httpd.serve_forever()
