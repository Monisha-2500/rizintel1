"""
target_app.py — Local Deliberately Vulnerable Target Application (WebGoat/Juice Shop Demo)
Port: 8085
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys

class WebGoatHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Server", "OWASP-WebGoat-Demo/8.2")
        self.end_headers()
        response = {"status": "vulnerable", "app": "OWASP WebGoat Demo Target", "path": self.path}
        self.wfile.write(json.dumps(response).encode("utf-8"))

    def log_message(self, format, *args):
        pass  # Quiet logging

def run_target_server(port=8085):
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, WebGoatHandler)
    print(f"[Target Server] Running OWASP WebGoat Target at http://127.0.0.1:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8085
    run_target_server(port)
