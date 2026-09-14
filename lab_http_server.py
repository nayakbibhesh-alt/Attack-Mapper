"""A tiny, self-contained HTTP server standing in for a lab target.
Serves an intentionally leaky debug endpoint so http_probe/parsers can
be demonstrated against something real, entirely on localhost -- no
third-party network involved.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/internal/debug":
            body = b'{"status": "ok", "service_account_token": "sa-tok-EXAMPLE1234567890abcdef"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"<html><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
    def log_message(self, fmt, *args):
        pass  # quiet

if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
