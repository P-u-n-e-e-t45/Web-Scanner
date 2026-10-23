from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Security-Policy", "script-src 'unsafe-inline'")
        self.send_header("Strict-Transport-Security", "max-age=100")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *a): pass

print("Vulnerable demo server on http://127.0.0.1:8000 (Ctrl+C to stop)")
ThreadingHTTPServer(("127.0.0.1", 8000), H).serve_forever()