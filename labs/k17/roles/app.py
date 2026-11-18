"""Jednoduchá aplikační služba: JSON, soubor 2 MB, zápis stavu na /data."""
import http.server, json, os, socketserver, sys, time, syslog
syslog.openlog("app", 0, syslog.LOG_DAEMON)
BLOB = os.urandom(2 * 1024 * 1024)

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        if self.path.startswith("/file"):
            body, ctype = BLOB, "application/octet-stream"
        else:
            try:
                with open(f"/data/state-{int(time.time()) % 50}.json", "w") as f:
                    f.write(json.dumps({"t": time.time(), "pad": "x" * 2048}))
            except OSError as e:
                syslog.syslog(syslog.LOG_ERR, f"state write failed: {e}")
                self.send_response(500); self.end_headers(); return
            body, ctype = json.dumps({"ok": True, "t": time.time()}).encode(), "application/json"
        self.send_response(200); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

os.makedirs("/data", exist_ok=True)
S(("127.0.0.1", 8080), H).serve_forever()
