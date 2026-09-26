#!/usr/bin/env python3
"""qx_harness.py: intentionally vulnerable local target for QA of redteam.py.
Modes: weak (default) | strong (hardened). NEVER run this exposed to a network.
"""
import hmac, hashlib, base64, json, os, re, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs, unquote

MODE = sys.argv[2] if len(sys.argv) > 2 else "weak"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8931
BASE = f"http://127.0.0.1:{PORT}"


def b64(d):
    return base64.urlsafe_b64encode(d).decode().rstrip("=")


def jwt_token(secret, with_exp=False):
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    pay = {"sub": "qa-user"}
    if with_exp:
        pay["exp"] = int(time.time()) + 3600
    payload = b64(json.dumps(pay).encode())
    signing = f"{head}.{payload}".encode()
    sig = b64(hmac.new(secret.encode(), signing, hashlib.sha256).digest())
    return f"{head}.{payload}.{sig}"


def html(title, body, extra_scripts=""):
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{title}"
            f"</title></head><body><h1>{title}</h1>{body}{extra_scripts}"
            f"</body></html>").encode()


INDEX_BODY = """
<nav><a href='/login'>Login</a> <a href='/assets/'>Assets</a>
<a href='/search?q=hello'>Search</a> <a href='/redirect?to=/home'>Home</a>
<a href='/download?file=readme.txt'>Download</a></nav>
<form method='post' action='/transfer'>
<input name='account'><input name='amount'>
<button>Send</button></form>
<form method='post' action='/login'>
<input name='username' type='text'>
<input name='password' type='password'>
<button>Log in</button></form>
<script src='https://cdn.example.org/lib.js'></script>
<script src='/assets/app.js'></script>
<script>//# sourceMappingURL=/assets/app.js.map</script>"""

STRONG_INDEX = INDEX_BODY.replace(
    "action='/transfer'>",
    "action='/transfer'><input type='hidden' name='csrf_token' value='t8f3k'>"
).replace(
    "action='/login'>",
    "action='/login'><input type='hidden' name='csrf_token' value='t8f3k'>"
).replace("<script src='https://cdn.example.org/lib.js'></script>",
          "<script src='https://cdn.example.org/lib.js' "
          "integrity='sha384-QAtest'></script>").replace(
    "<script>//# sourceMappingURL=/assets/app.js.map</script>", "")

JS_WEAK = """// quantiq client build
const KEY = "AKIAIOSFODNN7EXAMPLE";
const PAY = "sk_live_51H8xY2eZvKYlo2Cdeadbeef";
fetch('/api/v1/portfolio?id=123');
axios.get('/api/v1/prices');
//# sourceMappingURL=/assets/app.js.map
"""

JS_STRONG = """// quantiq client build
fetch('/api/v1/portfolio?id=123');
axios.get('/api/v1/prices');
"""

STRONG_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-site",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; "
                               "base-uri 'none'; frame-ancestors 'none'; "
                               "form-action 'self'",
    "Cache-Control": "no-store, private",
}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # ---------- helpers ----------
    def raw(self, body, status=200, ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        if MODE == "strong":
            for k, v in STRONG_HEADERS.items():
                if k == "Cache-Control" and "/login" not in self.path:
                    continue
                self.send_header(k, v)
        else:
            self.send_header("X-Powered-By", "Express/4.18.2")
        origin = self.headers.get("Origin")
        if origin and MODE == "weak":
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in (extra or {}).items():
            if isinstance(v, list):
                for item in v:
                    self.send_header(k, item)
            else:
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _notfound(self):
        if MODE == "weak":
            self.raw("Traceback (most recent call last):\n"
                     '  File "/app/server.py", line 42, in handler\n'
                     "KeyError: 'missing'\n", status=500, ctype="text/plain")
        else:
            self.raw(html("Not found", "<p>404</p>"), status=404)
