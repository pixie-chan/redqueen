#!/usr/bin/env python3
"""qx_harness.py: intentionally vulnerable local target for QA of redteam.py.
Modes: weak (default) | strong (hardened). NEVER run this exposed to a network.
"""
import hmac, hashlib, base64, json, os, re, sys, time, unicodedata
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
<a href='/download?file=readme.txt'>Download</a>
<a href='/unicode?q=hello'>Unicode</a> <a href='/echo-path'>Echo</a></nav>
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

# Tier B: a real OpenAPI 3 document with {param} path templates, so the
# API state walk has something to walk. The orders item declares an
# integer (so the walker synthesizes "0") and also a delete operation the
# walker must never send; the users item declares a string (so the walker
# synthesizes its own canary) and a post operation the walker may only
# send when --allow-spec-post is given.
OPENAPI_DOC = {
    "openapi": "3.0.0",
    "info": {"title": "placeholder_website api", "version": "1.0.0"},
    "paths": {
        "/api/v1/orders/{orderId}": {
            "get": {"operationId": "getOrder",
                    "parameters": [{"name": "orderId", "in": "path",
                                    "required": True,
                                    "schema": {"type": "integer"}}]},
            "delete": {"operationId": "deleteOrder",
                       "parameters": [{"name": "orderId", "in": "path",
                                       "required": True,
                                       "schema": {"type": "integer"}}]},
        },
        "/api/v1/users/{userId}": {
            "get": {"operationId": "getUser",
                    "parameters": [{"name": "userId", "in": "path",
                                    "required": True,
                                    "schema": {"type": "string"}}]},
            "post": {"operationId": "createUser",
                     "requestBody": {"content": {"application/json": {
                         "schema": {"type": "object", "properties": {
                             "email": {"type": "string"}}}}}},
                     "responses": {"201": {"description": "created"}}},
        },
    },
}

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

JS_WEAK = """// placeholder_website client build
const KEY = "AKIAIOSFODNN7EXAMPLE";
const PAY = "sk_live_51H8xY2eZvKYlo2Cdeadbeef";
fetch('/api/v1/portfolio?id=123');
axios.get('/api/v1/prices');
//# sourceMappingURL=/assets/app.js.map
"""

JS_STRONG = """// placeholder_website client build
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
    # Tier B: the method log lets a QA gate prove no mutating verb was ever
    # sent, and the stash backs the deliberately broken desync echo handler.
    # Declared on the class, so they exist before the first request arrives.
    methods = []
    stash = b""

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

    def parse_request(self):
        """Log every method the harness actually receives, so a QA gate can
        prove no mutating verb was ever sent rather than trusting the
        bot's own report."""
        ok = BaseHTTPRequestHandler.parse_request(self)
        if ok:
            H.methods.append(self.command)
        return ok


    def _read_bounded(self, n, seconds=1.5):
        """Read at most n bytes, giving up quickly instead of blocking.

        The Tier B desync cell "0" announces a Content-Length and then
        sends nothing, which is the whole point of that cell: a handler
        that trusts the header waits for bytes that never arrive. A real
        broken proxy hangs here; the harness gives up so QA stays fast.
        """
        old = self.connection.gettimeout()
        try:
            self.connection.settimeout(seconds)
            return self.rfile.read(n)
        except OSError:
            return b""
        finally:
            try:
                self.connection.settimeout(old)
            except OSError:
                pass

    def _read_body(self):
        """Whatever framing headers claim, read at most one message body."""
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > 0:
            return self._read_bounded(length)
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            size_line = self._read_bounded(65536).split(b";")[0].strip()
            try:
                size = int(size_line, 16)
            except ValueError:
                return b""
            if size <= 0:
                return b""
            body = self._read_bounded(size)
            self._read_bounded(2)          # trailing CRLF after the chunk
            self._read_bounded(2)          # and the 0-length terminator
            return body
        return b""

    def desync_echo(self):
        """DELIBERATELY BROKEN handler for the Tier B desync gate.

        It keeps whatever body the previous request on this connection
        carried and hands it back on the next request, which is what a
        front-end and back-end that disagree about message length look
        like from the outside. The canary planted by the setup request
        therefore comes back in the follow-up response.
        """
        body = self._read_body()
        if body:
            H.stash = body
        shown = H.stash.decode("utf-8", "replace") if H.stash else "(empty)"
        self.raw(html("Desync echo", f"<p>previous body: {shown}</p>"))
