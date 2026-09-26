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
// The scanner reads served text verbatim, so the fixture must be one
// unbroken token. These are synthetic QA values, not real credentials.
// Synthetic QA fixture, 20 chars, AWS-key shaped, deliberately
// obvious: the masking gates need a real shape to match against.
const KEY = "AKIAZZNOTAREALKEYXXX";
const PAY = "sk_livQXZQbeef7X4K2B";
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
    def do_GET(self):
        parts = urlsplit(self.path)
        path = unquote(parts.path)
        q = parse_qs(parts.query, keep_blank_values=True)

        if MODE == "empty":
            # every route is the same not-found page: nothing to crawl, so
            # the scan-quality warnings must fire. First branch on purpose.
            self.raw("<html><head><title>Not found</title></head>"
                     "<body><h1>404</h1></body></html>", status=404)
            return

        # ---------- Tier B surfaces ----------

        # deliberately broken: returns the previous request's body marker
        if path == "/desync-echo":
            self.desync_echo()
            return

        # what the server actually received, for the Tier B method gate
        if path == "/qx-method-log":
            self.raw(json.dumps(H.methods), ctype="application/json")
            return
        if path == "/qx-method-log/reset":
            H.methods.clear()
            self.raw(json.dumps({"reset": True}), ctype="application/json")
            return

        # Tier B: the same status, materially different bytes depending on
        # how the raw target is read. This is the cache-versus-origin
        # disagreement the delimiter check exists to catch, so the fixture
        # serves genuinely different documents. Near-identical bodies would
        # be a correct true negative: the check ignores differences under
        # its 0.15 distance threshold on purpose.
        if path.startswith("/echo-path"):
            raw = self.path
            if ";" in raw:
                self.raw(".echo{color:#39d98a;margin:0;padding:0}\n" * 12,
                         ctype="text/css")
            elif raw.endswith("."):
                self.raw("const echoPath = function (t) { return t; };\n" * 6,
                         ctype="application/javascript")
            elif "%2e" in raw:
                self.raw(json.dumps({"route": "encoded-dot", "raw": raw,
                                     "assets": ["a.css", "b.js", "c.png"]}),
                         ctype="application/json")
            else:
                # "?" and "#" land here on purpose: a server that treats
                # /echo-path? and /echo-path# as /echo-path is correct, and
                # the check must stay quiet when it does
                self.raw(html("Echo path", f"<p>raw path: {raw}</p>"))
            return

        # normalization oracle: NFKC-folds what it reflects (weak), or
        # escapes it faithfully (strong)
        if path == "/unicode":
            val = q.get("q", [""])[0]
            if MODE == "weak":
                self.raw(html("Unicode",
                              "<p>normalized: "
                              + unicodedata.normalize("NFKC", val) + "</p>"))
            else:
                import html as hl
                self.raw(html("Unicode", f"<p>value: {hl.escape(val)}</p>"))
            return

        # documented object paths: the weak build hands out an object to
        # anyone, the strong build demands authentication
        if re.match(r"^/api/v1/(orders|users)/[^/]+$", path):
            if MODE == "weak":
                self.raw(json.dumps({"id": path.rsplit("/", 1)[-1],
                                     "owner": "qa-user",
                                     "email": "qa@example.test",
                                     "status": "active"}),
                         ctype="application/json")
            else:
                self.raw(json.dumps({"error": "unauthorized"}), status=401,
                         ctype="application/json")
            return
        if path in ("/api/v1/orders", "/api/v1/users"):
            if MODE == "weak":
                self.raw(json.dumps({"items": [], "count": 0}),
                         ctype="application/json")
            else:
                self.raw(json.dumps({"error": "unauthorized"}), status=401,
                         ctype="application/json")
            return


    # ---------- GET ----------

        # reflection + injection playground
        if path == "/search":
            val = q.get("q", [""])[0]
            if MODE == "weak":
                if val.endswith("'"):
                    self.raw("Error: You have an error in your SQL syntax; "
                             "check the manual that corresponds to your MySQL "
                             "server version near '' at line 1",
                             status=500, ctype="text/plain")
                    return
                m = re.search(r"echo\s+(QX[A-Za-z0-9]+)", val)
                if m and (";" in val or "|" in val):
                    self.raw(html("Search", f"<p>results for {m.group(1)}</p>"))
                    return
                self.raw(html("Search", f"<p>results for {val}</p>"))
                return
            import html as hl
            self.raw(html("Search", f"<p>results for {hl.escape(val)}</p>"))
            return

        if path == "/redirect":
            to = q.get("to", [""])[0]
            if MODE == "strong" and not re.match(r"^/(?!/)", to):
                self.raw("", status=302, extra={"Location": "/"})
            else:
                self.raw("", status=302, extra={"Location": to})
            return

        if path == "/download":
            f = q.get("file", [""])[0]
            if ".." in f:
                if MODE == "strong":
                    self.raw("bad path", status=400, ctype="text/plain")
                else:
                    self.raw("QXPLANT.txt contents: PLANTED-CANARY-MARKER",
                             ctype="text/plain")
                return
            if MODE == "strong":
                import html as hl2
                self.raw(f"contents of {hl2.escape(f)}", ctype="text/plain")
            else:
                self.raw(f"contents of {f}", ctype="text/plain")
            return

        if path in ("/", "/index.html"):
            body = INDEX_BODY if MODE == "weak" else STRONG_INDEX
            xfh = self.headers.get("X-Forwarded-Host")
            if MODE == "weak" and xfh:
                body += (f"<footer><a href=\"http://{xfh}/reset-password\">"
                         f"Reset password</a></footer>")
            self.raw(html("placeholder_website QA", body))
            return

        if path == "/login":
            cookies = ["sessionid=abc123; Path=/"]
            if MODE == "strong":
                cookies = ["sessionid=abc123; Path=/; HttpOnly; SameSite=Lax",
                           "auth=" + jwt_token("u8X2!realSecret#QA", with_exp=True)
                           + "; Path=/; HttpOnly; SameSite=Lax; Secure"]
            else:
                cookies.append("auth=" + jwt_token("secret") + "; Path=/")
            token = ("<input type='hidden' name='csrf_token' value='t8f3k'>"
                     if MODE == "strong" else "")
            form = ("<form method='post' action='/login'>" + token +
                    "<input name='username'><input name='password' type='password'>"
                    "<button>Sign in</button></form>")
            self.raw(html("Login", form), extra={"Set-Cookie": cookies})
            return

        if path == "/assets/":
            if MODE == "strong":
                self.raw("forbidden", status=403, ctype="text/plain")
                return
            self.raw("<html><head><title>Index of /assets</title></head>"
                     "<body><h1>Index of /assets</h1>"
                     "<ul><li>app.js</li><li>app.js.map</li><li>logo.png</li>"
                     "</ul></body></html>")
            return
        if path == "/assets/app.js.map":
            self.raw(json.dumps({"version": 3, "sources": ["src/app.ts"],
                                 "mappings": "AAAA"}),
                     ctype="application/json")
            return

        if MODE == "weak":
            exposed = {
                "/.git/HEAD": ("ref: refs/heads/main\n", "text/plain"),
                "/.env": ("SECRET_KEY=hunter2\nDB_PASSWORD=hunter2\n", "text/plain"),
                "/package.json": ('{"name":"placeholder_website","dependencies":{"express":"^4.0.0"}}',
                                  "application/json"),
                "/config.json": ('{"db":{"password":"hunter2"}}', "application/json"),
                "/.aws/credentials": ("[default]\naws_access_key_id = AKIAFAKE\n",
                                      "text/plain"),
                "/id_rsa": ("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n"
                            "-----END OPENSSH PRIVATE KEY-----\n", "text/plain"),
                "/server-status": ("<html><title>Apache Server Status</title>"
                                   "<body>Server Version: Apache/2.4.49</body></html>",
                                   "text/html"),
                "/backup.zip": (b"PK\x03\x04fakezipdata", "application/zip"),
                "/admin": (html("Dashboard",
                                "<table><tr><td>metric</td><td>1284</td></tr>"
                                "<tr><td>users</td><td>91</td></tr></table>"
                                + "<p>" * 30 + "</p>"), "text/html"),
            }
            if path in exposed:
                body, ctype = exposed[path]
                self.raw(body, ctype=ctype)
                return

        if path == "/admin":
            if MODE == "strong":
                self.raw("", status=302, extra={"Location": "/login"})
            else:
                self.raw(html("Dashboard", "<table><tr><td>ok</td></tr></table>"
                               + "<p>" * 30 + "</p>"))
            return

        if path == "/assets/app.js":
            if MODE == "weak":
                self.raw(JS_WEAK, ctype="application/javascript")
            else:
                self.raw(JS_STRONG, ctype="application/javascript")
            return

        if path == "/item":
            val = q.get("id", [""])[0]
            if MODE == "weak" and "1=2" in val:
                self.raw(html("Item", "<p>no results for query</p>"))
                return
            self.raw(html("Item", "<table><tr><li>widget-alpha</li>"
                          "<li>widget-beta</li><li>widget-gamma</li></tr>"
                          "</table><p>done</p>"))
            return

        if path in ("/api/v1/portfolio", "/api/v1/prices"):
            if MODE == "weak":
                self.raw('{"positions":[{"sym":"XAU","qty":3}]}',
                         ctype="application/json")
            else:
                self._notfound()
            return

        if path == "/graphql":
            if MODE == "weak" and "__schema" in q.get("query", [""])[0]:
                self.raw('{"data":{"__schema":{"types":[{"name":"Query"}]}}}',
                         ctype="application/json")
                return
            self._notfound()
            return

        if path == "/account":
            if MODE == "strong":
                self.raw("", status=302, extra={"Location": "/login"})
                return
            self.raw(html("Account", "<h2>Overview</h2>"
                          "<table><tr><td>balance</td><td>42.00</td></tr>"
                          "<tr><td>orders</td><td>7</td></tr></table>"
                          + "<div>" * 40 + "</div>"))
            return

        # the real OpenAPI document with {param} templates is served by the
        # OPENAPI_DOC branch further down
            self._notfound()
            return

        if path == "/phpmyadmin/":
            if MODE == "weak":
                self.raw(html("phpMyAdmin", "<h1>phpMyAdmin</h1>"
                              "<form>Login to MySQL</form>"))
                return
            self._notfound()
            return

        if path == "/openapi.json":
            if MODE == "weak":
                self.raw(json.dumps(OPENAPI_DOC), ctype="application/json")
                return
            self._notfound()
            return

        if path == "/robots.txt":
            if MODE == "strong":
                self.raw("User-agent: *\nAllow: /\n"
                         f"Sitemap: {BASE}/sitemap.xml\n", ctype="text/plain")
            else:
                self.raw("User-agent: *\nDisallow: /admin\nDisallow: /backup\n"
                         f"Sitemap: {BASE}/sitemap.xml\n", ctype="text/plain")
            return

        if path == "/sitemap.xml":
            locs = ["/", "/login", "/search?q=hello", "/redirect?to=/home",
                    "/download?file=readme.txt", "/item?id=1", "/assets/"]
            xml = "<?xml version='1.0'?><urlset>" + "".join(
                f"<url><loc>{BASE}{l}</loc></url>" for l in locs) + "</urlset>"
            self.raw(xml, ctype="application/xml")
            return

        if path == "/security.txt":
            if MODE == "strong":
                self.raw("Contact: mailto:qa@example.test\nPolicy: "
                         f"{BASE}/policy\n", ctype="text/plain")
                return
            self._notfound()
            return

        self._notfound()

    # ---------- other methods ----------
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        path = urlsplit(self.path).path
        if path == "/login":
            if MODE == "strong":
                H.hits += 1
                if H.hits > 5:
                    self.raw("Too many attempts", status=429, ctype="text/plain",
                             extra={"Retry-After": "60"})
                    return
            self.raw(html("Welcome", "<p>Welcome back, test user.</p>"))
            return
        if path == "/transfer":
            self.raw(html("Transfer", "<p>queued for review</p>"))
            return
        self._notfound()

    def do_OPTIONS(self):
        allow = "GET, HEAD, POST, OPTIONS" if MODE == "strong" else \
            "GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS"
        self.raw("", status=204, extra={"Allow": allow})

    def do_TRACE(self):
        if MODE == "strong":
            self.raw("method not allowed", status=405, ctype="text/plain")
            return
        echo = (f"TRACE {self.path} HTTP/1.1\r\n"
                f"User-Agent: {self.headers.get('User-Agent', '')}\r\n"
                f"Cookie: {self.headers.get('Cookie', '')}\r\n")
        self.raw(echo, ctype="message/http")

    def do_PUT(self):
        self.raw("stored" if MODE == "weak" else "method not allowed",
                 status=200 if MODE == "weak" else 405, ctype="text/plain")


H.hits = 0
# Tier B: the method log lets a QA gate prove no mutating verb was ever sent,
# and the stash backs the deliberately broken desync echo handler.
H.methods = []
H.stash = b""


def main():
    H.server_version = "nginx/1.18.0" if MODE == "weak" else "nginx"
    H.sys_version = ""
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    if os.environ.get("QX_TLS") == "1":
        import ssl as _ssl
        here = os.path.dirname(os.path.abspath(__file__))
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(here, "cert.pem"),
                            os.path.join(here, "key.pem"))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"qx_harness {MODE} listening on {BASE}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
