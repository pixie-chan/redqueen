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


    # ---------- GET ----------
    def do_GET(self):
        parts = urlsplit(self.path)
        path = unquote(parts.path)
        q = parse_qs(parts.query, keep_blank_values=True)

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

        if path == "/openapi.json":
            if MODE == "weak":
                self.raw('{"openapi":"3.0.0","info":{"title":"placeholder_website api"}}',
                         ctype="application/json")
                return
            self._notfound()
            return

        if path == "/phpmyadmin/":
            if MODE == "weak":
                self.raw(html("phpMyAdmin", "<h1>phpMyAdmin</h1>"
                              "<form>Login to MySQL</form>"))
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
