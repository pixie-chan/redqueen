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
