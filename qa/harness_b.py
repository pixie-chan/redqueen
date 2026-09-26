
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
