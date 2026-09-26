
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
