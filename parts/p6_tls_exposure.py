

def check_tls(bot):
    if bot.t.scheme == "http":
        bot.add("no-tls", url=bot.t.base + bot.t.path,
                evidence="target served over http://", verify=lambda: True)
        return
    host, port = bot.t.host, bot.t.port
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=bot.args.timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ts:
                cert = ts.getpeercert()
                ver = ts.version()
        not_after = ssl.cert_time_to_seconds(cert["notAfter"])
        days = (not_after - time.time()) / 86400
        subj = dict(x[0] for x in cert.get("subject", ()))
        bot.recon.append(("tls", f"{ver}, {subj.get('commonName', host)}, "
                                 f"expires in {int(days)}d"))
        if days <= 21:
            bot.add("tls-expiry", url=bot.t.base, severity="HIGH" if days <= 7 else "MEDIUM",
                    evidence=f"notAfter {cert['notAfter']} ({int(days)} days left)",
                    verify=lambda: True)
        sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        if host not in sans and not any(
                h.startswith("*.") and host.endswith(h[1:]) for h in sans):
            bot.add("tls-unverified", url=bot.t.base,
                    evidence=f"CN {subj.get('commonName')} SANs {sans[:5]}")
    except ssl.SSLCertVerificationError as e:
        bot.add("tls-unverified", url=bot.t.base, evidence=str(e)[:200])
        try:
            pem = ssl.get_server_certificate((host, port))
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(pem.encode())
            days = (cert.not_valid_after_utc.timestamp() - time.time()) / 86400
            if days <= 21:
                bot.add("tls-expiry", url=bot.t.base,
                        severity="HIGH" if days <= 7 else "MEDIUM",
                        evidence=f"notAfter {cert.not_valid_after_utc.isoformat()} "
                                 f"({int(days)} days left)", verify=lambda: True)
        except Exception as e2:
            bot.note(f"certificate expiry unreadable: {e2}")
        return
    except (OSError, ssl.SSLError) as e:
        bot.note(f"TLS probe failed: {e}")
        return
    # legacy protocol acceptance
    for label, mn, mx in (("TLS 1.0", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
                          ("TLS 1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1)):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version, ctx.maximum_version = mn, mx
            with socket.create_connection((host, port),
                                          timeout=bot.args.timeout) as s:
                with ctx.wrap_socket(s) as ts:
                    ts.version()
            bot.add("tls-legacy", url=bot.t.base, evidence=f"{label} handshake accepted",
                    verify=lambda: True)
        except (OSError, ssl.SSLError, ValueError):
            pass


EXPOSURES = [
    ("/.git/HEAD", r"ref:\s+refs/heads/", "exp-git", "git HEAD ref"),
    ("/.git/config", r"\[core\]|repositoryformatversion", "exp-git", "git config"),
    ("/.env", r"(?m)^[A-Za-z_][A-Za-z0-9_]*\s*=", "exp-env", "env assignments"),
    ("/.env.local", r"(?m)^[A-Za-z_][A-Za-z0-9_]*\s*=", "exp-env", "env assignments"),
    ("/.env.production", r"(?m)^[A-Za-z_][A-Za-z0-9_]*\s*=", "exp-env", "env assignments"),
    ("/.aws/credentials", r"\[default\]", "exp-aws", "aws credentials block"),
    ("/web.config", r"<system\.webServer|<appSettings", "exp-config", "IIS config"),
    ("/.htaccess", r"(?i)rewriteengine|deny from|addtype", "exp-config", "htaccess"),
    ("/config.json", r"(?i)\"(db|secret|password|private)\"", "exp-config", "config keys"),
    ("/config.yml", r"(?i)(password|secret|key):", "exp-config", "config keys"),
    ("/package.json", r"\"(dependencies|scripts)\"\s*:", "exp-deps", "manifest"),
    ("/composer.json", r"\"(require|scripts)\"\s*:", "exp-deps", "manifest"),
    ("/server-status", r"Apache Server Status|Server Version:", "exp-debug-endpoint", "apache status"),
    ("/server-info", r"Server Configuration|Compiled Modules", "exp-debug-endpoint", "apache info"),
    ("/phpinfo.php", r"phpinfo\(\)|PHP Version", "exp-debug-endpoint", "phpinfo"),
    ("/actuator/env", r"\"activeProfiles\"|\"propertySources\"", "exp-debug-endpoint", "actuator env"),
    ("/actuator/health", r"\"status\"\s*:\s*\"UP\"", "exp-debug-endpoint", "actuator health"),
    ("/debug/default/view", r"\"framework\"|Yii|yii2", "exp-debug-endpoint", "debug view"),
    ("/console", r"(?i)django|laravel|symfony.*debug", "exp-debug-endpoint", "console"),
    ("/backup.zip", None, "exp-backup", "zip magic"),
    ("/site.tar.gz", None, "exp-backup", "gzip magic"),
    ("/dump.sql", None, "exp-backup", "sql dump"),
    ("/.DS_Store", None, "exp-config", "ds_store"),
    ("/id_rsa", r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----", "exp-keyfile", "private key"),
    ("/openapi.json", r'"openapi"\s*:|"swagger"\s*:', "exp-api-docs", "openapi spec"),
    ("/swagger.json", r'"swagger"\s*:|"openapi"\s*:', "exp-api-docs", "swagger spec"),
    ("/api-docs", r'"swagger"|"openapi"', "exp-api-docs", "api docs"),
    ("/phpmyadmin/", r"(?i)phpmyadmin", "exp-admin-panel", "phpmyadmin"),
    ("/adminer.php", r"(?i)adminer", "exp-admin-panel", "adminer"),
    ("/manager/html", r"(?i)tomcat", "exp-admin-panel", "tomcat manager"),
    ("/elmah.axd", r"(?i)elmah|errorlog", "exp-debug-endpoint", "elmah"),
    ("/trace.axd", r"(?i)web.*request|trace", "exp-debug-endpoint", "aspnet trace"),
    ("/actuator/mappings", r'"(handler|uri|pattern)"\s*:', "exp-debug-endpoint", "actuator mappings"),
    ("/debug/pprof/", r"(?i)goroutine|pprof", "exp-debug-endpoint", "go pprof"),
    ("/.svn/entries", r"(?i)dir|svn", "exp-config", "svn entries"),
]


class Calibration:
    """Learned "this route does not exist" profile.

    Probes N=5 random paths under the target root, keeps the modal status
    plus a body fingerprint (length bucket of about 15 percent, normalized
    body similarity at or above 0.90), and uses the real target response as
    a negative control: if the target itself looks like the not-found page,
    the profile is flagged as untrustworthy instead of silently swallowing
    every finding.

    In passive mode (no --i-own-this) it sends NOTHING and reuses one
    already-fetched response, so a passive scan never probes the target.
    """

    PROBES = 5
    SIM_MIN = 0.90
    LEN_TOL = 0.15
    LEN_FLOOR = 64          # never call a 10-byte page "same length" as 10k

    def __init__(self, bot):
        self.bot = bot
        self.mode = "unlearned"
        self.status = None
        self.length = 0
        self.body = ""
        self.samples = 0
        self.probes_sent = 0
        self.target_matches = None
        self.detail = "not learned yet"

    @property
    def ready(self):
        return self.status is not None

    @property
    def tolerance(self):
        return max(self.LEN_FLOOR, int(self.length * self.LEN_TOL))

    def learn(self):
        if self.ready:
            return self
        if self.bot.replay or not getattr(self.bot.args, "i_own_this", False):
            return self._learn_reuse()
        return self._learn_active()

    def _learn_active(self):
        bot = self.bot
        samples = []
        for _ in range(self.PROBES):
            r = bot.get(bot.t.base + "/qx-cal-" + secrets.token_hex(5))
            self.probes_sent += 1
            if r is not None and r.body:
                samples.append(r)
        if not samples:
            self.mode = "active"
            self.detail = (f"all {self.PROBES} calibration probes failed, "
                           f"soft-404 detection disabled")
            return self
        tally = {}
        for r in samples:
            tally[r.status] = tally.get(r.status, 0) + 1
        if len(tally) > 1:
            bot.note(f"calibration probes disagreed on status: "
                     f"{dict(sorted(tally.items()))}, using the most common one")
        self.status = max(sorted(tally), key=lambda k: tally[k])
        modal = [r for r in samples if r.status == self.status]
        self.length = sorted(len(r.body) for r in modal)[len(modal) // 2]
        self.body = norm(modal[0].text)[:6000]
        self.samples = len(samples)
        self.mode = "active"
        self.detail = (f"{self.samples} probes, status {self.status}, "
                       f"body about {self.length}B (+/-{self.tolerance})")
        self._control()
        bot.recon.append(("calibration", self.summary()))
        return self

    def _learn_reuse(self):
        """Passive mode: one already-fetched response, zero new requests."""
        bot = self.bot
        pick = None
        for r in bot.pages.values():
            if r.status >= 400:
                pick = r
                break
        self.mode = "passive-reuse"
        if pick is None:
            self.detail = ("passive mode: no not-found response was captured, "
                           "soft-404 detection stays off")
            return self
        self.status = pick.status
        self.length = len(pick.body)
        self.body = norm(pick.text)[:6000]
        self.samples = 1
        self.detail = (f"passive mode: reused one stored HTTP {self.status} "
                       f"response, 0 probes sent")
        if bot.replay:
            return self
        bot.recon.append(("calibration", self.summary()))
        return self

    def _control(self):
        """Negative control: the real target must not look like a 404."""
        bot = self.bot
        r = bot.pages.get(bot.t.base + bot.t.path)
        if r is None:
            return
        self.target_matches = bool(self.is_not_found(r))
        if self.target_matches:
            bot.note("calibration: the target itself matches the not-found "
                     "profile, treat every result as suspect")

    def is_not_found(self, resp):
        if resp is None or not self.ready:
            return False
        if self.status != 200:
            return resp.status == self.status
        # A 200-shaped not-found page is only "not found" when the body also
        # matches: a bare status match would label every real page as missing.
        return resp.status == 200 and self._body_match(resp)

    def _body_match(self, resp):
        if not self.body:
            return False
        if abs(len(resp.body) - self.length) > self.tolerance:
            return False
        ratio = difflib.SequenceMatcher(
            None, norm(resp.text[:6000]), self.body).ratio()
        return ratio >= self.SIM_MIN

    def summary(self):
        return (f"{self.mode}, status {self.status}, body about {self.length}B, "
                f"sim >= {self.SIM_MIN:.2f}, {self.probes_sent} probes")

    def profile(self):
        return {"mode": self.mode, "status": self.status,
                "length": self.length, "length_tolerance": self.tolerance,
                "similarity_min": self.SIM_MIN, "samples": self.samples,
                "probes_sent": self.probes_sent,
                "target_matches_profile": self.target_matches,
                "detail": self.detail}

GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql")


def check_graphql(bot):
    q = urllib.parse.quote("{__schema{types{name}}}")
    for path in GRAPHQL_PATHS:
        url = bot.t.base + path + "?query=" + q
        r = bot.get(url)
        if r is None or r.status != 200:
            continue
        t = r.text
        if "__schema" in t or "__Type" in t:
            def vfy(u=url):
                rr = bot.get(u)
                return rr is not None and rr.status == 200 and \
                    "__schema" in rr.text
            bot.add("graphql-introspection", url=bot.t.base + path,
                    evidence=f"introspection answered, {len(t)}B: "
                             f"{t[:160].replace(chr(10), ' ')}", verify=vfy)
            return
        bot.note(f"{path} answered {r.status} without schema "
                 f"(verify manually if it is a real endpoint)")


def check_exposures(bot):
    for path, sig, check_id, label in EXPOSURES:
        url = bot.t.base + path
        try:
            r = bot.get(url)
        except BudgetExceeded:
            raise
        if r is None or r.status != 200 or not r.body:
            continue
        if bot.calibration.is_not_found(r):
            continue
        head = r.body[:4096]
        if check_id == "exp-backup":
            magics = {"/backup.zip": b"PK", "/site.tar.gz": b"\x1f\x8b",
                      "/dump.sql": (b"CREATE TABLE", b"INSERT INTO", b"--")}
            want = magics.get(path)
            ok = head.startswith(want) if isinstance(want, bytes) else \
                any(m in head for m in want)
            if not ok:
                continue
        elif path == "/.DS_Store":
            if not head.startswith(b"\x00\x00\x00\x01Bud1") and b"Bud1" not in head[:64]:
                continue
        else:
            m = re.search(sig, head.decode("utf-8", "replace")) if sig else None
            if not m:
                continue
        def vfy(u=url):
            rr = bot.get(u)
            return rr is not None and rr.status == 200 and bool(rr.body)
        if check_id == "exp-api-docs":
            # keep the document itself, so check_api_states can walk the
            # paths it declares instead of re-discovering the spec
            bot.api_docs[url] = r.text
        # keep the response so the whole-corpus sweep sees exposure files too
        bot.pages.setdefault(url, r)
        bot.add(check_id, url=url, evidence=f"{label}: {r.header('content-type')} "
                f"{len(r.body)}B, status {r.status}", verify=vfy)
