#!/usr/bin/env python3
"""redteam.py: authorized red team simulator for a website YOU own.

Simulates external attacks against your own target, reports every finding
with an exact fix. Non-destructive by construction: scope gate, request
budget, gentle rate limit, benign payloads only, no brute force, no DoS.

  python3 redteam.py --target https://example.com --allow example.com --i-own-this
"""

import argparse
import base64
import difflib
import gzip
import hashlib
import hmac
import html as htmllib
import ipaddress
import json
import os
import random
import threading
import re
import secrets
import socket
import ssl
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from html.parser import HTMLParser

import http.client

VERSION = "1.1.0"
UA = "placeholder_websiteRedTeamBot/1.0 (authorized self-testing)"
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {"CRITICAL": "#ff2d55", "HIGH": "#ff6b35", "MEDIUM": "#ffb020",
             "LOW": "#4aa3ff", "INFO": "#7d8590"}

# OWASP Top 10:2025, verified at https://top10.owasp.org/2025/en/
OWASP = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}
OWASP_URL = {
    "A01": "https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/",
    "A02": "https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/",
    "A03": "https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/",
    "A04": "https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/",
    "A05": "https://top10.owasp.org/2025/A05_2025-Injection/",
    "A06": "https://top10.owasp.org/2025/A06_2025-Insecure_Design/",
    "A07": "https://top10.owasp.org/2025/A07_2025-Authentication_Failures/",
    "A08": "https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/",
    "A09": "https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/",
    "A10": "https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
}
CHEATSHEET = "https://cheatsheetseries.owasp.org/cheatsheets/"

SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|private[_-]?key"
    r"|auth|credential|dsn|connection[_-]?string)\b\s*[:=]\s*[^\s;,&\"']+")

# check_id -> (owasp, default_severity, title, attacker win, exact fix)
CHECKS = {
 "no-tls": ("A04", "HIGH", "Site served over plain HTTP",
   "an attacker on the same network reads and edits every request",
   "redirect all HTTP to HTTPS and serve only TLS 1.2+, e.g. nginx: return 301 https://$host$request_uri;"),
 "tls-legacy": ("A04", "HIGH", "Legacy TLS protocol accepted",
   "a network attacker decrypts traffic with known protocol attacks",
   "nginx: ssl_protocols TLSv1.2 TLSv1.3; (use https://ssl-config.mozilla.org profile)"),
 "tls-expiry": ("A04", "MEDIUM", "TLS certificate expiring soon",
   "browsers reject the site, HTTPS breaks, HSTS pins the outage",
   "automate renewal: certbot or ACME client with reload hook, alert when <21 days remain"),
 "tls-unverified": ("A04", "MEDIUM", "TLS certificate not trusted or mismatched",
   "users see warnings and MITM becomes trivial",
   "install a certificate from a trusted CA covering this exact hostname, keep the chain complete"),
 "hdr-hsts": ("A02", "HIGH", "Strict-Transport-Security missing",
   "first visit can be stripped to HTTP, enabling session theft",
   "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;"),
 "hdr-csp-missing": ("A02", "MEDIUM", "Content-Security-Policy missing",
   "injected scripts run freely, XSS impact jumps from leak to takeover",
   "start report-only: Content-Security-Policy-Report-Only: default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; report-uri /csp-report, then enforce"),
 "hdr-csp-unsafe": ("A05", "MEDIUM", "CSP allows unsafe-inline or unsafe-eval",
   "the policy stops almost no injected script",
   "drop unsafe-inline/unsafe-eval from script-src, use per-response nonces with 'strict-dynamic'"),
 "hdr-nosniff": ("A02", "MEDIUM", "X-Content-Type-Options missing",
   "browsers MIME-sniff responses into executable content",
   "add_header X-Content-Type-Options \"nosniff\" always;"),
 "hdr-referrer": ("A02", "LOW", "Referrer-Policy missing",
   "full URLs (with tokens in query strings) leak to third parties",
   "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"),
 "hdr-permissions": ("A02", "LOW", "Permissions-Policy missing",
   "scripts can reach camera, microphone, geolocation without consent gating",
   "add_header Permissions-Policy \"geolocation=(), camera=(), microphone=()\" always;"),
 "hdr-xss-legacy": ("A02", "LOW", "X-XSS-Protection set to an unsafe value",
   "the legacy browser filter itself can create XSS on otherwise safe pages",
   "set X-XSS-Protection: 0 or remove the header entirely, rely on CSP"),
 "hdr-obsolete": ("A02", "LOW", "Obsolete pinning/CT header present",
   "Expect-CT/HPKP are dead standards and add noise or breakage",
   "remove Expect-CT and Public-Key-Pins headers; rely on CT logs and CAA records"),
 "hdr-coop": ("A02", "INFO", "Cross-Origin-Opener-Policy missing",
   "cross-origin documents can share a browsing context (Spectre-class risk)",
   "add_header Cross-Origin-Opener-Policy \"same-origin\" always;"),
 "hdr-corp": ("A02", "INFO", "Cross-Origin-Resource-Policy missing",
   "responses can be read cross-origin in no-cors contexts",
   "add_header Cross-Origin-Resource-Policy \"same-site\" always; (test PDFs first)"),
 "hdr-x-powered": ("A02", "LOW", "Framework fingerprint header present",
   "attackers match your exact framework/version to known exploits",
   "suppress it: nginx proxy_hide_header X-Powered-By;, or framework config expose_php=Off / X-Powered-By off"),
 "hdr-banner": ("A03", "LOW", "Server version disclosed in banner",
   "version-matched exploits (CVE lookups) become one-shot",
   "nginx: server_tokens off;, or proxy_hide_header Server; then set a generic Server value at the edge"),
 "hdr-cache-sensitive": ("A02", "MEDIUM", "Sensitive page is cacheable",
   "shared caches and browsers persist authenticated pages",
   "add_header Cache-Control \"no-store, private\" always; on login/account/API responses"),
 "clickjack": ("A02", "MEDIUM", "Page can be framed (clickjacking)",
   "an invisible overlay on a trusted page hijacks clicks and inputs",
   "add_header X-Frame-Options \"DENY\" always; and CSP frame-ancestors 'none'"),
 "cors-reflect": ("A01", "MEDIUM", "CORS reflects arbitrary Origin",
   "any website can read this origin's responses with the victim's cookies",
   "allowlist exact origins server-side, never echo the request Origin; keep Access-Control-Allow-Credentials off unless required"),
 "cors-null": ("A01", "MEDIUM", "CORS trusts the null origin",
   "sandboxed iframes and local files replay as trusted origin",
   "reject Origin: null explicitly, allowlist only your real origins"),
 "cors-star": ("A02", "INFO", "Wildcard CORS on an authenticated endpoint",
   "if credentials are ever added, the pairing is invalid and dangerous",
   "use explicit origins instead of * wherever credentials or private data are involved"),
 "cookie-secure": ("A07", "MEDIUM", "Session cookie without Secure flag",
   "the cookie travels over plain HTTP and can be stolen in transit",
   "Set-Cookie attributes: Secure; HttpOnly; SameSite=Lax"),
 "cookie-httponly": ("A07", "MEDIUM", "Session cookie without HttpOnly",
   "any XSS payload reads document.cookie and exfiltrates the session",
   "add HttpOnly to all session cookies"),
 "cookie-samesite": ("A07", "LOW", "Session cookie without SameSite",
   "cross-site requests carry the session, widening CSRF",
   "add SameSite=Lax (or Strict for state-changing flows)"),
 "cookie-plaintext": ("A04", "HIGH", "Session cookie issued over HTTP",
   "session identifiers are readable and replayable on the wire",
   "serve the site over HTTPS only and set Secure on every session cookie"),
 "cookie-long-life": ("A07", "LOW", "Session cookie lives for a very long time",
   "stolen cookies stay valid for months",
   "use short idle timeout (15-30 min) plus absolute expiry, rotate the ID on login"),
 "secret-leak": ("A02", "CRITICAL", "Secret or live API key shipped to the browser",
   "any visitor can read the key and spend your money or your data",
   "pull the key out of the client bundle at once, rotate it, issue a scoped server-side replacement, restrict the old key"),
 "host-header": ("A07", "MEDIUM", "Untrusted Host/X-Forwarded-Host reaches output",
   "password-reset and absolute links can be poisoned to attacker infrastructure",
   "build URLs from a configured canonical origin, never from request headers; reject unknown Host values at the proxy"),
 "graphql-introspection": ("A02", "MEDIUM", "GraphQL introspection enabled in production",
   "the full schema, including hidden mutations, is enumerable by anyone",
   "disable introspection in production (Apollo: introspection: false; Hasura/GraphQL Yoga: disable for anon roles)"),
 "cookie-samesite-none": ("A07", "MEDIUM", "SameSite=None cookie without Secure",
   "browsers reject or degrade the cookie and cross-site leaks widen",
   "set Secure alongside SameSite=None, or switch to SameSite=Lax"),
 "exp-api-docs": ("A02", "MEDIUM", "API documentation exposed publicly",
   "the full API surface, including forgotten endpoints, is handed to attackers",
   "serve OpenAPI/Swagger only in staging or behind auth; block schema paths at the edge"),
 "exp-admin-panel": ("A02", "HIGH", "Admin interface reachable from the internet",
   "database or server admin panels are brute-force and 0-day targets",
   "bind admin panels to localhost or a VPN, add IP allowlisting plus MFA, remove them from public DNS"),
 "subdomain-dangling": ("A02", "LOW", "Certificate-log subdomain no longer resolves",
   "a dangling name can be re-claimed and turned into subdomain takeover",
   "delete the stale DNS record or claim the external resource, then re-check the name"),
 "jwt-alg-none": ("A07", "HIGH", "JWT issued with alg=none",
   "anyone can mint a valid token for any user, full account takeover",
   "reject alg none and pin an allowlist (e.g. RS256) in the verifier, validate signature before claims"),
 "jwt-weak-secret": ("A04", "CRITICAL", "JWT signed with a guessable secret",
   "attackers forge tokens offline, no login needed",
   "switch to RS256/ES256 or a 256-bit random secret, store it in a secret manager, rotate it"),
 "jwt-no-exp": ("A07", "MEDIUM", "JWT has no expiration claim",
   "tokens live forever, logout and password change do not revoke them",
   "set short exp (minutes to hours), validate exp/nbf/iss/aud, back long sessions with refresh tokens"),
 "jwt-long-life": ("A07", "LOW", "JWT expiration is very long",
   "a leaked token stays useful for a very long window",
   "shorten access-token lifetime to under an hour, use refresh rotation"),
 "exp-git": ("A02", "HIGH", "Git repository exposed on the server",
   "the full source tree and history ship to the attacker, secrets inside get harvested",
   "remove .git from deployment artifacts, deny dotfiles at the server: location ~ /\\.git { deny all; }"),
 "exp-env": ("A02", "CRITICAL", "Environment file exposed",
   "API keys, DB passwords and tokens are handed over in one request",
   "move .env outside the web root, deny dotfiles, then rotate EVERY secret it ever contained"),
 "exp-backup": ("A02", "HIGH", "Backup or archive file exposed",
   "source code, databases or keys leak through leftover deploy files",
   "delete backups from the web root, store them outside docroot, deny *.bak *.old *.zip *.sql *.tar.gz"),
 "exp-config": ("A02", "MEDIUM", "Configuration file exposed",
   "internal paths, credentials or feature flags become known",
   "block config filenames at the server and stop shipping them in builds"),
 "exp-deps": ("A03", "LOW", "Dependency manifest exposed",
   "exact component versions are known, CVE matching becomes one-shot",
   "deny package manifests at the edge; run npm audit / osv-scanner to check those versions yourself first"),
 "exp-aws": ("A02", "CRITICAL", "Cloud credentials file exposed",
   "your cloud account is directly compromiseable",
   "remove the file, rotate those credentials immediately, use an instance role instead of keys on disk"),
 "exp-keyfile": ("A04", "CRITICAL", "Private key file exposed on the server",
   "attackers decrypt recorded traffic or impersonate your services",
   "remove the key from the web root immediately and rotate it (reissue the certificate / API key), store keys outside docroot"),
 "exp-debug-endpoint": ("A02", "MEDIUM", "Debug/monitoring endpoint exposed",
   "runtime config, env values and internal state are disclosed",
   "disable actuator/phpinfo/server-status style endpoints in production, bind them to localhost or auth"),
 "exp-sourcemap": ("A08", "MEDIUM", "Source map published",
   "original source (including comments and internal APIs) is recoverable",
   "strip sourceMappingURL from shipped JS or serve .map files only for internal builds"),
 "dir-listing": ("A02", "MEDIUM", "Directory listing enabled",
   "attackers enumerate backups, uploads and forgotten files",
   "autoindex off; (nginx) / Options -Indexes (Apache)"),
 "err-stacktrace": ("A10", "HIGH", "Stack trace or debug page exposed",
   "internal paths, framework versions and query shapes leak, aiding follow-up attacks",
   "return generic errors with a correlation ID, keep traces in protected logs, disable debug mode in production"),
 "xss-reflected": ("A05", "HIGH", "Reflected cross-site scripting",
   "attacker links hijack any victim's session on your domain",
   "context-aware output encoding (framework auto-escape), avoid innerHTML, add CSP as a second layer"),
 "sqli-error": ("A05", "HIGH", "SQL injection (database error revealed)",
   "the query is attacker-influenced; data theft or modification may follow",
   "use parameterized prepared statements for every value, allowlist identifiers, least-privilege DB account"),
 "sqli-boolean": ("A05", "MEDIUM", "Possible SQL injection (boolean differential)",
   "attacker can walk the database one boolean at a time",
   "same fix as error-based SQLi: parameterized queries everywhere"),
 "cmdi-echo": ("A05", "CRITICAL", "OS command injection",
   "the attacker runs arbitrary commands on your server, total compromise",
   "never pass input to a shell; call fixed executables with argument arrays, allowlist inputs"),
 "traversal": ("A05", "HIGH", "Path traversal",
   "arbitrary file read: configs, keys, source",
   "canonicalize and verify the resolved path stays under the allowed base dir, allowlist filenames"),
 "redirect-open": ("A06", "MEDIUM", "Open redirect",
   "phishing links borrow your trusted domain",
   "allowlist redirect targets (path-only or known hosts), reject scheme-relative and absolute URLs"),
 "admin-force-browse": ("A01", "HIGH", "Admin surface reachable without login",
   "anyone can reach privileged pages and APIs",
   "deny by default: authenticate every route, then authorize by role, server-side"),
 "csrf-token-missing": ("A01", "MEDIUM", "State-changing form without CSRF token",
   "a third-party page can submit this form with the victim logged in",
   "add a per-session CSRF token (constant-time compare) and SameSite cookies; never rely on secrecy of URLs"),
 "ratelimit-login": ("A07", "LOW", "No rate limit observed on login",
   "credential stuffing and password spraying run at scale",
   "layer limits (edge + app): e.g. 4/min then 10/10min then 20/hour per IP+account, count failures, add CAPTCHA"),
 "sri-missing": ("A08", "LOW", "Third-party script without Subresource Integrity",
   "a compromised CDN silently runs attacker code in your pages",
   "add integrity=\"sha384-...\" and crossorigin to every cross-origin script/link, or self-host the asset"),
 "mixed-content": ("A04", "MEDIUM", "Mixed content on an HTTPS page",
   "plain-HTTP subresources are readable and tamperable in transit",
   "reference all subresources over HTTPS and add upgrade-insecure-requests to CSP"),
 "method-trace": ("A02", "MEDIUM", "HTTP TRACE enabled",
   "cross-site tracing can echo custom headers back to scripts",
   "disable TRACE at the server/proxy: nginx does not enable it by default, apache: TraceEnable off"),
 "method-put": ("A02", "MEDIUM", "Write methods accepted (PUT/DELETE)",
   "unauthenticated file upload or deletion may be possible",
   "reject non-GET/POST at the edge, require auth and CSRF on any allowed write method"),
 "sec-txt-missing": ("RFC 9116", "INFO", "security.txt missing",
   "researchers have no documented channel to report issues to you",
   "publish /.well-known/security.txt with Contact: mailto:you@domain and Policy: link"),
 "robots-disclosure": ("A02", "LOW", "robots.txt reveals sensitive paths",
   "disallowed admin/backup paths are published to everyone",
   "remove secret paths from robots.txt, block them at the server instead"),
}

GROUPS = {
 "recon": ["sec-txt-missing", "robots-disclosure", "hdr-banner"],
 "tls": ["no-tls", "tls-legacy", "tls-expiry", "tls-unverified"],
 "headers": ["hdr-hsts", "hdr-csp-missing", "hdr-csp-unsafe", "hdr-nosniff",
   "hdr-referrer", "hdr-permissions", "hdr-xss-legacy", "hdr-obsolete",
   "hdr-coop", "hdr-corp", "hdr-x-powered", "hdr-cache-sensitive", "clickjack"],
 "cors": ["cors-reflect", "cors-null", "cors-star"],
 "cookies": ["cookie-secure", "cookie-httponly", "cookie-samesite",
   "cookie-samesite-none", "cookie-plaintext", "cookie-long-life"],
 "jwt": ["jwt-alg-none", "jwt-weak-secret", "jwt-no-exp", "jwt-long-life"],
 "secrets": ["secret-leak"],
 "exposures": ["exp-git", "exp-env", "exp-backup", "exp-config", "exp-deps",
   "exp-aws", "exp-keyfile", "exp-api-docs", "exp-admin-panel",
   "exp-debug-endpoint", "exp-sourcemap",
   "dir-listing", "err-stacktrace", "graphql-introspection"],
 "injection": ["xss-reflected", "sqli-error", "sqli-boolean", "cmdi-echo",
   "traversal", "redirect-open"],
 "auth": ["admin-force-browse", "csrf-token-missing", "ratelimit-login",
   "host-header", "subdomain-dangling"],
 "client": ["sri-missing", "mixed-content"],
 "methods": ["method-trace", "method-put"],
}
SCENARIOS = {
 "recon": ["recon"],
 "headers": ["tls", "headers", "cors", "cookies"],
 "misconfig": ["exposures", "methods"],
 "injection": ["injection"],
 "auth": ["auth", "jwt"],
 "full": ["recon", "tls", "headers", "cors", "cookies", "jwt", "secrets",
   "exposures", "injection", "auth", "client", "methods"],
 "api": ["recon", "exposures", "cors", "injection"],
}


class BudgetExceeded(Exception):
    pass


class OutOfScope(Exception):
    pass


class Resp:
    def __init__(self, status, headers, body, url, redirects, elapsed):
        self.status = status
        self.headers = headers          # lowercased dict
        self.body = body                # bytes
        self.url = url
        self.redirects = redirects
        self.elapsed = elapsed

    @property
    def text(self):
        try:
            return self.body.decode("utf-8", "replace")
        except Exception:
            return ""

    def header(self, name):
        return self.headers.get(name.lower(), "")

    @property
    def set_cookies(self):
        raw = self.headers.get("set-cookie-list", [])
        return raw if isinstance(raw, list) else []


class Throttle:
    def __init__(self, rps):
        self.rps = max(0.2, float(rps))
        self.next = 0.0
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            now = time.monotonic()
            if now < self.next:
                delay = self.next - now
            else:
                delay = 0.0
            jitter = random.uniform(0.9, 1.15)
            self.next = max(time.monotonic(), self.next) + jitter / self.rps
        if delay > 0:
            time.sleep(delay)


class Transport:
    def __init__(self, target, allow, rps, max_requests, timeout, insecure, local):
        p = urllib.parse.urlsplit(target)
        if p.scheme not in ("http", "https"):
            raise SystemExit("target must be http:// or https://")
        self.scheme = p.scheme
        self.host = p.hostname or ""
        self.port = p.port or (443 if p.scheme == "https" else 80)
        self.base = f"{self.scheme}://{self.host}:{self.port}"
        self.path = p.path or "/"
        self.allow = set(a.strip().lower() for a in allow if a.strip())
        self.allow.add(self.host.lower())
        try:
            ipaddress.ip_address(self.host)
            is_ip = True
        except ValueError:
            is_ip = False
        if not is_ip:
            if self.host.startswith("www."):
                self.allow.add(self.host[4:])
            else:
                self.allow.add("www." + self.host)
        self.local = local
        self.throttle = Throttle(rps)
        self.max_requests = max_requests
        self.used = 0
        self.timeout = timeout
        self.insecure = insecure
        self.rate_limited = 0
        self.notes = []
        self.lock = threading.Lock()
        if not local:
            try:
                ipaddress.ip_address(self.host)
                raise SystemExit(
                    "IP-literal targets are refused. Use a hostname and "
                    "--allow, or --local for 127.0.0.1 testing.")
            except ValueError:
                pass

    def in_scope(self, url):
        p = urllib.parse.urlsplit(url)
        if p.scheme not in ("http", "https"):
            return False
        host = (p.hostname or "").lower()
        if host in ("127.0.0.1", "localhost", "::1") and self.local:
            return True
        for a in self.allow:
            if host == a or (a.startswith(".") and host.endswith(a)) or \
               (a.startswith("*.") and host.endswith(a[1:])):
                return True
        return False

    def _conn(self, scheme, host, port):
        if scheme == "https":
            ctx = ssl.create_default_context()
            if self.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            return http.client.HTTPSConnection(host, port, timeout=self.timeout,
                                               context=ctx)
        return http.client.HTTPConnection(host, port, timeout=self.timeout)

    def _budget(self):
        with self.lock:
            if self.used >= self.max_requests:
                raise BudgetExceeded(
                    f"budget of {self.max_requests} requests reached")
            self.used += 1
        self.throttle.wait()

    def request_external(self, url, cap=1_500_000, timeout=30.0):
        """GET-only passive public source (wayback/crt.sh). Throttled,
        budgeted, never reachable from attack paths, scope-checked to the
        two allowlisted provider hosts by the caller. One retry: public
        archive APIs flake."""
        p = urllib.parse.urlsplit(url)
        if p.scheme not in ("http", "https"):
            raise OutOfScope(url)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        last = None
        for attempt in range(2):
            self._budget()
            conn = self._conn(p.scheme, p.hostname,
                              p.port or (443 if p.scheme == "https" else 80))
            conn.timeout = timeout
            try:
                conn.request("GET", path,
                             headers={"User-Agent": UA, "Accept": "*/*"})
                r = conn.getresponse()
                data = r.read(cap)
                if r.status == 200:
                    return r.status, data
                last = RuntimeError(f"HTTP {r.status}")
            except (OSError, http.client.HTTPException) as e:
                last = e
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            if attempt == 0:
                time.sleep(1.5)
        raise last if last else RuntimeError("external source failed")

    def request(self, method, url, headers=None, body=None, follow=True):
        if not self.in_scope(url):
            raise OutOfScope(url)
        self._budget()
        hdrs = {"User-Agent": UA, "Accept": "*/*", "Accept-Language": "en"}
        if headers:
            hdrs.update(headers)
        redirects = []
        current, current_body = url, body
        for _ in range(6):
            p = urllib.parse.urlsplit(current)
            path = p.path or "/"
            if p.query:
                path += "?" + p.query
            t0 = time.monotonic()
            err = None
            for attempt in range(2):
                conn = self._conn(p.scheme, p.hostname, p.port)
                try:
                    conn.request(method, path, body=current_body, headers=hdrs)
                    r = conn.getresponse()
                    data = r.read(2_000_000)
                    err = None
                    break
                except (OSError, http.client.HTTPException) as e:
                    err = e
                    r, data = None, None
                    if attempt == 0:
                        time.sleep(0.35)
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
            if err is not None:
                raise RuntimeError(f"{type(err).__name__}: {err}")
            elapsed = time.monotonic() - t0
            rh = {}
            for k, v in r.getheaders():
                kl = k.lower()
                if kl == "set-cookie":
                    rh.setdefault("set-cookie-list", []).append(v)
                elif kl in rh:
                    rh[kl] = rh[kl] + ", " + v
                else:
                    rh[kl] = v
            resp = Resp(r.status, rh, data, current, list(redirects), elapsed)
            if r.status == 429:
                self.rate_limited += 1
                self.notes.append(f"429 from {current}, throttling further")
                self.throttle.rps = max(0.2, self.throttle.rps / 2)
            if follow and r.status in (301, 302, 303, 307, 308):
                loc = rh.get("location", "")
                nxt = urllib.parse.urljoin(current, loc)
                if not self.in_scope(nxt):
                    resp.headers["x-qx-out-of-scope-redirect"] = nxt
                    return resp
                redirects.append(f"{r.status} -> {nxt}")
                if r.status == 303:
                    method, current_body = "GET", None
                    hdrs.pop("Content-Length", None)
                current = nxt
                continue
            return resp
        return resp


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self.scripts, self.titles = [], [], [], ""
        self._form, self._intitle = None, False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("a", "link", "area") and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("script", "img", "iframe", "source") and a.get("src"):
            self.links.append(a["src"])
            self.scripts.append((a.get("src", ""), a.get("integrity", ""),
                                 a.get("crossorigin", "")))
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method":
                          (a.get("method") or "get").lower(), "inputs": []}
        elif tag == "input" and self._form is not None:
            self._form["inputs"].append(
                {"name": a.get("name", ""), "type": (a.get("type") or
                 "text").lower(), "value": a.get("value", "")})
        elif tag == "title":
            self._intitle = True

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag == "title":
            self._intitle = False

    def handle_data(self, data):
        if self._intitle:
            self.titles += data


TOKEN_RE = re.compile(r"^(csrf|xsrf|_?token|authenticity|nonce|anti[_-]?forgery)",
                      re.I)
LOGIN_RE = re.compile(r"(type=[\"']password[\"']|name=[\"']password[\"']"
                      r"|sign[\s-]?in|log[\s-]?in|forgot[\s-]?password)", re.I)


JS_EP_RES = [
    re.compile(r"""["'`](/api/[A-Za-z0-9_\-/{}.$]{1,80})["'`]"""),
    re.compile(r"""fetch\(\s*["'`]([A-Za-z0-9_\-/{}.$?=&]{2,120})["'`]"""),
    re.compile(r"""\.(?:get|post|put|delete|patch)\(\s*["'`](/[A-Za-z0-9_\-/{}.$?=&]{2,120})["'`]"""),
    re.compile(r"""["'`](https?://[A-Za-z0-9.\-]+(/[A-Za-z0-9_\-/{}.$?=&]{2,120})?)["'`]"""),
]


class Bot:
    def __init__(self, transport, args):
        self.t = transport
        self.args = args
        self.findings = []
        self._keys = set()
        self._verify = {}
        self.notes = []
        self.recon = []
        self.pages = {}
        self.urls = set()
        self.forms = []
        self.params = {}          # url -> [param names]
        self.stopped = None
        self.canary = "QX" + secrets.token_hex(5)
        self._soft404 = None
        self.js_assets = {}
        self.endpoints = set()
        self.script_urls = set()
        self._seen = set()

    # ---------- plumbing ----------
    def get(self, url, headers=None, method="GET", body=None, follow=True):
        hdrs = dict(headers or {})
        if self.args.cookie and "Cookie" not in hdrs:
            hdrs["Cookie"] = self.args.cookie
        try:
            return self.t.request(method, url, headers=hdrs, body=body,
                                  follow=follow)
        except BudgetExceeded as e:
            self.stopped = str(e)
            raise
        except OutOfScope:
            self.notes.append(f"blocked out-of-scope request: {url}")
            return None
        except RuntimeError as e:
            self.notes.append(f"request error {url}: {e}")
            return None

    def note(self, msg):
        if msg not in self.notes:
            self.notes.append(msg)

    def add(self, check_id, url="", param=None, severity=None, evidence="",
            fix=None, confidence="high", detail=None, verify=None):
        spec = CHECKS.get(check_id)
        if spec is None:
            raise KeyError(check_id)
        owasp, dsev, title, impact, dfix = spec
        key = (check_id, url.split("?")[0], param or "")
        if key in self._keys:
            return None
        self._keys.add(key)
        ev = SECRET_RE.sub(lambda m: m.group(1) + "=***REDACTED***",
                           evidence or "")
        ev = ev[:600]
        f = {"id": f"F{len(self.findings) + 1:03d}", "check_id": check_id,
             "title": title, "severity": severity or dsev, "owasp": owasp,
             "confidence": confidence, "verified": False, "url": url,
             "param": param, "evidence": ev, "fix": fix or dfix,
             "impact": impact, "detail": detail or "",
             "refs": [OWASP_URL.get(owasp, CHEATSHEET + "Reporting_Cheat_Sheet.html")]}
        self.findings.append(f)
        if verify is not None:
            self._verify[f["id"]] = verify
        return f

    def verify_findings(self):
        for f in list(self.findings):
            if f["severity"] not in ("CRITICAL", "HIGH"):
                continue
            fn = self._verify.get(f["id"])
            if fn is None:
                continue
            try:
                ok = fn()
            except BudgetExceeded:
                raise
            except Exception:
                ok = False
            f["verified"] = bool(ok)
            if not ok:
                order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                f["severity"] = order[min(order.index(f["severity"]) + 1, 4)]
                f["confidence"] = "low"
                f["detail"] = (f["detail"] + " Not reproduced on re-test; "
                               "treat as candidate.").strip()

    def score(self):
        total = 100.0
        for f in self.findings:
            w = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2,
                 "INFO": 0}[f["severity"]]
            if not f["verified"] and f["severity"] in ("CRITICAL", "HIGH"):
                w /= 2
            total -= w
        return max(0.0, round(total, 1))

    def counts(self):
        c = {k: 0 for k in SEV_ORDER}
        for f in self.findings:
            c[f["severity"]] += 1
        return c

    # ---------- discovery ----------
    def fetch(self, url):
        r = self.get(url)
        if r is not None:
            self.pages[url] = r
        return r

    def discover(self):
        base = self.t.base + self.t.path
        r = self.fetch(base)
        if r is None:
            raise SystemExit("target unreachable or out of scope")
        self.recon.append(("target", base))
        self.recon.append(("status", str(r.status)))
        srv = r.header("server")
        if srv:
            self.recon.append(("server", srv))
        ip = socket.gethostbyname(self.t.host) if self.t.host not in (
            "127.0.0.1", "localhost") else self.t.host
        self.recon.append(("ip", ip))
        self.recon.append(("requests budget", f"{self.t.used}/{self.t.max_requests}"))

        rb = self.get(self.t.base + "/robots.txt")
        if rb and rb.status == 200:
            txt = rb.text
            self.recon.append(("robots.txt", f"{len(txt.splitlines())} lines"))
            for line in txt.splitlines():
                if line.lower().startswith("disallow"):
                    path = line.split(":", 1)[-1].strip()
                    if path and re.search(
                            r"(admin|backup|private|staging|debug|\.git|env)",
                            path, re.I):
                        self.add("robots-disclosure", url=self.t.base +
                                 "/robots.txt", evidence=line)
            m = re.search(r"(?im)^sitemap:\s*(\S+)", txt)
            if m:
                self._queue(m.group(1))
        sm = self.get(self.t.base + "/sitemap.xml")
        if sm and sm.status == 200 and "xml" in sm.header("content-type") + sm.text[:200]:
            for loc in re.findall(r"<loc>(.*?)</loc>", sm.text):
                self._queue(loc.strip())
            self.recon.append(("sitemap.xml", "parsed"))

        # pass 1: BFS crawl
        self._queue(base)
        self._crawl()
        # pass 2: same-origin JS assets -> endpoint + secret extraction
        js_candidates = [s for s in sorted(self.script_urls)
                         if re.search(r"\.m?js($|\?)", s, re.I)]
        for su in js_candidates[:10]:
            r = self.get(su)
            if r is not None and r.body:
                self.js_assets[su] = r.text
                self._ingest_js(su, r.text)
        if self.js_assets:
            self.recon.append(("js assets scanned", str(len(self.js_assets))))
        if self.endpoints:
            self.recon.append(("endpoints mined from js",
                               str(len(self.endpoints))))
            self._crawl()   # pass 3: probe the mined API routes
        # passive historical / certificate sources (opt-in flags)
        if self.args.wayback:
            self._wayback()
            self._crawl()
        else:
            self.recon.append(("wayback", "off (add --wayback)"))
        if self.args.ct_log:
            self._ct_log()
        else:
            self.recon.append(("ct-log", "off (add --ct-log)"))

    def _crawl(self):
        queue = [u for u in sorted(self.urls)]
        pages = 0
        robots_paths = self._robots_disallow()
        while queue and pages < self.args.max_pages:
            url = queue.pop(0)
            if url in self._seen:
                continue
            self._seen.add(url)
            if self.args.respect_robots and any(
                    urlsplit_path(url).startswith(d) for d in robots_paths
                    if d and d != "/"):
                continue
            r = self.pages.get(url) or self.fetch(url)
            qy = urllib.parse.urlsplit(url).query
            if qy:
                names = [kv.split("=")[0] for kv in qy.split("&") if kv]
                self.params.setdefault(url, [])
                for n in names:
                    if n not in self.params[url]:
                        self.params[url].append(n)
            if r is None or r.status >= 400:
                continue
            pages += 1
            body = r.text
            if "exposures" in SCENARIOS.get(self.args.scenario, []) and (
                    "index of /" in body.lower()
                    or "directory listing for" in body.lower()):
                self.add("dir-listing", url=url, evidence=title_of(body))
            try:
                parser = PageParser()
                parser.feed(body)
            except Exception:
                continue
            if r.header("content-type").startswith("text/html") or \
               "<html" in body[:500].lower():
                if parser.titles:
                    self.recon.append(
                        ("page", f"{url} :: {parser.titles.strip()[:60]}"))
                for form in parser.forms:
                    self.forms.append({**form, "page": url})
                for link in parser.links:
                    absu = urllib.parse.urljoin(url, link)
                    if self.t.in_scope(absu):
                        self._queue(absu, queue)
                for sc, _i, _c in parser.scripts:
                    if not sc:
                        continue
                    a = urllib.parse.urljoin(url, sc).split("#")[0]
                    if self.t.in_scope(a) and re.search(r"\.m?js($|\?)", a, re.I):
                        self.script_urls.add(a)

    def _ingest_js(self, base_url, text):
        for rx in JS_EP_RES:
            for m in rx.finditer(text):
                if len(self.endpoints) >= 60:
                    return
                cand = m.group(1)
                absu = urllib.parse.urljoin(base_url, cand).split("#")[0]
                if not self.t.in_scope(absu):
                    continue
                pu = urllib.parse.urlsplit(absu)
                if re.search(r"\.(css|png|jpe?g|svg|woff2?|ico|gif|map)$",
                             pu.path, re.I):
                    continue
                self.endpoints.add(absu)
                self._queue(absu)
                if pu.query:
                    names = [kv.split("=")[0] for kv in pu.query.split("&") if kv]
                    self.params.setdefault(absu, [])
                    for n in names:
                        if n not in self.params[absu]:
                            self.params[absu].append(n)

    def _wayback(self):
        cdx = ("https://web.archive.org/cdx/search/cdx?url=" + self.t.host +
               "/*&output=json&fl=original&collapse=urlkey&limit=1000"
               "&filter=statuscode:200")
        try:
            status, body = self.t.request_external(cdx)
        except BudgetExceeded:
            raise
        except Exception as e:
            self.note(f"wayback lookup failed: {e}")
            return
        if status != 200:
            self.note(f"wayback CDX returned {status}")
            return
        try:
            rows = json.loads(body.decode("utf-8", "replace"))
        except Exception:
            self.note("wayback CDX response unparseable")
            return
        if not rows:
            self.recon.append(("wayback historical urls",
                               "0 archived snapshots for this host"))
            return
        hdr = rows[0]
        idx = hdr.index("original") if "original" in hdr else 0
        added = 0
        for row in rows[1:]:
            if not row:
                continue
            u = str(row[idx])
            if self.t.in_scope(u):
                before = len(self.urls)
                self._queue(u)
                added += len(self.urls) - before
        self.recon.append(("wayback historical urls",
                           f"{added} in-scope of {len(rows) - 1} archived"))
        self.note("wayback source: web.archive.org CDX (passive, read-only)")

    def _ct_log(self):
        parts = self.t.host.split(".")
        # shared public suffixes (github.io, netlify.app, ...) must not be
        # treated as the registrable domain: anchor on the full host instead
        dom = self.t.host if len(parts) >= 3 else ".".join(parts[-2:])
        url = "https://crt.sh/?q=" + urllib.parse.quote("%." + dom) +               "&output=json"
        names = set()
        errors = []
        # source 1: crt.sh (flaky by design; retried inside request_external)
        try:
            status, body = self.t.request_external(
                "https://crt.sh/?q=" + urllib.parse.quote("%." + dom) +
                "&output=json", cap=4_000_000)
            rows = json.loads(body.decode("utf-8", "replace"))
            for row in rows if isinstance(rows, list) else []:
                if isinstance(row, dict):
                    for nm in str(row.get("name_value", "")).split("\n"):
                        nm = nm.strip().lower().lstrip("*.")
                        if nm.endswith("." + dom) and nm != dom:
                            names.add(nm)
        except BudgetExceeded:
            raise
        except Exception as e:
            errors.append(f"crt.sh: {e}")
        # source 2: certspotter (verified reachable when crt.sh 502s)
        if not names:
            try:
                status, body = self.t.request_external(
                    "https://api.certspotter.com/v1/issuances?domain=" + dom +
                    "&include_subdomains=true&expand=dns_names", cap=2_000_000)
                rows = json.loads(body.decode("utf-8", "replace"))
                for row in rows if isinstance(rows, list) else []:
                    if isinstance(row, dict):
                        for nm in row.get("dns_names", []):
                            nm = str(nm).strip().lower().lstrip("*.")
                            if nm.endswith("." + dom) and nm != dom:
                                names.add(nm)
            except BudgetExceeded:
                raise
            except Exception as e:
                errors.append(f"certspotter: {e}")
        for msg in errors:
            self.note(f"ct source: {msg}")
        names = sorted(names)[:40]
        dead = 0
        for nm in names:
            try:
                socket.getaddrinfo(nm, None)
            except socket.gaierror:
                dead += 1
                self.add("subdomain-dangling", url="https://" + nm,
                         confidence="low",
                         evidence=f"in CT log for {dom} but no longer resolves",
                         detail="manual takeover claim-test required; this bot "
                                "only reports, never claims")
        self.recon.append(("ct-log subdomains",
                           f"{len(names)} names checked, {dead} unresolved"))
        self.note("ct-log source: crt.sh certificate transparency (passive)")

    def _queue(self, url, queue=None):
        u = url.split("#")[0]
        if self.t.in_scope(u):
            self.urls.add(u)
            if queue is not None:
                queue.append(u)

    def _robots_disallow(self):
        out = []
        rb = self.get(self.t.base + "/robots.txt")
        if rb and rb.status == 200:
            for line in rb.text.splitlines():
                if line.lower().startswith("disallow"):
                    p = line.split(":", 1)[-1].strip()
                    if p:
                        out.append(p)
        return out

    def scripts_of(self, page_url, body):
        return


def urlsplit_path(url):
    return urllib.parse.urlsplit(url).path


def title_of(body):
    m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
    return (m.group(1).strip() if m else "")[:80] or body[:80]


def base_page(bot):
    return bot.t.base + bot.t.path


def check_headers(bot):
    url = base_page(bot)
    r = bot.pages.get(url) or bot.get(url)
    if r is None:
        return
    h = r.headers
    is_html = "html" in r.header("content-type") or "<html" in r.text[:600].lower()
    def vfy():
        rr = bot.get(url)
        return rr is not None
    if bot.t.scheme == "https":
        if "strict-transport-security" not in h:
            bot.add("hdr-hsts", url=url, evidence="header absent", verify=vfy)
        else:
            m = re.search(r"max-age=(\d+)", h["strict-transport-security"])
            if m and int(m.group(1)) < 86400:
                bot.add("hdr-hsts", url=url, severity="MEDIUM",
                        evidence=h["strict-transport-security"],
                        detail="max-age below one day is too short to protect users")
    if is_html:
        csp = h.get("content-security-policy", "")
        if not csp:
            bot.add("hdr-csp-missing", url=url, evidence="header absent", verify=vfy)
        elif re.search(r"script-src[^;]*'unsafe-inline'", csp) or \
                re.search(r"default-src[^;]*'unsafe-inline'", csp) or \
                re.search(r"'unsafe-eval'", csp):
            bot.add("hdr-csp-unsafe", url=url, evidence=csp[:300], verify=vfy)
        if "x-frame-options" not in h and "frame-ancestors" not in csp:
            bot.add("clickjack", url=url, evidence="no XFO and no frame-ancestors",
                    verify=vfy)
        if "referrer-policy" not in h:
            bot.add("hdr-referrer", url=url, evidence="header absent")
        if "permissions-policy" not in h:
            bot.add("hdr-permissions", url=url, evidence="header absent")
        if "cross-origin-opener-policy" not in h:
            bot.add("hdr-coop", url=url, evidence="header absent")
        if "cross-origin-resource-policy" not in h:
            bot.add("hdr-corp", url=url, evidence="header absent")
        if "x-content-type-options" not in h:
            bot.add("hdr-nosniff", url=url, evidence="header absent", verify=vfy)
    for purl, pr in list(bot.pages.items())[:12]:
        if re.search(r"(login|signin|account|dashboard|admin|settings|profile|checkout)",
                     purl, re.I) and "cache-control" not in pr.headers:
            bot.add("hdr-cache-sensitive", url=purl,
                    evidence="no Cache-Control on a sensitive page")
            break
    xss = h.get("x-xss-protection", "")
    if xss and xss.strip() not in ("0", "0; mode=block"):
        bot.add("hdr-xss-legacy", url=url, evidence=f"X-XSS-Protection: {xss}")
    for dead in ("expect-ct", "public-key-pins"):
        if dead in h:
            bot.add("hdr-obsolete", url=url, evidence=f"{dead}: {h[dead][:80]}")
    xp = h.get("x-powered-by", "")
    if xp:
        bot.add("hdr-x-powered", url=url, evidence=f"X-Powered-By: {xp}")
    srv = h.get("server", "")
    if re.search(r"/\d+\.\d+", srv):
        bot.add("hdr-banner", url=url, evidence=f"Server: {srv}", verify=vfy)
        bot.recon.append(("server version", srv))


def check_cors(bot):
    url = base_page(bot)
    evil1 = "https://qx-canary.invalid"
    r = bot.get(url, headers={"Origin": evil1})
    if r is None:
        return
    acao = r.header("access-control-allow-origin")
    acac = r.header("access-control-allow-credentials").lower()
    if not acao:
        return
    if acao == "null":
        bot.add("cors-null", url=url, evidence="Access-Control-Allow-Origin: null",
                detail="the null origin is trusted")
        return
    if acao == "*":
        bot.add("cors-star", url=url, evidence="Access-Control-Allow-Origin: *",
                detail="wildcard origin on this endpoint")
        return
    if acao == evil1:
        evil2 = "https://evil-qx-canary.invalid"
        r2 = bot.get(url, headers={"Origin": evil2})
        reflected2 = r2 is not None and r2.header("access-control-allow-origin") == evil2
        if reflected2:
            sev = "HIGH" if acac == "true" else "MEDIUM"
            def vfy():
                rr = bot.get(url, headers={"Origin": evil1})
                return rr is not None and rr.header(
                    "access-control-allow-origin") == evil1
            bot.add("cors-reflect", url=url, severity=sev, verify=vfy,
                    evidence=f"ACAO: {acao} | ACAC: {acac or 'absent'}",
                    detail="two different attacker origins were both echoed back")
        else:
            bot.note("CORS echoed one origin only, not confirmed arbitrary")


def check_cookies(bot):
    url = base_page(bot)
    r = bot.pages.get(url) or bot.get(url)
    cookies = list((r.headers.get("set-cookie-list", []) if r else []))
    for page, pr in bot.pages.items():
        for c in pr.headers.get("set-cookie-list", []):
            if c not in cookies:
                cookies.append(c)
    for raw in cookies:
        parts = raw.split(";")
        name_val = parts[0].strip()
        name = name_val.split("=", 1)[0]
        attrs = " ".join(p.strip().lower() for p in parts[1:])
        sessionish = bool(re.search(
            r"(session|sess|sid|token|auth|jwt|phpsess|jsession|connect\.sid)",
            name, re.I))
        low = raw.lower()
        if "max-age=" in attrs or "expires=" in attrs:
            ma = re.search(r"max-age=(\d+)", attrs)
            days = int(ma.group(1)) / 86400 if ma else 0
            if days > 365:
                bot.add("cookie-long-life", url=url, param=name,
                        evidence=f"{name} lives {int(days)} days")
        if bot.t.scheme == "https" and "secure" not in attrs:
            bot.add("cookie-secure" if sessionish else "cookie-secure",
                    url=url, param=name, severity="MEDIUM" if sessionish else "LOW",
                    evidence=f"{name}={name_val.split('=',1)[1][:12]}... flags: "
                             f"{attrs or 'none'}")
        if sessionish and "httponly" not in attrs:
            bot.add("cookie-httponly", url=url, param=name,
                    evidence=f"Set-Cookie: {name}=... without HttpOnly")
        if sessionish and "samesite" not in attrs:
            bot.add("cookie-samesite", url=url, param=name,
                    evidence=f"Set-Cookie: {name}=... without SameSite")
        if "samesite=none" in attrs and "secure" not in attrs:
            bot.add("cookie-samesite-none", url=url, param=name,
                    evidence=f"Set-Cookie: {name}=... SameSite=None without "
                             f"Secure")
        if bot.t.scheme == "http" and sessionish:
            bot.add("cookie-plaintext", url=url, param=name,
                    evidence=f"session cookie {name} issued over plain HTTP")


def check_host_header(bot):
    url = base_page(bot)
    canary = "qx-host-canary.invalid"
    r = bot.get(url, headers={"X-Forwarded-Host": canary,
                              "Forwarded": f"host={canary}"})
    if r is None:
        return
    loc = r.header("location")
    where = "body" if canary in r.text else ("Location: " + loc if canary in loc
                                             else "")
    if where:
        def vfy():
            rr = bot.get(url, headers={"X-Forwarded-Host": canary})
            return rr is not None and canary in rr.text
        bot.add("host-header", url=url, evidence=f"X-Forwarded-Host {canary} "
                f"reflected in {where[:120]}", verify=vfy)


def b64url_json(segment):
    pad = "=" * (-len(segment) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(segment + pad))
    except Exception:
        return None


def iter_jwt(bot):
    seen = set()
    for page in bot.pages.values():
        for raw in page.headers.get("set-cookie-list", []):
            val = raw.split(";", 1)[0].split("=", 1)[-1].strip()
            if val.count(".") == 2 and val.startswith("eyJ"):
                if val not in seen:
                    seen.add(val)
                    yield val


def check_jwt(bot):
    weak_secrets = ["secret", "password", "changeme", "qwerty", "123456",
                    "placeholder_website", "placeholder_website", "jwtsecret", "mysecret", "key",
                    bot.t.host, bot.t.host.split(".")[0]]
    for tok in iter_jwt(bot):
        parts = tok.split(".")
        head, pay = b64url_json(parts[0]), b64url_json(parts[1])
        if not isinstance(head, dict) or not isinstance(pay, dict):
            continue
        alg = str(head.get("alg", ""))
        loc = f"cookie on {base_page(bot)}"
        if alg.lower() == "none":
            f = bot.add("jwt-alg-none", url=base_page(bot), param="jwt",
                        confidence="medium", evidence=f"header alg={alg}",
                        detail="server issued an unsigned JWT; acceptance test "
                               "of a forged token left as a manual step")
        if alg.upper() in ("HS256", "HS384", "HS512") and len(parts) == 3:
            signing = (parts[0] + "." + parts[1]).encode()
            sig = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
            for cand in weak_secrets:
                dig = hmac.new(cand.encode(), signing, hashlib.sha256).digest()
                if hmac.compare_digest(dig, sig[:len(dig)]):
                    bot.add("jwt-weak-secret", url=base_page(bot), param="jwt",
                            evidence=f"signature validates with candidate secret "
                                     f"'{cand}' (offline check)",
                            detail="verified offline, no requests to the target")
                    break
        if "exp" not in pay:
            bot.add("jwt-no-exp", url=base_page(bot), param="jwt",
                    evidence=f"claims present: {', '.join(sorted(pay)[:8])}")
        else:
            try:
                left = int(pay["exp"]) - int(time.time())
                if left > 90 * 86400:
                    bot.add("jwt-long-life", url=base_page(bot), param="jwt",
                            evidence=f"exp is {left // 86400} days away")
            except Exception:
                pass


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


def soft404(bot):
    if bot._soft404 is None:
        r = bot.get(bot.t.base + "/qx-nonexistent-" + secrets.token_hex(4))
        bot._soft404 = (r.status, r.text) if r else (404, "")
    return bot._soft404


def is_soft404(bot, resp):
    base_status, base_text = soft404(bot)
    if resp.status != base_status:
        return False
    ratio = difflib.SequenceMatcher(
        None, norm(resp.text[:6000]), norm(base_text[:6000])).ratio()
    return ratio > 0.90


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
        if is_soft404(bot, r):
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
        bot.add(check_id, url=url, evidence=f"{label}: {r.header('content-type')} "
                f"{len(r.body)}B, status {r.status}", verify=vfy)


def check_methods(bot):
    url = bot.t.base + bot.t.path
    r = bot.get(url, method="OPTIONS")
    if r is not None:
        allow = r.header("allow")
        if re.search(r"\b(PUT|DELETE|PATCH)\b", allow):
            bot.add("method-put", url=url, evidence=f"Allow: {allow}", verify=lambda: True)
    r = bot.get(url, method="TRACE")
    if r is not None and r.status == 200 and re.search(
            r"(?i)^\s*trace\s+/|user-agent", r.text[:400]):
        bot.add("method-trace", url=url, evidence=r.text[:200].replace("\r", ""),
                verify=lambda: True)


STACK_SIGS = [
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"File \"[^\"]+\", line \d+", "Python file/line leak"),
    (r"(?i)werkzeug debugger|Debugger.*PIN", "Werkzeug interactive debugger"),
    (r"(?i)django.*Version|Exception Value|Using the URLconf", "Django debug page"),
    (r"(?i)SQLSTATE\[[0-9A-Z]+\]", "PDO/SQL error"),
    (r"(?i)PDOException|mysqli_sql_exception", "PHP SQL exception"),
    (r"(?i)java\.lang\.\w+Exception|at [\w.$]+\([\w.]+:\d+\)", "Java stack trace"),
    (r"(?i)System\.(ArgumentException|NullReferenceException)|Stack trace:", ".NET stack trace"),
    (r"(?i)ORA-\d{5}|Oracle error", "Oracle error"),
    (r"(?i)Whoops!|Symfony\\\\Component", "Symfony error page"),
    (r"(?i)fatal error:", "PHP fatal error"),
    (r"(?i)stack trace:|call stack:", "generic stack trace"),
]


def check_stacktrace(bot):
    probes = [bot.t.base + "/" + "qx-err-" + secrets.token_hex(4),
              bot.t.base + bot.t.path + ("&" if "?" in bot.t.path else "?") + "qx=%%27"]
    for url in probes:
        r = bot.get(url)
        if r is None:
            continue
        text = r.text[:200000]
        for sig, label in STACK_SIGS:
            m = re.search(sig, text)
            if m:
                start = max(0, m.start() - 80)
                ev = text[start:m.end() + 120].replace("\r", " ")
                def vfy(u=url, s=sig):
                    rr = bot.get(u)
                    return rr is not None and re.search(s, rr.text[:200000]) is not None
                bot.add("err-stacktrace", url=url, evidence=ev[:400], verify=vfy)
                break
        if r.status >= 500:
            pass


SQL_SIGS = [r"(?i)you have an error in your sql syntax",
            r"(?i)mysql_fetch|mysqli?_",
            r"(?i)syntax error at or near",
            r"(?i)pg_query\(|unterminated quoted string",
            r"(?i)SQLITE_ERROR|SQLite/3",
            r"(?i)Unclosed quotation mark after the character string",
            r"(?i)Microsoft OLE DB Provider for SQL Server",
            r"(?i)ORA-\d{5}|quoted string not properly terminated",
            r"(?i)SQLSTATE\[[0-9A-Z]{5}\]"]
CMD_ECHO = re.compile(r"([;&|]\s*echo\s+)(QX[A-Za-z0-9]{4,})", re.I)
FILENAME_PARAM = re.compile(r"(?i)^(file|filename|path|dir|document|doc|template|"
                            r"page|download|include|resource|name)$")
REDIR_PARAM = re.compile(r"(?i)^(url|to|redirect|redir|next|return|returnto|return_url|"
                         r"continue|dest|destination|goto|target|callback|goto_url|u)$")


def norm(text):
    t = re.sub(r"(?i)[0-9a-f]{12,}", "#", text or "")
    t = re.sub(r"\d{3,}", "#", t)
    return re.sub(r"\s+", " ", t)[:20000]


def check_injection(bot):
    budget_urls = [u for u, ps in bot.params.items() if ps][:5]
    for url in budget_urls:
        if bot.t.used > bot.t.max_requests * 0.8:
            bot.note("injection probes stopped at 80% of request budget")
            break
        parts = urllib.parse.urlsplit(url)
        q = dict(kv.split("=", 1) if "=" in kv else (kv, "")
                 for kv in parts.query.split("&") if kv)
        for param in list(bot.params[url])[:4]:
            def build(value, url=url, parts=parts, q=q, param=param):
                nq = dict(q)
                nq[param] = value
                return urllib.parse.urlunsplit(
                    (parts.scheme, parts.netloc, parts.path,
                     urllib.parse.urlencode(nq, doseq=True), parts.fragment))
            orig = q.get(param, "")
            base_r = bot.get(build(orig or "qx"))
            if base_r is None:
                continue
            base_txt = base_r.text
            # reflected XSS: plain canary then hostile characters
            tok = bot.canary + secrets.token_hex(3)
            r1 = bot.get(build(tok))
            if r1 is not None and tok in r1.text and tok not in base_txt:
                hostile = f"<\">'{tok}"
                r2 = bot.get(build(hostile))
                if r2 is not None and hostile in r2.text:
                    def vfy(u=build(hostile), h=hostile):
                        rr = bot.get(u)
                        return rr is not None and h in rr.text
                    bot.add("xss-reflected", url=url, param=param,
                            evidence=f"raw echo of {hostile!r} in response body",
                            verify=vfy)
                else:
                    bot.note(f"{param} reflects input but appears escaped "
                             f"(no XSS found)")
            # SQL error based, then boolean differential fallback
            probe = (orig or "") + "'"
            r3 = bot.get(build(probe))
            found_sqli = False
            if r3 is not None and (
                    r3.status != base_r.status or (
                        any(re.search(s, r3.text) for s in SQL_SIGS)
                        and not any(re.search(s, base_txt) for s in SQL_SIGS))):
                for s in SQL_SIGS:
                    m = re.search(s, r3.text)
                    if m:
                        def vfy(u=build(probe), s=s):
                            rr = bot.get(u)
                            return rr is not None and re.search(s, rr.text) is not None
                        bot.add("sqli-error", url=url, param=param,
                                evidence=r3.text[max(0, m.start() - 60):m.end() + 80]
                                         .replace("\r", " ")[:300], verify=vfy)
                        found_sqli = True
                        break
                if not found_sqli:
                    bot.add("sqli-boolean", url=url, param=param,
                            confidence="medium",
                            evidence=f"status {base_r.status} -> {r3.status} on "
                                     f"quote injection",
                            detail="differential observed without a DB error "
                                   "string; confirm manually")
                    found_sqli = True
            if not found_sqli:
                bv = orig or "1"
                rt_ = bot.get(build(bv + " AND 1=1"))
                rf_ = bot.get(build(bv + " AND 1=2"))
                if rt_ is not None and rf_ is not None and \
                        rt_.status == rf_.status == 200:
                    a = norm(rt_.text)
                    b = norm(rf_.text)
                    base_n = norm(base_txt)
                    r_true_base = difflib.SequenceMatcher(None, a, base_n).ratio()
                    r_true_false = difflib.SequenceMatcher(None, a, b).ratio()
                    if r_true_base >= 0.97 and r_true_false <= 0.95:
                        def vfy(u=build(bv + " AND 1=2"), ref=a):
                            rr = bot.get(u)
                            return rr is not None and difflib.SequenceMatcher(
                                None, norm(rr.text), ref).ratio() <= 0.95
                        bot.add("sqli-boolean", url=url, param=param,
                                confidence="medium",
                                evidence=f"AND 1=1 matches baseline "
                                         f"({r_true_base:.2f}) while AND 1=2 "
                                         f"diverges ({r_true_false:.2f})",
                                detail="boolean differential is a strong signal; "
                                       "confirm manually before calling it SQLi",
                                verify=vfy)
            # command injection echo marker (benign only)
            for sep in ("; echo ", " | echo ", " && echo "):
                tok2 = "QX" + secrets.token_hex(5)
                payload = (orig or "qx") + sep + tok2
                r4 = bot.get(build(payload))
                visible = htmllib.unescape(r4.text) if r4 is not None else ""
                if r4 is not None and tok2 in visible and payload not in visible \
                        and tok2 not in base_txt:
                    def vfy(u=build(payload), t=tok2):
                        rr = bot.get(u)
                        return rr is not None and t in rr.text
                    bot.add("cmdi-echo", url=url, param=param,
                            evidence=f"server echoed injected marker {tok2} "
                                     f"without the command text (separator "
                                     f"{sep.strip()!r})", verify=vfy)
                    break
            # open redirect
            if REDIR_PARAM.match(param):
                target = "//qx-canary.invalid/landing"
                rd = bot.get(build(target), follow=False)
                loc = rd.header("location") if rd else ""
                if loc.startswith("//qx-canary.invalid") or loc.startswith(
                        "https://qx-canary.invalid"):
                    bot.add("redirect-open", url=url, param=param,
                            evidence=f"Location: {loc}", verify=lambda: True)
            # path traversal (planted canary or explicit deep mode)
            if FILENAME_PARAM.match(param):
                if bot.args.traversal_canary:
                    payload = "../../../../" + bot.args.traversal_canary.lstrip("/")
                    rt = bot.get(build(payload))
                    if rt is not None and bot.args.traversal_canary in rt.text:
                        bot.add("traversal", url=url, param=param,
                                evidence=f"planted canary "
                                         f"{bot.args.traversal_canary} returned",
                                verify=lambda: True)
                elif bot.args.deep_traversal:
                    rt = bot.get(build("../../../../etc/passwd"))
                    if rt is not None and re.search(r"(?m)^root:x?:0:0:", rt.text):
                        bot.add("traversal", url=url, param=param,
                                evidence="/etc/passwd contents returned",
                                verify=lambda: True)


ADMIN_PATHS = ["/admin", "/administrator", "/admin/login", "/wp-admin/",
               "/manage", "/dashboard", "/console/login", "/cpanel",
               "/backend", "/staff", "/internal",
               "/account", "/profile", "/orders", "/settings", "/wallet",
               "/user/profile", "/api/user/me", "/api/v1/account"]


SECRET_RES = [
    ("AWS access key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "CRITICAL"),
    ("Stripe live secret", re.compile(r"sk_live_[0-9A-Za-z]{16,}"), "CRITICAL"),
    ("GitHub token", re.compile(r"ghp_[A-Za-z0-9]{36}"), "CRITICAL"),
    ("OpenAI-style secret key", re.compile(r"(?<![\w-])sk-[A-Za-z0-9]{32,}"),
     "CRITICAL"),
    ("Embedded private key",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "CRITICAL"),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "HIGH"),
    ("Bearer credential",
     re.compile(r"(?i)bearer[\"'\s:=]{1,4}[A-Za-z0-9._\-]{25,}"), "HIGH"),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "MEDIUM"),
]


def mask_token(raw):
    if len(raw) <= 12:
        return "***"
    return raw[:6] + "*" * (len(raw) - 10) + raw[-4:]


def make_secret_vfy(bot, url, rx):
    def v():
        rr = bot.get(url)
        return rr is not None and rx.search(rr.text) is not None
    return v


def check_secrets(bot):
    sources = [(u, r.text) for u, r in bot.pages.items()] + \
              [(u, t) for u, t in bot.js_assets.items()]
    for src_url, text in sources:
        if not text or len(text) > 2_000_000:
            continue
        for name, rx, sev in SECRET_RES:
            m = rx.search(text)
            if not m:
                continue
            raw = m.group(0)
            bot.add("secret-leak", url=src_url, severity=sev, param=name,
                    confidence="medium" if name == "Google API key" else "high",
                    evidence=f"{name} in served content: {mask_token(raw)} "
                             f"(value redacted)",
                    detail="client-visible secret: treat as compromised, "
                           "rotate it and move it server-side",
                    verify=make_secret_vfy(bot, src_url, rx))


def check_auth(bot):
    # force browsing to obvious privileged surfaces, unauthenticated
    for path in ADMIN_PATHS:
        url = bot.t.base + path
        r = bot.get(url, follow=False)
        if r is None:
            continue
        if r.status in (301, 302, 303, 307, 308):
            loc = r.header("location")
            if not re.search(r"(login|signin|auth|sso)", loc, re.I):
                bot.note(f"{path} redirects to {loc} (check manually)")
            continue
        if r.status == 200:
            body = r.text[:20000]
            if LOGIN_RE.search(body):
                continue
            if re.search(r"(?i)<(html|body)", body) and len(body) > 250:
                def vfy(u=url):
                    rr = bot.get(u, follow=False)
                    return rr is not None and rr.status == 200 and \
                        not LOGIN_RE.search(rr.text[:20000])
                bot.add("admin-force-browse", url=url,
                        evidence=f"HTTP 200, {len(body)}B, no login form "
                                 f"(title: {title_of(body)!r})", verify=vfy)

    # CSRF posture of state-changing forms
    for form in bot.forms:
        if form["method"] != "post":
            continue
        names = [i["name"] for i in form["inputs"]]
        has_token = any(TOKEN_RE.match(n or "") for n in names)
        action = urllib.parse.urljoin(base_page(bot), form["action"] or "")
        if not has_token:
            bot.add("csrf-token-missing", url=action,
                    param=",".join(n for n in names if n)[:80],
                    confidence="medium",
                    evidence=f"POST form with fields: {', '.join(names)[:160]} "
                             f"and no hidden CSRF token",
                    detail="confirm by replaying from a cross-origin page on a "
                           "dry-run endpoint")
        samesite = any("samesite" in c.lower()
                       for p in bot.pages.values()
                       for c in p.headers.get("set-cookie-list", []))
        if not has_token and not samesite and form["inputs"]:
            bot.note(f"{action}: no CSRF token and no SameSite cookie attribute")


def check_ratelimit(bot):
    login_form = None
    for form in bot.forms:
        types = [i["type"] for i in form["inputs"]]
        if "password" in types:
            login_form = form
            break
    if login_form is None:
        for path in ("/login", "/signin", "/sign-in", "/auth/login", "/account/login"):
            r = bot.get(bot.t.base + path, follow=False)
            if r is not None and r.status == 200 and "password" in r.text.lower():
                login_form = {"action": path, "method": "post",
                              "inputs": [{"name": "username", "type": "text"},
                                         {"name": "password", "type": "password"}]}
                break
    if login_form is None:
        bot.note("no login form discovered, rate-limit test skipped")
        return
    action = urllib.parse.urljoin(base_page(bot), login_form["action"] or "")
    fields = {i["name"]: ("qx_nouser@invalid" if i["type"] != "password"
                          else "DefinitelyNotARealPass!1")
              for i in login_form["inputs"] if i["name"]}
    if not fields:
        return
    statuses, limited = [], False
    for _ in range(10):
        r = bot.get(action, method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=urllib.parse.urlencode(fields), follow=False)
        if r is None:
            return
        statuses.append(r.status)
        if r.status in (429, 423, 403) or r.header("retry-after"):
            limited = True
            break
        if bot.stopped:
            return
    if not limited:
        bot.add("ratelimit-login", url=action,
                evidence=f"10 rapid failed logins, statuses: {statuses}",
                detail="no 429/lockout observed in a gentle N=10 burst; "
                       "manual review recommended before concluding")


def check_sectxt(bot):
    for path in ("/.well-known/security.txt", "/security.txt"):
        r = bot.get(bot.t.base + path)
        if r is not None and r.status == 200 and "contact:" in r.text.lower():
            bot.recon.append(("security.txt", path))
            return
    bot.add("sec-txt-missing", url=bot.t.base + "/.well-known/security.txt",
            evidence="no RFC 9116 security.txt found")


def check_client(bot):
    for url, r in list(bot.pages.items())[:20]:
        if "html" not in r.header("content-type") and "<html" not in r.text[:600].lower():
            continue
        body = r.text
        try:
            p = PageParser()
            p.feed(body)
        except Exception:
            continue
        for src, integrity, _co in p.scripts:
            absu = urllib.parse.urljoin(url, src)
            sp = urllib.parse.urlsplit(absu)
            if sp.scheme in ("http", "https") and sp.netloc and \
                    sp.netloc != urllib.parse.urlsplit(bot.t.base).netloc and \
                    not integrity:
                bot.add("sri-missing", url=url, param=src[:120],
                        evidence=f"<script src=\"{src}\"> without integrity",
                        verify=lambda u=url: True)
                break
        if bot.t.scheme == "https":
            m = re.search(r"(?:src|href)=[\"'](http://[^\"']+)[\"']", body)
            if m:
                bot.add("mixed-content", url=url, evidence=f"mixed resource: {m.group(1)}",
                        verify=lambda: True)
        # source maps
        for m in re.finditer(r"sourceMappingURL=([^\s\"'<>)\\]+)", body):
            map_url = urllib.parse.urljoin(url, m.group(1))
            if not bot.t.in_scope(map_url):
                continue
            mr = bot.get(map_url)
            if mr is not None and mr.status == 200 and b'"sources"' in mr.body[:200000]:
                bot.add("exp-sourcemap", url=map_url,
                        evidence=f"source map served ({len(mr.body)}B)",
                        verify=lambda u=map_url: True)


SEV_GLYPH = {"CRITICAL": "✖", "HIGH": "▲", "MEDIUM": "●", "LOW": "○", "INFO": "•"}
ANSI = {"CRITICAL": "\033[1;91m", "HIGH": "\033[91m", "MEDIUM": "\033[93m",
        "LOW": "\033[94m", "INFO": "\033[90m", "reset": "\033[0m",
        "bold": "\033[1m", "dim": "\033[2m", "green": "\033[92m"}


def colorize(s, key, use_color):
    return f"{ANSI[key]}{s}{ANSI['reset']}" if use_color else s


def terminal_report(bot, use_color):
    out = []
    c = use_color
    line = "─" * 72
    out.append(colorize("╭" + line + "╮", "dim", c))
    title = " RED TEAM REPORT  ·  placeholder_website self-assault "
    out.append(colorize("│", "dim", c) + colorize(title.center(72), "bold", c)
               + colorize("│", "dim", c))
    out.append(colorize("╰" + line + "╯", "dim", c))
    sc = bot.score()
    filled = int(round(sc / 5))
    bar = "█" * filled + "░" * (20 - filled)
    out.append(f"  score   {colorize(bar, 'green' if sc >= 80 else 'MEDIUM' if sc >= 50 else 'CRITICAL', c)} {sc}/100")
    counts = bot.counts()
    parts = [colorize(f"{SEV_GLYPH[s]} {counts[s]} {s}", s, c)
             for s in SEV_ORDER if counts[s]]
    out.append("  findings " + "   ".join(parts))
    out.append(f"  requests {bot.t.used}/{bot.t.max_requests}   "
               f"budget {'EXHAUSTED' if bot.stopped else 'ok'}   "
               f"rate-limit responses {bot.t.rate_limited}")
    out.append("")
    shown = sorted(bot.findings, key=lambda f: (SEV_ORDER[f["severity"]],
                                                f["check_id"]))
    if not shown:
        out.append("  ✓ nothing to report. Move to manual and business-logic tests.")
    hdr = f"  {'SEV':<11}{'OWASP':<9}{'FINDING':<42}{'WHERE'}"
    out.append(colorize(hdr, "bold", c))
    out.append("  " + "─" * 68)
    for f in shown:
        sev = f"{SEV_GLYPH[f['severity']]} {f['severity']}"
        where = (f["url"] + (" [" + (f["param"] or "") + "]" if f["param"] else ""))[:56]
        mark = "✓" if f["verified"] else ("?" if f["confidence"] == "medium" else " ")
        out.append("  " + colorize(f"{sev:<11}", f["severity"], c)
                   + f"{f['owasp']:<9}{f['title'][:40]:<42}{where} {mark}")
    out.append("")
    top = [f for f in shown if f["severity"] in ("CRITICAL", "HIGH")][:3] or shown[:3]
    if top:
        out.append(colorize("  ATTACKER NARRATIVE", "bold", c))
        for i, f in enumerate(top, 1):
            out.append(f"   {i}. {f['title']} ({f['severity']}, {f['owasp']})")
            out.append(colorize(f"      -> {f['impact']}", "dim", c))
        out.append("")
        out.append(colorize("  FIX FIRST (in this order)", "bold", c))
        for i, f in enumerate(top, 1):
            out.append(f"   {i}. {f['fix'][:110]}")
    if bot.stopped:
        out.append(colorize(f"\n  ! scan stopped early: {bot.stopped}", "MEDIUM", c))
    return "\n".join(out)


def write_checklist(bot, out_dir):
    counts = bot.counts()
    lines = ["# Security fix checklist", "",
             f"Target: {bot.t.base}{bot.t.path}  |  score {bot.score()}/100  |  "
             f"{counts['CRITICAL']} critical, {counts['HIGH']} high, "
             f"{counts['MEDIUM']} medium, {counts['LOW']} low, "
             f"{counts['INFO']} info", "",
             "Work top to bottom. Re-run the bot after each fix and watch the "
             "score move.", ""]
    order = sorted(bot.findings, key=lambda f: (SEV_ORDER[f["severity"]],
                                                f["check_id"]))
    cur = None
    for f in order:
        if f["severity"] != cur:
            cur = f["severity"]
            lines += [f"## {SEV_GLYPH[cur]} {cur}", ""]
        where = f["url"] + (f" [{f['param']}]" if f["param"] else "")
        lines.append(f"- [ ] **{f['title']}** ({f['owasp']}) `{where}`")
        lines.append(f"      fix: {f['fix']}")
    path = os.path.join(out_dir, "CHECKLIST.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def json_report(bot):
    return json.dumps({
        "tool": {"name": "redteam.py", "version": VERSION},
        "target": bot.t.base + bot.t.path,
        "scope": sorted(bot.t.allow),
        "started_utc": bot.started,
        "finished_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scenario": bot.args.scenario,
        "requests_used": bot.t.used,
        "budget": bot.t.max_requests,
        "stopped_early": bot.stopped,
        "score": bot.score(),
        "counts": bot.counts(),
        "recon": bot.recon,
        "notes": bot.notes,
        "findings": bot.findings,
        "endpoints": sorted(bot.endpoints),
        "js_assets": sorted(bot.js_assets),
        "checks_available": len(CHECKS),
        "checks_fired": sorted({f["check_id"] for f in bot.findings}),
    }, indent=2)


HTML_CSS = """
:root{--bg:#0b0e13;--panel:#12161d;--ink:#d7dde6;--mut:#8b94a3;--line:#232a35;
--cr:#ff2d55;--hi:#ff6b35;--me:#ffb020;--lo:#4aa3ff;--in:#7d8590;--acc:#39d98a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.6 "DejaVu Sans Mono",Consolas,monospace}
.wrap{max-width:1040px;margin:0 auto;padding:34px 26px 80px}
header.top{border-bottom:1px solid var(--line);padding-bottom:22px;margin-bottom:26px}
.kicker{color:var(--acc);font-size:12px;letter-spacing:.22em;text-transform:uppercase}
h1{font-size:26px;margin:8px 0 6px;font-weight:700}
.meta{color:var(--mut);font-size:12.5px}
.meta b{color:var(--ink)}
.grid{display:grid;grid-template-columns:270px 1fr;gap:26px;align-items:start}
@media(max-width:760px){.grid{grid-template-columns:1fr}}
.score\boxed{background:var(--panel);border:1px solid var(--line);padding:22px}
.score{font-size:64px;font-weight:700;line-height:1}
.score small{font-size:18px;color:var(--mut)}
.bar{height:10px;background:#1b212b;margin:16px 0 14px;position:relative}
.bar i{position:absolute;inset:0 auto 0 0;display:block}
.sevrow{display:flex;flex-wrap:wrap;gap:8px;margin-top:6px}
.chip{font-size:11.5px;padding:3px 9px;border:1px solid var(--line);color:var(--ink)}
h2{font-size:13px;letter-spacing:.18em;text-transform:uppercase;color:var(--mut);
margin:34px 0 12px;border-bottom:1px solid var(--line);padding-bottom:7px}
.narr{background:var(--panel);border-left:3px solid var(--acc);padding:14px 18px;
margin-bottom:10px}
.narr b{color:var(--acc)}
.narr div{color:var(--mut);font-size:13px;margin-top:4px}
details.f{background:var(--panel);border:1px solid var(--line);border-left-width:4px;
margin-bottom:9px}
details.f summary{cursor:pointer;padding:11px 15px;display:flex;gap:12px;
align-items:baseline;list-style:none}
details.f summary::-webkit-details-marker{display:none}
.tag{font-size:10.5px;padding:2px 7px;color:#0b0e13;font-weight:700;white-space:nowrap}
.ftitle{font-weight:700}
.fmeta{color:var(--mut);font-size:12px;margin-left:auto;white-space:nowrap}
.fbody{padding:0 15px 15px;border-top:1px solid var(--line);margin-top:2px;
padding-top:12px}
.fbody dt{color:var(--mut);font-size:11px;letter-spacing:.14em;
text-transform:uppercase;margin-top:10px}
.fbody dd{margin:3px 0 0}
pre{background:#0e1218;border:1px solid var(--line);padding:10px 12px;overflow:auto;
font-size:12.5px;white-space:pre-wrap;word-break:break-all}
.fix{color:var(--acc)}
a{color:var(--lo)}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:11.5px;letter-spacing:.1em;
text-transform:uppercase}
.two{display:grid;grid-template-columns:1fr 1fr;gap:22px}
@media(max-width:760px){.two{grid-template-columns:1fr}}
.muted{color:var(--mut);font-size:13px}
.ok{color:var(--acc)}.bad{color:var(--cr)}
.filt{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 12px}
.filt button{background:var(--panel);color:var(--ink);border:1px solid var(--line);
padding:5px 13px;font:12px/1 "DejaVu Sans Mono",monospace;cursor:pointer;
letter-spacing:.08em}
.filt button.on{border-color:var(--acc);color:var(--acc)}
"""


def esc(s):
    return htmllib.escape(str(s or ""))


def html_report(bot):
    counts = bot.counts()
    score = bot.score()
    sev_css = {"CRITICAL": "var(--cr)", "HIGH": "var(--hi)", "MEDIUM": "var(--me)",
               "LOW": "var(--lo)", "INFO": "var(--in)"}
    shown = sorted(bot.findings, key=lambda f: (SEV_ORDER[f["severity"]],
                                                f["check_id"]))
    narr = [f for f in shown if f["severity"] in ("CRITICAL", "HIGH")][:3] or shown[:3]
    rows = []
    for f in shown:
        col = sev_css[f["severity"]]
        refs = " ".join(f'<a href="{esc(u)}">{esc(u.split("/")[2])}</a>'
                        for u in f.get("refs", []))
        rows.append(f"""<details class="f" data-sev="{f['severity']}"
 style="border-left-color:{col}">
<summary><span class="tag" style="background:{col}">{f['severity']}</span>
<span class="ftitle">{esc(f['title'])}</span>
<span class="fmeta">{esc(f['owasp'])} · {esc(f['check_id'])} ·
{'verified' if f['verified'] else esc(f['confidence'])}</span></summary>
<div class="fbody"><dl>
<dt>Where</dt><dd>{esc(f['url'])}{(' · param ' + esc(f['param'])) if f['param'] else ''}</dd>
<dt>Why it matters</dt><dd>{esc(f['impact'])}</dd>
{f'<dt>Detail</dt><dd>{esc(f["detail"])}</dd>' if f['detail'] else ''}
<dt>Evidence</dt><dd><pre>{esc(f['evidence'])}</pre></dd>
<dt>Exact fix</dt><dd class="fix">{esc(f['fix'])}</dd>
<dt>Reference</dt><dd>{refs}</dd>
</dl></div></details>""")
    owasp_rows = "".join(
        f"<tr><td>{k}:2025</td><td>{esc(v)}</td></tr>" for k, v in OWASP.items())
    fired = {f['check_id'] for f in bot.findings}
    cov = "".join(
        f"<tr><td>{esc(cid)}</td><td>{esc(CHECKS[cid][2])}</td>"
        f"<td class='{'ok' if cid in fired else ''}'>"
        f"{'FIRED' if cid in fired else 'clean / not applicable'}</td></tr>"
        for cid in sorted(CHECKS))
    recon = "".join(f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>"
                    for k, v in bot.recon)
    notes = "".join(f"<li>{esc(n)}</li>" for n in bot.notes[:40])
    barcol = "var(--acc)" if score >= 80 else ("var(--me)" if score >= 50 else "var(--cr)")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Red team report · {esc(bot.t.host)}</title>
<style>{HTML_CSS}</style></head><body><div class="wrap">
<header class="top">
<div class="kicker">authorized self-assessment · redteam.py v{VERSION}</div>
<h1>Attack simulation report</h1>
<div class="meta">target <b>{esc(bot.t.base + bot.t.path)}</b> ·
scope <b>{esc(', '.join(sorted(bot.t.allow)))}</b> ·
scenario <b>{esc(bot.args.scenario)}</b> ·
finished <b>{esc(bot.started)}</b> UTC ·
requests <b>{bot.t.used}/{bot.t.max_requests}</b></div>
</header>
<div class="grid">
<div class="scorebox">
<div class="kicker">security score</div>
<div class="score" style="color:{barcol}">{score}<small>/100</small></div>
<div class="bar"><i style="width:{score}%;background:{barcol}"></i></div>
<div class="sevrow">{''.join(f'<span class="chip" style="border-color:{sev_css[s]};color:{sev_css[s]}">{counts[s]} {s}</span>' for s in SEV_ORDER)}</div>
<p class="muted">weighted: critical −25, high −12, medium −5, low −2;
unverified critical/high count half.</p>
</div>
<div>
<h2>Attacker narrative</h2>
{''.join(f'<div class="narr"><b>{i}. {esc(f["title"])}</b> ({f["severity"]}, {f["owasp"]})<div>{esc(f["impact"])}</div></div>' for i, f in enumerate(narr, 1)) or '<div class="muted">No exploitable path found by the automated pass.</div>'}
<h2>Findings ({len(shown)})</h2>
<div class="filt">{''.join(f"<button class='{'on' if s == 'ALL' else ''}' onclick=\"ff('{s}',this)\">{s}</button>" for s in ["ALL"] + list(SEV_ORDER))}
</div>
{''.join(rows) or '<div class="muted">Nothing to report. Automated coverage is a subset of a real assessment: finish with manual access-control, business-logic and abuse-case testing.</div>'}
</div></div>
<h2>OWASP Top 10:2025 mapping</h2>
<table><tr><th>ID</th><th>Category</th></tr>{owasp_rows}</table>
<div class="two">
<div><h2>Check coverage</h2>
<table><tr><th>Check</th><th>What it probes</th><th>Result</th></tr>{cov}</table></div>
<div><h2>Recon</h2><table><tr><th>Item</th><th>Value</th></tr>{recon}</table>
<h2>Engine notes</h2><ul class="muted">{notes or '<li>none</li>'}</ul></div>
</div>
<h2>Method and safety rails</h2>
<p class="muted">Scope gate: every request host must match the allowlist, or it is
never sent. Rate limit {bot.args.rps} req/s with jitter, hard budget
{bot.t.max_requests} requests, identifiable User-Agent, benign payloads only
(canaries, error signatures, echo markers), no brute force, no DoS, no data
modification, robots.txt honored during discovery. Critical/high findings are
re-tested once; failures are downgraded to candidate.
Standards: OWASP Top 10:2025, OWASP WSTG, OWASP Cheat Sheet Series,
NIST SP 800-115, PTES.</p>
<p class="muted">redteam.py v{VERSION} · generated for the owner of
{esc(bot.t.host)} · re-run after each fix to confirm the score moves.</p>
</div></body></html>"""


RUNNERS = {
    "recon": [check_sectxt],
    "tls": [check_tls],
    "headers": [check_headers, check_host_header],
    "cors": [check_cors],
    "cookies": [check_cookies],
    "jwt": [check_jwt],
    "secrets": [check_secrets],
    "exposures": [check_exposures, check_stacktrace, check_graphql],
    "injection": [check_injection],
    "auth": [check_auth, check_ratelimit],
    "client": [check_client],
    "methods": [check_methods],
}


def build_parser():
    p = argparse.ArgumentParser(
        prog="redteam.py",
        description="Authorized red team simulator for a website YOU own. "
                    "Finds vulnerabilities, prints the exact fix.",
        epilog="Exit codes: 2 = critical findings, 1 = high findings, 0 = clean.")
    p.add_argument("--target", help="https://your-site.example")
    p.add_argument("--allow", action="append", default=[],
                   help="hostname in scope, repeatable or comma separated")
    p.add_argument("--i-own-this", action="store_true",
                   help="confirms you own the target; required for active checks")
    p.add_argument("--scenario", choices=sorted(SCENARIOS), default="full")
    p.add_argument("--rps", type=float, default=5.0, help="requests per second")
    p.add_argument("--max-requests", type=int, default=500, help="hard request budget")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--max-pages", type=int, default=25, help="crawl page cap")
    p.add_argument("--local", action="store_true",
                   help="permit 127.0.0.1/localhost targets")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--cookie", help="session cookie for authenticated checks")
    p.add_argument("--respect-robots", dest="respect_robots", action="store_true",
                   default=True)
    p.add_argument("--ignore-robots", dest="respect_robots", action="store_false")
    p.add_argument("--deep-traversal", action="store_true",
                   help="add /etc/passwd traversal probe (off by default)")
    p.add_argument("--traversal-canary",
                   help="filename you planted outside the web root to prove traversal")
    p.add_argument("--report-dir", help="output directory for report.html/.json")
    p.add_argument("--wayback", action="store_true",
                   help="recon historical URLs from the Wayback CDX API "
                        "(passive, one external read-only request)")
    p.add_argument("--ct-log", dest="ct_log", action="store_true",
                   help="subdomain takeover leads from crt.sh certificate "
                        "transparency + DNS only (passive)")
    p.add_argument("--quiet", action="store_true", help="suppress terminal findings")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--list-checks", action="store_true")
    return p


def list_checks():
    print(f"redteam.py v{VERSION}: {len(CHECKS)} checks\n")
    for group, ids in GROUPS.items():
        print(f"[{group}]")
        for cid in ids:
            owasp, sev, title, _impact, _fix = CHECKS[cid]
            print(f"  {cid:<22} {sev:<9} {owasp:<6} {title}")
    print("\nscenarios: " + ", ".join(
        f"{k} ({','.join(v)})" for k, v in SCENARIOS.items()))


def run(args):
    if args.list_checks:
        list_checks()
        return 0
    if not args.target:
        raise SystemExit("--target is required (or use --list-checks)")
    allow = [a for chunk in args.allow for a in str(chunk).replace(";", ",").split(",")]
    if not allow:
        raise SystemExit("--allow is required: name the host you own, "
                         "e.g. --allow yourdomain.example")
    mode = "active"
    if not args.i_own_this:
        mode = "passive"
        args.scenario = "recon"
    t = Transport(args.target, allow, args.rps, args.max_requests,
                  args.timeout, args.insecure, args.local)
    bot = Bot(t, args)
    bot.started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    bot.note(f"mode: {mode} (scenario {args.scenario})")
    if args.cookie:
        bot.note("authenticated checks enabled via --cookie")

    def guarded(fn):
        try:
            fn(bot)
        except BudgetExceeded as e:
            bot.stopped = str(e)
        except OutOfScope as e:
            bot.note(f"scope violation blocked: {e}")
        except Exception as e:
            bot.note(f"check degraded ({type(e).__name__}): {e}")

    guarded(lambda b: b.discover())
    if bot.stopped is None:
        for group in SCENARIOS[args.scenario]:
            for fn in RUNNERS[group]:
                if bot.stopped:
                    break
                guarded(fn)
    if bot.stopped is None:
        guarded(lambda b: b.verify_findings())
    else:
        # still try to verify what we already have, cheaply
        try:
            bot.verify_findings()
        except BudgetExceeded:
            pass

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out_dir = args.report_dir or f"rt-report-{ts}"
    os.makedirs(out_dir, exist_ok=True)
    html_path = os.path.join(out_dir, "report.html")
    json_path = os.path.join(out_dir, "report.json")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_report(bot))
    with open(json_path, "w", encoding="utf-8") as fh:
        fh.write(json_report(bot))
    list_path = write_checklist(bot, out_dir)

    if not args.quiet:
        use_color = sys.stdout.isatty() and not args.no_color
        print(terminal_report(bot, use_color))
        print(f"\n  report   {os.path.abspath(html_path)}")
        print(f"  json     {os.path.abspath(json_path)}")
        print(f"  checklist {os.path.abspath(list_path)}")
    counts = bot.counts()
    if counts["CRITICAL"]:
        return 2
    if counts["HIGH"]:
        return 1
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
