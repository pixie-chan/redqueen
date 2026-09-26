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
import unicodedata
import urllib.parse
from datetime import datetime, timezone
from html.parser import HTMLParser

import http.client

VERSION = "2.0.0"
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
 "global-secret-sweep": ("A02", "HIGH", "Secret or trace signature in served content",
   "a key or an internal trace that no single check looked for is readable by anyone",
   "pull the value out of client-visible content, rotate it at the provider and keep it server-side; return generic error pages and store traces in private logs"),
"desync-confirmed": ("A01", "CRITICAL",
    "Confirmed HTTP request desync cross-contamination (CWE-444)",
    "one client's request is answered with another client's request or "
    "response: sessions, responses and cache entries cross over between users",
    "end to end HTTP/2 or a single strict HTTP/1.1 parser, reject duplicate "
    "Content-Length and Transfer-Encoding, and validate rewritten requests "
    "against RFC 9112 before forwarding"),
  "desync-cells": ("A06", "INFO", "Length-interpretation cell (CL/TE/0/H2) probe",
    "an anomaly, not a vulnerability: one hop read a different message length "
    "than another hop did",
    "read the anomaly table and confirm by hand before changing anything; a "
    "differential here is a lead, not a bug"),
  "unicode-oracle": ("A07", "INFO",
    "Unicode normalization oracle in a reflected value",
    "an anomaly, not a vulnerability: the stored or echoed form of a value "
    "differs from the form sent, which can break an identity comparison",
    "normalize with NFKC on input and on the stored value, compare code-point "
    "sequences rather than rendered strings, reject mixed-form input at the edge"),
  "delimiter-confusion": ("A02", "INFO",
    "Path delimiter handled differently by cache and origin",
    "an anomaly, not a vulnerability: two hops disagree about what the path "
    "is, which is the precondition for cache poisoning",
    "normalize the path once at the edge, cache only on the normalized key, "
    "reject unencoded ; . and %2e upstream"),
  "api-state-authz": ("A01", "INFO",
    "Authorization differential on a documented object path",
    "an anomaly, not a vulnerability: an unauthenticated read of a single "
    "object differs from the anonymous collection baseline",
    "authenticate then authorize per object server-side; add a second "
    "owner-provided test account to the plan and re-run before concluding "
    "anything about BOLA"),
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
 "sweep": ["global-secret-sweep"],
}
SCENARIOS = {
 "recon": ["recon"],
 "headers": ["tls", "headers", "cors", "cookies"],
 "misconfig": ["exposures", "methods"],
 "injection": ["injection"],
 "auth": ["auth", "jwt"],
 # the whole-corpus sweep runs after exposures, so it sees the files the
 # exposure probes captured and not only the crawl
 "full": ["recon", "tls", "headers", "cors", "cookies", "jwt", "secrets",
   "exposures", "sweep", "injection", "auth", "client", "methods"],
 "anomaly": ["anomaly"],
 "tierc": ["tierc"],
"tierb": ["desync-confirmed", "desync-cells", "unicode-oracle",
   "delimiter-confusion", "api-state-authz"],
 "api": ["recon", "exposures", "cors", "injection"],
# the API state walk reads the OpenAPI document that exp-api-docs captured,
# so the exposures group has to run first inside the tierb scenario
"tierb": ["exposures", "tierb"],
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
        self.frozen = False
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
        # A frozen transport is the Tier C guarantee: once the dossier phase
        # starts, no code path can put bytes on the wire. Checked here, the
        # single choke point every request passes through.
        if getattr(self, "frozen", False):
            raise OutOfScope("transport is frozen (tierc research phase)")
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

    def _read_exact(self, fh, n):
        out = b""
        while len(out) < n:
            chunk = fh.read(n - len(out))
            if not chunk:
                break
            out += chunk
        return out

    def _read_raw_response(self, fh, sock):
        line = fh.readline(65536)
        if not line:
            return None
        parts = line.decode("iso-8859-1", "replace").rstrip("\r\n").split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            return None
        status, reason = int(parts[1]), (parts[2] if len(parts) > 2 else "")
        headers = {}
        while True:
            hl = fh.readline(65536)
            if not hl or hl in (b"\r\n", b"\n"):
                break
            k, _sep, v = hl.decode("iso-8859-1", "replace").partition(":")
            kl, v = k.strip().lower(), v.strip()
            if not kl:
                continue
            # a repeated header is joined, which is exactly how a
            # duplicated Content-Length shows up as an ambiguity
            headers[kl] = headers[kl] + ", " + v if kl in headers else v
        body = b""
        if "chunked" in headers.get("transfer-encoding", "").lower():
            chunks, size = [], 0
            for _ in range(32):            # bounded: never a chunked flood
                sz = fh.readline(65536).strip()
                if not sz:
                    break
                try:
                    size = int(sz.split(b";")[0], 16)
                except ValueError:
                    break
                if size <= 0:
                    fh.readline(65536)      # trailing CRLF, trailers dropped
                    break
                chunks.append(self._read_exact(fh, size))
                fh.readline(65536)
            body = b"".join(chunks)
        elif "content-length" in headers:
            first = headers["content-length"].split(",")[0].strip()
            if first.isdigit():
                body = self._read_exact(fh, min(int(first), 2_000_000))
        else:
            # no framing header: take what arrives, but never block on a
            # response that stays open
            try:
                sock.settimeout(0.5)
                for _ in range(32):
                    chunk = fh.read(8192)
                    if not chunk:
                        break
                    body += chunk
            except OSError:
                pass
            finally:
                sock.settimeout(self.timeout)
        return RawResp(status, headers, body, reason)

    def raw_exchange(self, url, messages, timeout=None):
        """Send pre-serialized HTTP/1.1 messages over ONE keep-alive
        connection and return the responses in order.

        Only the Tier B desync and delimiter probes use this. They need
        the exact octets on the wire: http.client computes its own
        framing and drops a duplicate Content-Length, which is precisely
        the disagreement under test. Both messages are written before
        either response is read, because a desync is only a desync if the
        follow-up is already on the wire. Scope-gated and budgeted like
        request(), one budget tick per message, never retried.
        """
        if not self.in_scope(url):
            raise OutOfScope(url)
        p = urllib.parse.urlsplit(url)
        conn = self._conn(p.scheme, p.hostname,
                          p.port or (443 if p.scheme == "https" else 80))
        conn.timeout = timeout or self.timeout
        out, fh = [], None
        try:
            sock = None
            for msg in messages:
                self._budget()          # may raise BudgetExceeded
                if sock is None:
                    conn.connect()
                    sock = conn.sock
                    sock.settimeout(timeout or self.timeout)
                    fh = sock.makefile("rb")
                sock.sendall(msg)
            if sock is not None:
                for _ in messages:
                    resp = self._read_raw_response(fh, sock)
                    if resp is None:
                        break
                    resp.url = url
                    out.append(resp)
        except (OSError, http.client.HTTPException) as e:
            if not out:                 # partial reads are still data
                raise RuntimeError(f"{type(e).__name__}: {e}")
        finally:
            if fh is not None:
                try:
                    fh.close()
                except Exception:
                    pass
            try:
                conn.close()
            except Exception:
                pass
        return out


class RawResp:
    """A response parsed straight off the socket by Transport.raw_exchange.

    Deliberately not an http.client response: the Tier B probes need the
    bytes the server actually sent, including a duplicated Content-Length,
    which http.client either refuses to hand back or normalizes away
    before we could compare it. Same field names as Resp so the tierb
    modules can treat both alike."""

    def __init__(self, status, headers, body, reason=""):
        self.status = status
        self.headers = headers          # lowercased, repeats joined with ", "
        self.body = body                # bytes
        self.reason = reason
        self.url = ""
        self.redirects = []
        self.elapsed = 0.0

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



    # ---------- raw HTTP/1.1 (Tier B) ----------


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
        self.js_assets = {}
        self.endpoints = set()
        self.script_urls = set()
        self._seen = set()
        # R2: soft-404 profile, scan-quality warnings, degraded checks,
        # authenticated-session verdict, and the passive replay switch.
        # Every new flag is read with getattr so a Namespace built by an
        # older caller (unit_sources.py) still works unchanged.
        self.calibration = Calibration(self)
        self.warnings = []
        # Tier A + C state. Declared here so a scenario that runs either
        # engine finds the attributes, and so a degraded engine leaves an
        # empty list behind instead of raising AttributeError.
        # Tier A/B anomalies. Interesting, needs human review, never a
        # finding: they stay out of counts(), the score, the checklist and
        # the exit code. Shared sink, only `tier` differs.
        self.anomalies = []
        self._anomaly_keys = set()
        self.anomaly_routes = []
        self.anomaly_requests = 0
        self.api_docs = {}            # url -> openapi/swagger text found
        self.tierb = {"desync_requests": 0, "unicode_requests": 0,
                      "delimiter_requests": 0, "api_state_requests": 0,
                      "methods": [], "api_spec_source": ""}
        self.tierc = []
        self.degraded = []
        self.status_counts = {}
        self.responses_seen = 0
        self.auth_state = {"state": "not-checked", "reason": "",
                           "verify_url": "", "marker": ""}
        self.replay = False
        self.replay_map = {}
        self.replay_base = None
        self.replayed = False

    # ---------- plumbing ----------
    def get(self, url, headers=None, method="GET", body=None, follow=True):
        if self.replay:
            # passive replay: answer from stored responses only, never the
            # network. bot.t.used must stay exactly 0 for the whole run.
            r = self.replay_map.get(url)
            if r is None:
                self.note(f"replay: no stored response for {url}")
                return None
            self._track(r)
            return r
        hdrs = dict(headers or {})
        if self.args.cookie and "Cookie" not in hdrs:
            hdrs["Cookie"] = self.args.cookie
        try:
            r = self.t.request(method, url, headers=hdrs, body=body,
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
        self._track(r)
        return r

    def _track(self, resp):
        if resp is None:
            return
        self.responses_seen += 1
        self.status_counts[resp.status] = self.status_counts.get(resp.status, 0) + 1

    ANOMALY_DISCLAIMER = ("INTERESTING, NOT A VULNERABILITY: needs human review")

    def add_anomaly(self, check_id, route="", probe_class="", note="",
                    confidence="low", tier="B", detail="", evidence="",
                    distance=None, status_delta=None, headers_added=None,
                    headers_removed=None, canary_reflected=False,
                    param=None):
        """Record an anomaly. Anomalies are never findings: they never
        enter counts(), the score, the checklist or the exit code, and
        they are never re-verified. Tier A and Tier B share this sink and
        differ only in the `tier` field, so one report section serves
        both. Every record carries the disclaimer sentence verbatim."""
        key = (check_id, route.split("?")[0], probe_class, param or "")
        if key in self._anomaly_keys:
            return None
        self._anomaly_keys.add(key)
        ev = SECRET_RE.sub(lambda m: m.group(1) + "=***REDACTED***",
                           evidence or "")[:600]
        a = {"id": f"A{len(self.anomalies) + 1:03d}", "check_id": check_id,
             "tier": tier, "route": route, "param": param,
             "probe_class": probe_class, "confidence": confidence,
             "distance": distance, "status_delta": status_delta,
             "headers_added": sorted(headers_added or []),
             "headers_removed": sorted(headers_removed or []),
             "canary_reflected": bool(canary_reflected),
             "note": note, "detail": detail, "evidence": ev,
             "title": (CHECKS.get(check_id) or ("", "", "", "", ""))[2],
             "disclaimer": self.ANOMALY_DISCLAIMER}
        self.anomalies.append(a)
        return a

    def note(self, msg):
        if msg not in self.notes:
            self.notes.append(msg)

    def warn(self, code, message):
        """Scan-quality warning. One entry per code, always recorded."""
        if any(w["code"] == code for w in self.warnings):
            return
        self.warnings.append({"code": code, "message": message})

    def degrade(self, who, why):
        self.degraded.append(f"{who}: {why}")

    def add(self, check_id, url="", param=None, severity=None, evidence="",
            fix=None, confidence="high", detail=None, verify=None,
            internal=False, negative=False):
        """Record a finding.

        internal=True  evidence only: stored and reported, but never counted
                       in counts(), the score, checks_fired or the exit code.
        negative=True  the signal is the ABSENCE of something. Scored and
                       counted exactly like a positive finding; the flag only
                       documents that the matcher fires on a missing control.
        """
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
             "internal": bool(internal), "negative": bool(negative),
             "used_cookie": bool(getattr(self.args, "cookie", None)),
             "refs": [OWASP_URL.get(owasp, CHEATSHEET + "Reporting_Cheat_Sheet.html")]}
        self.findings.append(f)
        if verify is not None:
            self._verify[f["id"]] = verify
        return f

    def scored(self):
        """Findings that count: internal evidence records do not."""
        return [f for f in self.findings if not f.get("internal")]

    def evidence_records(self):
        return [f for f in self.findings if f.get("internal")]

    def fired_check_ids(self):
        return {f["check_id"] for f in self.scored()}

    def verify_findings(self):
        for f in list(self.findings):
            if f.get("internal"):
                continue
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
        for f in self.scored():
            w = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2,
                 "INFO": 0}[f["severity"]]
            if not f["verified"] and f["severity"] in ("CRITICAL", "HIGH"):
                w /= 2
            total -= w
        return max(0.0, round(total, 1))

    def counts(self):
        c = {k: 0 for k in SEV_ORDER}
        for f in self.scored():
            c[f["severity"]] += 1
        return c

    # ---------- R2: quality, auth, passive replay ----------
    def soft404_audit(self):
        """(soft404-shaped, genuinely live) counts over the captured pages."""
        soft = live = 0
        for r in self.pages.values():
            if self.calibration.is_not_found(r):
                soft += 1
            elif r.status < 400:
                live += 1
        return soft, live

    def verify_auth(self):
        """M14: one cheap fetch of the verify URL decides whether the cookie
        the operator passed is actually authenticated. Runs after discovery,
        so the first cookie-bearing request has already happened. Without
        --cookie nothing is fetched: there is no session to verify."""
        url = getattr(self.args, "auth_verify_url", None) or (
            self.t.base + self.t.path)
        marker = getattr(self.args, "auth_marker", None) or ""
        cookie = getattr(self.args, "cookie", None)
        if not cookie:
            self.auth_state = {
                "state": "unverified", "verify_url": url, "marker": marker,
                "reason": "no --cookie supplied, so every request in this run "
                          "was anonymous and nothing proves a session"}
            self.recon.append(("auth", "unverified (no --cookie)"))
            return self.auth_state
        r = self.get(url)
        if r is None:
            reason = f"verify url {url} could not be fetched"
        elif LOGIN_RE.search(r.text[:20000]):
            reason = (f"{url} still serves a login or signin form, so the "
                      f"supplied cookie does not authenticate")
        else:
            marker_ok = bool(marker) and marker in r.text
            echo = [c.split(";", 1)[0].split("=", 1)[0].strip()
                    for c in (r.headers.get("set-cookie-list") or [])]
            echo = [c for c in echo if re.search(
                r"(session|sess|sid|token|auth|jwt|phpsess|jsession|connect\.sid)",
                c, re.I)]
            if marker_ok or echo:
                how = ("--auth-marker present" if marker_ok
                       else "session cookie echoed: " + ", ".join(echo))
                self.auth_state = {
                    "state": "verified", "verify_url": url, "marker": marker,
                    "reason": f"{url} returned HTTP {r.status} with no login "
                              f"form and {how}"}
                self.recon.append(("auth", f"verified ({how})"))
                return self.auth_state
            reason = (f"{url} returned HTTP {r.status} with no login form, but "
                      f"neither the --auth-marker nor a session cookie echo "
                      f"was observed")
        self.auth_state = {"state": "unverified", "verify_url": url,
                           "marker": marker, "reason": reason}
        self.recon.append(("auth", f"unverified ({reason[:100]})"))
        return self.auth_state

    def downgrade_cookie_confidence(self):
        """An unverified session means every finding collected with that
        cookie may just be the anonymous view of the page."""
        if not (getattr(self.args, "cookie", None)
                and self.auth_state.get("state") == "unverified"):
            return 0
        n = 0
        for f in self.findings:
            if f.get("used_cookie") and f.get("confidence") == "high":
                f["confidence"] = "medium"
                n += 1
        if n:
            self.note(f"{n} findings downgraded to medium confidence: the "
                      f"supplied cookie could not be verified as authenticated")
        return n

    # ---------- R2: passive replay ----------
    def load_passive_files(self, paths):
        """Read saved HTML into synthetic responses. No request is made."""
        added = []
        for path in paths or []:
            try:
                with open(path, "rb") as fh:
                    data = fh.read(2_000_000)
            except OSError as e:
                self.note(f"passive file unreadable: {path} ({e})")
                continue
            head = data[:600].decode("utf-8", "replace").lower()
            ctype = ("text/html; charset=utf-8"
                     if "<html" in head or "<!doctype" in head
                     else "text/plain; charset=utf-8")
            url = "file://" + os.path.abspath(path)
            self.pages[url] = Resp(200, {
                "content-type": ctype,
                "content-length": str(len(data)),
                "x-qx-passive-file": os.path.abspath(path)},
                data, url, [], 0.0)
            added.append(url)
        if added:
            self.recon.append(("passive files", f"{len(added)} loaded from disk"))
            self.note(f"passive replay: {len(added)} stored response(s), "
                      f"0 requests sent")
        return added

    def enter_replay(self):
        self.replay_map = dict(self.pages)
        self.replay = True
        self.replayed = True

    def exit_replay(self):
        self.replay = False
        self.replay_map = {}
        self.replay_base = None

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
            # Tier C is documentation-only and must work with no reachable
            # target at all; every other scenario needs the seed page.
            if getattr(self.args, "scenario", "") == "tierc" or \
                    getattr(self.args, "tierc_candidates", None):
                self.note("tier C: target unreachable, continuing with "
                          "documentation only (sends nothing)")
                return
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
        # learn the not-found profile once the crawl is done, so every later
        # check (exposures, sweep, scan-quality) shares one verdict
        self.calibration.learn()

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
    # a passive replay points base_page at the stored response being judged
    if getattr(bot, "replay_base", None):
        return bot.replay_base
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
            bot.add("hdr-hsts", url=url, evidence="header absent", verify=vfy,
                    negative=True)
        else:
            m = re.search(r"max-age=(\d+)", h["strict-transport-security"])
            if m and int(m.group(1)) < 86400:
                bot.add("hdr-hsts", url=url, severity="MEDIUM",
                        evidence=h["strict-transport-security"],
                        detail="max-age below one day is too short to protect users")
    if is_html:
        csp = h.get("content-security-policy", "")
        if not csp:
            bot.add("hdr-csp-missing", url=url, evidence="header absent",
                    verify=vfy, negative=True)
        elif re.search(r"script-src[^;]*'unsafe-inline'", csp) or \
                re.search(r"default-src[^;]*'unsafe-inline'", csp) or \
                re.search(r"'unsafe-eval'", csp):
            bot.add("hdr-csp-unsafe", url=url, evidence=csp[:300], verify=vfy)
        if "x-frame-options" not in h and "frame-ancestors" not in csp:
            bot.add("clickjack", url=url, evidence="no XFO and no frame-ancestors",
                    verify=vfy, negative=True)
        if "referrer-policy" not in h:
            bot.add("hdr-referrer", url=url, evidence="header absent",
                    negative=True)
        if "permissions-policy" not in h:
            bot.add("hdr-permissions", url=url, evidence="header absent",
                    negative=True)
        if "cross-origin-opener-policy" not in h:
            bot.add("hdr-coop", url=url, evidence="header absent", negative=True)
        if "cross-origin-resource-policy" not in h:
            bot.add("hdr-corp", url=url, evidence="header absent", negative=True)
        if "x-content-type-options" not in h:
            bot.add("hdr-nosniff", url=url, evidence="header absent",
                    verify=vfy, negative=True)
    for purl, pr in list(bot.pages.items())[:12]:
        if re.search(r"(login|signin|account|dashboard|admin|settings|profile|checkout)",
                     purl, re.I) and "cache-control" not in pr.headers:
            bot.add("hdr-cache-sensitive", url=purl, negative=True,
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
                    negative=True,
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


def secret_hash(value, url):
    """Stable dedupe key for one secret value seen on one URL."""
    return hashlib.sha256((value + "\n" + url).encode("utf-8", "replace")
                          ).hexdigest()[:16]


def make_secret_vfy(bot, url, rx):
    def v():
        rr = bot.get(url)
        return rr is not None and rx.search(rr.text) is not None
    return v


def header_blob(resp):
    """Every header the server sent, as one searchable string."""
    out = []
    for k, v in resp.headers.items():
        if k == "set-cookie-list":
            out.extend(str(x) for x in (v or []))
        else:
            out.append(f"{k}: {v}")
    return "\n".join(out)


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
            f = bot.add("secret-leak", url=src_url, severity=sev, param=name,
                        confidence="medium" if name == "Google API key"
                        else "high",
                        evidence=f"{name} in served content: "
                                 f"{mask_token(raw)} (value redacted)",
                        detail="client-visible secret: treat as compromised, "
                               "rotate it and move it server-side",
                        verify=make_secret_vfy(bot, src_url, rx))
            if f is not None:
                f["secret_hash"] = secret_hash(raw, src_url)


# M8 global matcher sweep: run once over every captured response, body AND
# headers, with the secret patterns plus the stack-trace signatures. Same
# secret on the same URL is reported once, no matter which check found it.
SWEEP_RES = [
    ("Embedded private key",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "CRITICAL"),
    ("AWS access key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "HIGH"),
    ("Stripe live secret", re.compile(r"sk_live_[0-9A-Za-z]{10,}"), "HIGH"),
    ("GitHub token", re.compile(r"ghp_[A-Za-z0-9]{20,}"), "HIGH"),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "HIGH"),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "HIGH"),
    ("OpenAI-style secret key", re.compile(r"(?<![\w-])sk-[A-Za-z0-9]{32,}"),
     "HIGH"),
    ("Bearer credential",
     re.compile(r"(?i)bearer[\"'\s:=]{1,4}[A-Za-z0-9._\-]{25,}"), "HIGH"),
] + [("Stack trace: " + label, re.compile(rx), "HIGH")
     for rx, label in STACK_SIGS]


def sweep_family(name):
    """One stack trace per page is a finding; the rest is noise. Every secret
    pattern keeps its own family so a page carrying two different keys still
    reports both."""
    return "stack-trace" if name.startswith("Stack trace: ") else name


def make_sweep_vfy(bot, url, rx, where):
    def v():
        rr = bot.get(url)
        if rr is None:
            return False
        if where == "body":
            return rx.search(rr.text) is not None
        return rx.search(header_blob(rr)) is not None
    return v


def check_global_sweep(bot):
    reported = {f["secret_hash"] for f in bot.findings
                if f["check_id"] == "secret-leak" and f.get("secret_hash")}
    swept = matched = dupes = collapsed = 0
    seen_family = set()
    for url, r in bot.pages.items():
        for where, text in (("body", r.text), ("header", header_blob(r))):
            if not text or len(text) > 2_000_000:
                continue
            swept += 1
            for name, rx, sev in SWEEP_RES:
                m = rx.search(text)
                if not m:
                    continue
                matched += 1
                fam = (url, sweep_family(name))
                if fam in seen_family:
                    collapsed += 1
                    continue
                seen_family.add(fam)
                raw = m.group(0)
                h = secret_hash(raw, url)
                if h in reported:
                    dupes += 1
                    bot.add("global-secret-sweep", url=url, param=f"dedupe:{name}",
                            internal=True, severity="INFO",
                            evidence=f"{name} on {url} was already reported as "
                                     f"secret-leak (hash {h}); suppressed here so "
                                     f"one secret counts once")
                    continue
                reported.add(h)
                f = bot.add("global-secret-sweep", url=url, param=name,
                            severity=sev,
                            evidence=f"{name} matched in the {where} of this "
                                     f"response: {mask_token(raw)} "
                                     f"(value redacted)",
                            detail="found by the global matcher sweep across "
                                   "every captured response, not only where an "
                                   "exposure probe happened to land",
                            verify=make_sweep_vfy(bot, url, rx, where))
                if f is not None:
                    f["secret_hash"] = h
    bot.add("global-secret-sweep", url=bot.t.base, param="sweep-evidence",
            internal=True, severity="INFO",
            evidence=f"global sweep read {swept} captured response halves "
                     f"({len(bot.pages)} responses, bodies and headers): "
                     f"{matched} pattern matches, {dupes} already reported by "
                     f"secret-leak, {collapsed} more signatures of an already "
                     f"reported class on the same page")


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
                    confidence="medium", negative=True,
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
            evidence="no RFC 9116 security.txt found", negative=True)


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

# ---------- Tier B: empty-taxonomy surface hunting ----------
# CWE-444 has existed since 2008, so the novel part is never a new class
# name, it is a new MECHANISM. TE.0 exists because somebody asked "why is
# there no TE.0?" and then validated the answer against a live target.
# These four modules enumerate the cells nobody has tested instead of
# replaying the classic CL.TE probe.
#
# THE RULE: everything here emits ANOMALIES (bot.anomalies, tier "B"),
# never findings. The single exception is a confirmed desync
# cross-contamination, which IS a finding. Anomalies never touch
# counts(), the score or the exit code.

TIERB_DESYNC_CAP = 8          # hard cap for the whole desync module
TIERB_CHUNK_MAX = 64          # never send a chunked body larger than this
TIERB_BODY_DELTA = 0.15       # normalized body distance that counts as differs
TIERB_STATUS_TOLERANCE = 0    # a status is categorical: any change is a change
TIERB_UNICODE_CAP = 12
TIERB_DELIMITER_CAP = 10
TIERB_API_CAP = 30
DESYNC_CELLS = ("CL", "TE", "0", "H2")


def tierb_base(bot):
    return bot.t.base + (bot.t.path or "/")


def tierb_host_header(bot, url):
    p = urllib.parse.urlsplit(url)
    host = p.hostname or bot.t.host
    default = 443 if p.scheme == "https" else 80
    if p.port and p.port != default:
        return "%s:%d" % (host, p.port)
    return host


def tierb_message(method, target, host_header, headers=None, body=None):
    """Serialize one HTTP/1.1 request as bytes.

    The Tier B probes need byte-exact control of the request line and of
    the framing headers, so they cannot go through http.client: it
    computes its own Content-Length and drops a duplicate one, which is
    exactly the disagreement under test. body is the bytes that follow
    the blank line, never a length of its own.
    """
    lines = ["%s %s HTTP/1.1" % (method, target), "Host: " + host_header,
             "User-Agent: " + UA, "Accept: */*", "Connection: keep-alive"]
    for k, v in (headers or {}).items():
        lines.append("%s: %s" % (k, v))
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1", "replace")
    if body is None:
        return head
    if isinstance(body, str):
        body = body.encode("utf-8", "replace")
    return head + body


def tierb_distance(a, b):
    """Normalized body distance in [0, 1]. 0 means identical once
    canaries, long digit runs and whitespace are normalized away."""
    return 1.0 - difflib.SequenceMatcher(None, norm(a), norm(b)).ratio()


def tierb_notfound(bot, spend):
    """The not-found profile every Tier B differential is measured against.

    R2 (prompt 1) replaces soft404() with a learned Calibration object.
    Until that lands this reuses the single probe soft404() already caches
    on the bot, so nothing is re-fetched and the two can never disagree
    about what "not found" means on this target."""
    if not hasattr(bot, "_soft404"):
        # R2 replaced the old soft404 cache with the learned Calibration
        # object. Callers unpack (status, text), so hand back that pair
        # from the calibration profile instead of the object itself.
        cal = bot.calibration
        if getattr(cal, "ready", False):
            return (getattr(cal, "status", 404) or 404,
                    getattr(cal, "body", "") or "")
        # nothing learned yet (replay or passive): synthesize from the
        # stored pages so the probe still has a comparison baseline
        for _u, _r in (getattr(bot, "pages", None) or {}).items():
            if _r is not None and _r.status >= 400:
                return _r.status, _r.text
        return 404, ""
    if bot._soft404 is None:
        spend()
    status, text = soft404(bot)
    return status, text


def tierb_send(bot, url, messages, label, method="GET"):
    """One raw keep-alive exchange, with the transport errors folded into
    engine notes instead of taking the module down. Every message sent is
    recorded in bot.tierb["methods"], so a QA gate can assert the verb set
    from the bot side as well as from the server side."""
    try:
        responses = bot.t.raw_exchange(url, messages)
    except BudgetExceeded:
        raise
    except OutOfScope as e:
        bot.note("blocked out-of-scope request: %s" % e)
        return []
    except Exception as e:
        bot.note("%s not sent: %s: %s" % (label, type(e).__name__, e))
        return []
    bot.tierb["methods"].extend([method] * len(messages))
    return responses


def tierb_header_delta(a, b):
    return (sorted(set(b.headers) - set(a.headers)),
            sorted(set(a.headers) - set(b.headers)))


# ---------- module 1: the four length-interpretation cells ----------
def tierb_cell_pair(cell, target, host, marker):
    """The two requests for one cell: a setup request whose body embeds the
    per-run canary, then a follow-up GET with a zero-length body.

    Every cell uses GET, never POST. A body-carrying GET is a perfectly
    good smuggling carrier and cannot mutate server state, which the
    safety rails forbid outright. Content-Length and Transfer-Encoding
    are never both attached to a real body, and the chunked body stays
    under TIERB_CHUNK_MAX bytes.
    """
    if cell == "CL":
        setup = tierb_message("GET", target, host, headers={
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(marker))}, body=marker)
    elif cell == "TE":
        if len(marker) > TIERB_CHUNK_MAX:
            return None, None
        chunked = "%x\r\n%s\r\n0\r\n\r\n" % (len(marker), marker)
        setup = tierb_message("GET", target, host, headers={
            "Content-Type": "application/octet-stream",
            "Transfer-Encoding": "chunked"}, body=chunked)
    elif cell == "0":
        # implicit zero: a Content-Length that promises bytes this request
        # never carries, so a hop that trusts CL and a hop that defaults
        # to zero disagree about where the message ends
        setup = tierb_message("GET", target, host, headers={
            "Content-Length": str(len(marker))})
    else:
        return None, None
    follow = tierb_message("GET", target, host,
                           headers={"Content-Length": "0"})
    return setup, follow


def check_desync_cells(bot):
    """Probe CL, TE, 0 and H2 in that order, one keep-alive connection per
    cell, at most two requests per cell, at most 8 requests in total.

    A canary that comes back in the follow-up is cross-contamination and
    is the one thing in Tier B that is a finding. Everything else is a
    differential worth a human's time and nothing more, so it is an
    anomaly.
    """
    if not getattr(bot.args, "desync_probe", False):
        bot.add_anomaly(
            "desync-cells", route=tierb_base(bot), probe_class="not-probed",
            note="desync cells were not probed: pass --desync-probe to walk "
                 "the CL, TE, 0 and H2 length-interpretation cells",
            detail="without the flag this module sends nothing at all")
        return

    used = [0]

    def spend():
        used[0] += 1

    def exhausted():
        return used[0] >= TIERB_DESYNC_CAP

    path = getattr(bot.args, "desync_path", None) or bot.t.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    url = bot.t.base + path
    host = tierb_host_header(bot, url)
    marker = bot.canary + secrets.token_hex(3)      # unique per run, inert
    nf_status, nf_text = tierb_notfound(bot, spend)
    bot.tierb["desync_requests"] = used[0]

    # H2 is recorded first so the cell is accounted for even if the cap
    # stops the loop before it. http.client speaks HTTP/1.1 only, so this
    # cell is detection-only: it is never sent, with or without
    # --allow-h2-probe, which relaxes reporting and nothing else.
    relaxed = getattr(bot.args, "allow_h2_probe", False)
    bot.add_anomaly(
        "desync-cells", route=url, probe_class="H2",
        note="skipped: needs an HTTP/2 client" + (
            "; --allow-h2-probe relaxes reporting only, still nothing sent"
            if relaxed else "; nothing was sent for this cell"),
        detail="HTTP/2 gives the frame its own length, so it is a different "
               "mechanism than HTTP/1.1 framing. Test it with a real HTTP/2 "
               "client (nghttp2, h2load) rather than a desync probe here")

    for cell in ("CL", "TE", "0"):
        if exhausted():
            bot.note("desync module stopped at its %d request cap before "
                     "cell %s" % (TIERB_DESYNC_CAP, cell))
            break
        setup, follow = tierb_cell_pair(cell, path, host, marker)
        if setup is None:
            continue
        responses = tierb_send(bot, url, [setup, follow], "desync cell " + cell)
        used[0] += 2
        bot.tierb["desync_requests"] = used[0]
        if not responses:
            bot.note("desync cell %s: no response to the follow-up" % cell)
            continue
        head, tail = responses[0], responses[-1]
        reflected = marker in tail.text
        dist = tierb_distance(tail.text, nf_text)
        delta = tail.status - nf_status
        added, removed = tierb_header_delta(head, tail)
        if reflected:
            f = bot.add(
                "desync-confirmed", url=url,
                evidence="cell %s: the follow-up response carried the canary "
                         "planted by the setup request on the same connection "
                         "(%s). setup status %s, follow-up status %s, %dB"
                         % (cell, marker, head.status, tail.status,
                            len(tail.body)),
                detail="cross-contamination confirmed: one request was "
                       "answered with bytes queued by another. CWE-444, "
                       "https://cwe.mitre.org/data/definitions/444.html",
                verify=lambda: True)
            if f is not None:
                f["refs"].append(
                    "https://cwe.mitre.org/data/definitions/444.html")
            bot.note("desync confirmed in cell %s, remaining cells skipped"
                     % cell)
            return
        if dist > TIERB_BODY_DELTA or delta != 0:
            bot.add_anomaly(
                "desync-cells", route=url, probe_class=cell,
                distance=round(dist, 3), status_delta=delta,
                headers_added=added, headers_removed=removed,
                canary_reflected=False,
                note="cell %s: the follow-up answered status %s against a "
                     "calibrated not-found baseline of %s, body distance %.2f "
                     "from that profile" % (cell, tail.status, nf_status, dist),
                evidence="setup: %s framing carrying marker %s\n"
                         "follow-up: status %s, %dB, distance %.2f\n"
                         "head excerpt: %r\ntail excerpt: %r"
                         % (cell, marker, tail.status, len(tail.body), dist,
                            head.text[:200], tail.text[:200]))


# ---------- module 2: unicode normalization oracles ----------
# U+212A folds to 'K' and U+FF21 folds to 'A' under NFKC; a base letter
# plus U+0301 is the same grapheme as the precomposed character under NFC
# and a different byte string under NFD. A server that stores one form and
# compares against the other can be made to call two strings one identity.
UNICODE_PROBES = (
    ("U+212A", "\u212a"),
    ("U+FF21", "\uff21"),
    ("U+0301", "e\u0301"),
)


def tierb_codepoints(s):
    return " ".join("U+%04X" % ord(ch) for ch in s)


def tierb_codepoint_names(s):
    out = []
    for ch in s:
        try:
            name = unicodedata.name(ch)
        except ValueError:
            name = "<unnamed>"
        out.append("U+%04X %s" % (ord(ch), name))
    return ", ".join(out)


def tierb_folded_forms(value):
    """Every normalized shape of value that is not the value itself, in the
    order a server is most likely to have applied: NFKC, then the
    precomposed form, then the fully decomposed one."""
    forms = [("NFKC", unicodedata.normalize("NFKC", value))]
    forms.append(("NFC", unicodedata.normalize("NFC",
                                              unicodedata.normalize("NFD",
                                                                    value))))
    forms.append(("NFD", unicodedata.normalize("NFD", value)))
    out, seen = [], set()
    for how, form in forms:
        if form != value and form not in seen:
            seen.add(form)
            out.append((how, form))
    return out


def tierb_with_param(url, param, value):
    p = urllib.parse.urlsplit(url)
    q = dict(kv.split("=", 1) if "=" in kv else (kv, "")
             for kv in p.query.split("&") if kv)
    q[param] = value
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path,
                                    urllib.parse.urlencode(q, doseq=True),
                                    p.fragment))


def tierb_reflected_targets(bot, limit=4):
    """(url, param) pairs whose original value really is reflected in the
    crawled page.

    A parameter that is swallowed by the server cannot leak a
    normalization oracle, so probing it would spend the request cap for
    nothing. The reflected ones are also the only ones where a folded
    form is meaningful, because the baseline already contains the ASCII
    letter a fold would produce.
    """
    out = []
    for url in sorted(bot.params):
        page = bot.pages.get(url)
        if page is None:
            continue
        text = htmllib.unescape(page.text)
        p = urllib.parse.urlsplit(url)
        pairs = dict(kv.split("=", 1) if "=" in kv else (kv, "")
                     for kv in p.query.split("&") if kv)
        for name in bot.params[url]:
            value = urllib.parse.unquote_plus(pairs.get(name, ""))
            if not value or value not in text:
                continue
            out.append((url, name))
            if len(out) >= limit:
                return out
    return out


def check_unicode_oracles(bot):
    """Send three confusable values to every reflected query parameter and
    compare what came back against what was sent.

    The oracle is not "is the value reflected", it is "is the stored form
    the same as the sent form". A folded form is only interesting where
    the page did not already contain it, so each candidate is checked
    against the crawled baseline for that URL. Every value is inert and
    sent once. Cap: 12 requests.
    """
    targets = tierb_reflected_targets(bot)
    if not targets:
        bot.add_anomaly(
            "unicode-oracle", route=tierb_base(bot), probe_class="no-params",
            note="no reflected query parameter was discovered, so no "
                 "normalization oracle could be tested",
            detail="crawl a page that reflects a query value (a search page "
                   "will do) and re-run with --tierb")
        return
    sent = 0
    for url, param in targets:
        cached = bot.pages.get(url)
        baseline = htmllib.unescape(cached.text) if cached is not None else None
        if baseline is None:
            neutral = tierb_with_param(url, param, "qxprobe")
            base_r = bot.get(neutral)
            sent += 1
            bot.tierb["unicode_requests"] = sent
            baseline = htmllib.unescape(base_r.text) if base_r else ""
        for label, value in UNICODE_PROBES:
            if sent >= TIERB_UNICODE_CAP:
                bot.note("unicode oracle probes stopped at the %d request cap"
                         % TIERB_UNICODE_CAP)
                return
            r = bot.get(tierb_with_param(url, param, value))
            sent += 1
            bot.tierb["unicode_requests"] = sent
            if r is None:
                continue
            text = htmllib.unescape(r.text)
            if value in text:
                continue                      # stored exactly as sent
            for how, form in tierb_folded_forms(value):
                if form in baseline:
                    continue                  # the page already had it
                if form not in text:
                    continue
                bot.add_anomaly(
                    "unicode-oracle", route=url, param=param,
                    probe_class="%s/%s" % (label, how), canary_reflected=True,
                    note="the server returned the %s form of the value "
                         "instead of the bytes that were sent: sent %s, "
                         "stored %s" % (how, tierb_codepoints(value),
                                       tierb_codepoints(form)),
                    detail="an identity comparison between the two forms "
                           "would not match. sent: %s. stored: %s"
                           % (tierb_codepoint_names(value),
                              tierb_codepoint_names(form)),
                    evidence="value=%r returned form=%r" % (value, form))
                break


# ---------- module 3: delimiter confusion ----------
# ; . and %2e are the three a cache and an origin most often normalize
# differently, and the fragment is the one that never belongs on the wire
# at all. A status change is loud; two hops returning different bytes for
# the same status is the cache-poisoning precondition. Cap: 10 requests.
DELIMITER_VARIANTS = (
    ("semicolon", ";"),
    ("query", "?"),
    ("fragment", "#"),
    ("trailing-dot", "."),
    ("encoded-dot", "%2e"),
)


def tierb_delimiter_baseline(bot):
    forced = getattr(bot.args, "delimiter_path", None)
    if forced:
        path = forced if forced.startswith("/") else "/" + forced
        url = bot.t.base + path
        r = bot.pages.get(url) or bot.get(url)
        return (url, urlsplit_path(url), r) if r is not None else (None, None, None)
    for cand in sorted(bot.pages):
        path = urlsplit_path(cand)
        page = bot.pages.get(cand)
        if path and "?" not in path and page is not None and page.status == 200:
            return cand, path, page
    url = tierb_base(bot)
    r = bot.pages.get(url) or bot.get(url)
    return (url, urlsplit_path(url), r) if r is not None else (None, None, None)


def check_delimiter_confusion(bot):
    """Append five delimiter variants to one crawled GET path and see
    whether anything downstream still agrees on what the path is.

    The delimiter goes on the wire exactly as written: a fragment quietly
    stripped by the client library would test nothing at all.
    """
    url, path, base = tierb_delimiter_baseline(bot)
    if not url or base is None:
        bot.add_anomaly(
            "delimiter-confusion", route=tierb_base(bot),
            probe_class="no-baseline",
            note="no crawled GET path had a baseline response, so no "
                 "delimiter variant could be compared",
            detail="crawl at least one 200 page first, or pass "
                   "--delimiter-path PATH")
        return
    host = tierb_host_header(bot, url)
    sent = 0
    for name, delim in DELIMITER_VARIANTS:
        if sent >= TIERB_DELIMITER_CAP:
            bot.note("delimiter probes stopped at the %d request cap"
                     % TIERB_DELIMITER_CAP)
            break
        raw = path + delim
        responses = tierb_send(bot, url, [tierb_message("GET", raw, host)],
                               "delimiter variant " + name)
        sent += 1
        bot.tierb["delimiter_requests"] = sent
        if not responses:
            continue
        r = responses[0]
        dist = tierb_distance(r.text, base.text)
        same_status = r.status == base.status
        if same_status and dist <= TIERB_BODY_DELTA:
            continue
        added, removed = tierb_header_delta(base, r)
        bot.add_anomaly(
            "delimiter-confusion", route=url, probe_class=name,
            distance=round(dist, 3), status_delta=r.status - base.status,
            headers_added=added, headers_removed=removed,
            note=("%s: %r returned status %s against a baseline of %s, body "
                  "distance %.2f" % (
                      "cache and origin may disagree on the path"
                      if same_status else
                      "status changed for a delimited variant",
                      raw, r.status, base.status, dist)),
            evidence="baseline %r status %s %dB\nvariant %r status %s %dB"
                     % (path, base.status, len(base.body), raw, r.status,
                        len(r.body)))


# ---------- module 4: documented API state walk ----------
API_SPEC_PATHS = ("/openapi.json", "/swagger.json", "/api-docs",
                  "/v3/api-docs", "/api/openapi.json")
API_NEVER_SEND = ("delete", "put", "patch")


def tierb_spec_paths(text):
    try:
        doc = json.loads(text)
    except Exception:
        return {}
    if not isinstance(doc, dict):
        return {}
    paths = doc.get("paths")
    return paths if isinstance(paths, dict) else {}


def tierb_api_doc(bot, spend):
    """The OpenAPI document: --api-spec first, then whatever exp-api-docs
    already found this run, then the usual public locations."""
    src = getattr(bot.args, "api_spec", None)
    if src:
        try:
            with open(src, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            bot.note("--api-spec %s unreadable: %s" % (src, e))
        else:
            if tierb_spec_paths(text):
                return text, "file:" + src
            bot.note("--api-spec %s parsed but declares no paths" % src)
    for url, text in sorted(bot.api_docs.items()):
        if tierb_spec_paths(text):
            return text, "discovered:" + url
    for path in API_SPEC_PATHS:
        spend()
        r = bot.get(bot.t.base + path)
        if r is not None and r.status == 200 and tierb_spec_paths(r.text):
            return r.text, "fetched:" + path
    return None, ""


def tierb_iter_params(path_item, operation):
    """Declared parameters for a path template, path level first."""
    out = []
    for src in (path_item if isinstance(path_item, dict) else {},):
        if isinstance(src.get("parameters"), list):
            out.extend(p for p in src["parameters"] if isinstance(p, dict))
    op = (path_item or {}).get(operation) or {}
    if isinstance(op.get("parameters"), list):
        out.extend(p for p in op["parameters"] if isinstance(p, dict))
    return out


def tierb_inert_value(bot, path_item, operation):
    """Exactly ONE inert value per documented path.

    The candidates are ordered by how likely they are to name an object
    that really exists, because a differential only shows up when one
    does: 0 for an unconstrained integer, 1 when the spec sets a minimum
    above 0, and an inert canary string for anything non-numeric.
    """
    schema = {}
    for p in tierb_iter_params(path_item, operation):
        if isinstance(p.get("schema"), dict):
            schema = p["schema"]
            break
    if str(schema.get("type", "")).lower() in ("integer", "number"):
        try:
            if float(schema.get("minimum", 0)) >= 1:
                return "1"
        except (TypeError, ValueError):
            pass
        return "0"
    return bot.canary + "z"


def tierb_fill(tpl, value):
    return re.sub(r"\{[^}]+\}",
                  lambda _m: urllib.parse.quote(value, safe=""), tpl)


def tierb_dummy_body(path_item, operation):
    """Scanner-owned dummy values only: never anything lifted from the
    target, never anything that could create a real record."""
    op = (path_item or {}).get(operation) or {}
    content = ((op.get("requestBody") or {}).get("content") or {})
    for _ct, media in content.items():
        schema = ((media or {}).get("schema") or {})
        props = schema.get("properties")
        if isinstance(props, dict):
            return {name: "QX-probe-dummy" for name in list(props)[:10]}
        return {"probe": "QX-probe-dummy"}
    return {"probe": "QX-probe-dummy"}


def check_api_states(bot):
    """Walk the documented object paths the way an unauthenticated caller
    would and report any authorization differential as an anomaly.

    One inert value per path, never DELETE, PUT or PATCH, and POST only
    when the spec marks the operation and --allow-spec-post was given,
    with a body of scanner-owned dummy values. A single anonymous read
    that differs from the collection baseline is NOT a proven BOLA:
    confirming it needs a second owner-provided account, so it stays an
    anomaly at medium confidence. Cap: 30 requests.
    """
    used = [0]

    def spend():
        used[0] += 1

    text, source = tierb_api_doc(bot, spend)
    bot.tierb["api_spec_source"] = source
    bot.tierb["api_state_requests"] = used[0]
    paths = tierb_spec_paths(text or "")
    templates = sorted(p for p in paths
                       if isinstance(p, str) and "{" in p and "}" in p)
    if not templates:
        bot.add_anomaly(
            "api-state-authz", route=tierb_base(bot), probe_class="no-spec",
            note="no OpenAPI document declaring {param} paths was available, "
                 "so no authorization differential could be tested",
            detail="spec source: %s. pass --api-spec FILE, or publish the "
                   "document (an exposed spec is itself the finding "
                   "exp-api-docs)" % (source or "none"))
        return

    baselines = {}

    def collection(tpl):
        coll = re.sub(r"\{[^}]+\}", "", tpl).rstrip("/") or "/"
        if coll not in baselines:
            url = bot.t.base + coll
            r = bot.pages.get(url)
            if r is None:
                spend()
                r = bot.get(url)
            baselines[coll] = r
        return baselines[coll]

    for tpl in templates:
        if used[0] >= TIERB_API_CAP:
            bot.note("api state walk stopped at the %d request cap"
                     % TIERB_API_CAP)
            break
        item = paths[tpl] if isinstance(paths[tpl], dict) else {}
        ops = [k for k in item
               if isinstance(k, str) and k.lower() not in API_NEVER_SEND
               and k.lower() not in ("parameters", "$ref", "summary",
                                     "description", "servers")]
        plans = ["get"] if "get" in [o.lower() for o in ops] else []
        if ("post" in [o.lower() for o in ops]
                and getattr(bot.args, "allow_spec_post", False)):
            plans.append("post")
        for operation in plans:
            if used[0] >= TIERB_API_CAP:
                break
            method = operation.upper()
            if method not in ("GET", "POST"):
                continue                  # belt and braces: nothing else ships
            value = tierb_inert_value(bot, item, operation)
            item_path = tierb_fill(tpl, value)
            url = bot.t.base + item_path
            host = tierb_host_header(bot, url)
            headers = {"Accept": "application/json"}
            body = None
            if method == "POST":
                headers["Content-Type"] = "application/json"
                headers["Content-Length"] = str(
                    len(json.dumps(tierb_dummy_body(item, operation))))
                body = json.dumps(tierb_dummy_body(item, operation))
            responses = tierb_send(
                bot, url, [tierb_message(method, item_path, host, headers,
                                         body)], "api state " + method,
                method)
            used[0] += 1
            bot.tierb["api_state_requests"] = used[0]
            if not responses:
                continue
            r = responses[0]
            # a refusal is a refusal, not a leak: 401/403/404, a redirect
            # to a login page, or a server error tells us nothing either way
            if r.status in (401, 403, 404) or r.status >= 300:
                continue
            base = collection(tpl)
            bot.tierb["api_state_requests"] = used[0]
            base_status = base.status if base is not None else 0
            base_text = base.text if base is not None else ""
            dist = tierb_distance(r.text, base_text)
            if r.status == base_status and dist <= TIERB_BODY_DELTA:
                continue
            if not r.body.strip() or r.body.strip() in (b"[]", b"{}"):
                continue                  # an empty collection, not an object
            bot.add_anomaly(
                "api-state-authz", route=url, param=value, confidence="medium",
                probe_class="%s %s" % (method, tpl),
                distance=round(dist, 3),
                status_delta=r.status - base_status,
                canary_reflected=True,
                note="an unauthenticated %s of one object answered %s with "
                     "%dB while the anonymous collection baseline answered "
                     "%s (body distance %.2f); not a proven BOLA, needs a "
                     "second owner-provided account to confirm"
                     % (method, r.status, len(r.body), base_status, dist),
                detail="the differential is against %s, the collection path "
                       "for %s. A single anonymous read cannot separate "
                       "'public by design' from 'someone else's object', so "
                       "this stays an anomaly until a second owner-provided "
                       "account is in the test plan" % (urlsplit_path(
                           re.sub(r"\{[^}]+\}", "", tpl).rstrip("/") or "/"),
                           tpl),
                evidence="value=%r status=%s %dB\n%s"
                         % (value, r.status, len(r.body), r.text[:400]))
# Tier A anomaly engine (Red Queen v2.0).
#
# THE RULE: an anomaly is NOT a vulnerability. Every record this module builds
# goes into bot.anomalies and nowhere else. It never touches bot.findings, so
# counts(), score(), verify_findings() and the exit code cannot see it. The
# only thing an anomaly asks for is a human reading it.

ANOMALY_BANNER = "INTERESTING, NOT A VULNERABILITY: needs human review."
ANOMALY_NOISE_FLOOR = 0.15     # body match above this with no canary echo = noise
ANOMALY_PROBES_PER_ROUTE = 9  # hard cap, prompt 2 step 2
ANOMALY_REQUEST_BUDGET = 120   # hard cap for the whole engine, prompt 2 step 2
ANOMALY_CAP_MAX = 20           # --anomaly-cap ceiling, prompt 2 step 6
ANOMALY_CANARY_RE = re.compile(r"QX[a-f0-9]+")
ANOMALY_CANARY_TOK = "QXCANARY"
ANOMALY_HOST_SUFFIX = ".qx-probe.invalid"
ANOMALY_HEADERS = ("X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL")
ANOMALY_SUFFIXES = (".css", ".png", ".js")
ANOMALY_METHODS = ("HEAD", "OPTIONS")


def anomaly_norm(text):
    """Body normalization for fingerprinting and matching: canaries to one
    fixed token, then the shared norm() (digit runs of 3+ and whitespace runs
    collapsed). Runs before norm() so a random canary cannot inflate the
    distance on its own."""
    return norm(ANOMALY_CANARY_RE.sub(ANOMALY_CANARY_TOK, text or ""))


def anomaly_header_names(resp):
    """Response header names as a set. set-cookie-list is our own transport
    bookkeeping, not a header the server sent."""
    return {k for k in resp.headers if k != "set-cookie-list"}


def anomaly_not_found(bot, resp):
    """Is this response the site-wide not-found shape? Prefers the R2
    Calibration profile when that release is present, falls back to the v1.1.0
    soft-404 probe. Both mean the same thing here: a difference against this
    shape is routing noise, never a signal."""
    cal = getattr(bot, "calibration", None)
    if cal is not None and hasattr(cal, "is_not_found"):
        try:
            return bool(cal.is_not_found(resp))
        except BudgetExceeded:
            raise
        except Exception:
            pass
    try:
        return bool(is_soft404(bot, resp))
    except BudgetExceeded:
        raise
    except Exception:
        return False


def anomaly_routes(bot):
    """Crawled routes worth probing, target first, then crawl order, capped so
    that cap-per-route x routes stays inside the engine request budget."""
    base = bot.t.base + bot.t.path
    order = []
    if base in bot.pages:
        order.append(base)
    order += [u for u in bot.pages if u != base]
    room = max(1, ANOMALY_REQUEST_BUDGET // ANOMALY_PROBES_PER_ROUTE)
    return order[:room]


def anomaly_baseline(bot, route):
    """Per-route baseline record, taken from the response the crawl already
    holds, so building it costs zero requests."""
    r = bot.pages.get(route)
    if r is None:
        return None
    body = anomaly_norm(r.text)
    return {"route": route, "status": r.status, "length": len(r.body),
            "headers": sorted(anomaly_header_names(r)),
            "header_set": anomaly_header_names(r),
            "content_type": r.header("content-type"),
            "body_fp": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest(),
            "body": body, "resp": r}


def anomaly_probes(route, canary, rotation=0, cap=ANOMALY_PROBES_PER_ROUTE):
    """Probe shapes for one route, in the five classes of the contract:
    header canary, path suffix, path delimiter, method variant, accept
    variant. GET-safe methods only (GET, HEAD, OPTIONS), never a body.

    Every probe carries the per-run canary so canary_reflected means something
    for all five classes: in the header value for class a, as a benign
    qxcanary query parameter for the rest (the path shape stays exactly as
    specified).

    A route may cost at most `cap` requests, and the five classes hold 13
    shapes, so the plan is class balanced: every class offers its first
    variant, then its second, and so on. The rotation shifts each class by the
    route index, so a crawl of several routes exercises all 13 shapes instead
    of starving the tail classes forever.
    """
    p = urllib.parse.urlsplit(route)
    path = p.path or "/"
    host = canary + ANOMALY_HOST_SUFFIX

    def build(new_path):
        q = p.query
        q = (q + "&" if q else "") + "qxcanary=" + canary
        return urllib.parse.urlunsplit((p.scheme, p.netloc, new_path, q, ""))

    def rot(items, n):
        n = n % len(items)
        return items[n:] + items[:n]

    header = [{"probe_class": "header-canary", "variant": h, "method": "GET",
               "url": build(path), "headers": {h: host}}
              for h in ANOMALY_HEADERS]
    suffix = [{"probe_class": "path-suffix", "variant": s, "method": "GET",
               "url": build(path + s), "headers": {}}
              for s in ANOMALY_SUFFIXES]
    # a bare "?" cannot be the last byte of a path (the request line would read
    # it as the query separator), so the trailing question mark goes out
    # percent-encoded and stays a real path byte.
    delimiter = [{"probe_class": "delimiter", "variant": label, "method": "GET",
                  "url": build(path + tail), "headers": {}}
                 for label, tail in (("trailing semicolon", ";"),
                                     ("trailing question mark", "%3f"),
                                     ("trailing dot", "."),
                                     ("percent-encoded dot segment", "/%2e"))]
    method = [{"probe_class": "method", "variant": m, "method": m,
               "url": build(path), "headers": {}}
              for m in ANOMALY_METHODS]
    accept = [{"probe_class": "accept", "variant": "text/plain", "method": "GET",
               "url": build(path), "headers": {"Accept": "text/plain"}}]
    groups = [rot(g, rotation) for g in (header, suffix, delimiter, method,
                                         accept)]
    plan, i = [], 0
    while len(plan) < cap:
        added = False
        for g in groups:
            if i < len(g):
                plan.append(g[i])
                added = True
                if len(plan) >= cap:
                    break
        if not added:
            break
        i += 1
    return plan


def anomaly_probe(bot, route, base, probe, canary, keep_all=False):
    """Run one probe and turn it into a record, or None when the filter says
    the response is noise."""
    r = bot.get(probe["url"], headers=probe["headers"] or None,
                method=probe["method"], follow=True)
    if r is None:
        return None
    if anomaly_not_found(bot, r):
        return None
    ratio = difflib.SequenceMatcher(None, anomaly_norm(r.text),
                                    base["body"]).ratio()
    distance = round(ratio, 3)
    names = anomaly_header_names(r)
    reflected = (canary in r.text
                 or any(canary in str(v) for v in r.headers.values()))
    added = sorted(names - base["header_set"])
    removed = sorted(base["header_set"] - names)
    delta = r.status - base["status"]
    bodyless = not r.body
    if not keep_all and not reflected:
        if distance > ANOMALY_NOISE_FLOOR:
            return None          # body still matches the baseline, nothing echoed
        if bodyless and delta == 0 and not added and not removed:
            # a HEAD (or empty) response has no body to match, so the only
            # remaining evidence is status and headers, and neither moved
            return None
    in_body = canary in r.text
    in_hdr = any(canary in str(v) for v in r.headers.values())
    echo = "body and headers" if (in_body and in_hdr) else \
        ("body" if in_body else "headers")
    match = ("no body to compare" if bodyless
             else f"body match {distance} against baseline")
    note = (f"{probe['variant']} probe: status {r.status} against baseline "
            f"{base['status']} (delta {delta:+d}), {match}, headers "
            f"+{len(added)}/-{len(removed)}, "
            + (f"canary echoed in {echo}" if reflected else "no canary echo")
            + f". {ANOMALY_BANNER}")
    return {"route": route, "probe_class": probe["probe_class"],
            "distance": distance, "status_delta": delta,
            "headers_added": added, "headers_removed": removed,
            "canary_reflected": reflected, "note": note,
            "confidence": "low", "text": ANOMALY_BANNER}


def check_anomaly(bot):
    """Tier A differential engine. One baseline per crawled route, a capped
    set of read-only probes per route, a body match plus header set difference
    per probe, then filter, rank and cap. Findings stay untouched."""
    cap = max(0, min(int(getattr(bot.args, "anomaly_cap", 5) or 0),
                     ANOMALY_CAP_MAX))
    keep_all = bool(getattr(bot.args, "anomaly_keep_all", False))
    canary = bot.canary
    start_used = bot.t.used

    def spent():
        return bot.t.used - start_used

    try:
        for n, route in enumerate(anomaly_routes(bot)):
            if spent() >= ANOMALY_REQUEST_BUDGET:
                bot.note(f"anomaly engine stopped at its {ANOMALY_REQUEST_BUDGET} "
                         f"request budget after {len(bot.anomaly_routes)} routes")
                break
            base = anomaly_baseline(bot, route)
            if base is None:
                continue
            recs, sent, dropped = [], 0, 0
            for probe in anomaly_probes(route, canary, n):
                if spent() >= ANOMALY_REQUEST_BUDGET:
                    bot.note(f"anomaly engine hit its {ANOMALY_REQUEST_BUDGET} "
                             f"request budget on {route}")
                    break
                sent += 1
                rec = anomaly_probe(bot, route, base, probe, canary, keep_all)
                if rec is None:
                    dropped += 1
                else:
                    recs.append(rec)
            # rank ascending by body match, so the responses that drifted
            # furthest from the baseline come first
            kept = sorted(recs, key=lambda r: (r["distance"], r["probe_class"]))[:cap]
            bot.anomalies.extend(kept)
            bot.anomaly_routes.append(
                {"route": route, "status": base["status"],
                 "length": base["length"], "headers": base["headers"],
                 "content_type": base["content_type"],
                 "body_fp": base["body_fp"], "probes": sent,
                 "filtered": dropped, "anomalies": len(kept)})
    finally:
        for rec in (bot.anomalies or []):
            rec.setdefault("tier", "A")
        bot.anomaly_requests = spent()
    bot.recon.append(("anomaly probes", f"{bot.anomaly_requests} requests, "
                        f"{len(bot.anomalies)} anomalies kept"))
    bot.note("anomaly engine: records are review material only, they are not "
             "findings and never move the score, the counts or the exit code")


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
    shown = sorted(bot.scored(), key=lambda f: (SEV_ORDER[f["severity"]],
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
    ev = bot.evidence_records()
    if ev:
        out.append("")
        out.append(colorize("  EVIDENCE RECORDS (not scored, not counted)",
                            "dim", c))
        for f in ev:
            out.append(colorize(f"   · {f['check_id']} [{f['param'] or ''}] "
                                f"{f['evidence'][:96]}", "dim", c))
    out.append("")
    out.extend(scan_quality_lines(bot, c))
    st = bot.auth_state.get("state", "not-checked")
    out.append("    auth  " + colorize(st, "green" if st == "verified"
                                       else "MEDIUM", c) + ": " +
               (bot.auth_state.get("reason") or "no auth verdict this run"))
    cov = coverage_statement(bot)
    out.append("    " + colorize(coverage_line(bot, cov), "dim", c))
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
    order = sorted(bot.scored(), key=lambda f: (SEV_ORDER[f["severity"]],
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


# R2 coverage accounting. NEVER_TESTED is static and deliberate: these
# vulnerability classes are out of scope for an automated pass, and saying
# so out loud is more honest than a green tick.
NEVER_TESTED = [
    {"class": "DoS and resource exhaustion",
     "reason": "no denial-of-service testing at all: a bot that hammers a "
               "host is indistinguishable from an attack"},
    {"class": "API6 sensitive business flows",
     "reason": "workflow logic (payments, refunds, limits, state machines) "
               "needs a human who knows the intended business rules"},
    {"class": "DOM and browser-only XSS",
     "reason": "no JavaScript engine here: DOM sinks, prototype pollution and "
               "client-side storage need a real browser session"},
    {"class": "request smuggling escalation",
     "reason": "only the detection half is in scope; storing a poisoned "
               "response or poisoning a response queue would mutate shared "
               "infrastructure and can affect other users"},
    {"class": "cross-account mutation",
     "reason": "proving cross-account access needs two owner-provided "
               "accounts, and the bot only ever has anonymous plus at most "
               "one --cookie identity"},
    {"class": "HTTP/2 CONTINUATION flood and Rapid Reset",
     "reason": "these are availability attacks by construction; active "
               "probing is refused, and http.client cannot speak HTTP/2"},
]
# checks that a scenario can nominally run but that can never fire on this
# target shape. Used as the reason string when coverage says not tested.
NOT_TESTED_CONDITION = {
    "no-tls": "only observable on an http:// target",
    "hdr-hsts": "only observable on an https:// target",
    "cookie-secure": "only observable on an https:// target",
    "cookie-plaintext": "only observable on an http:// target",
    "tls-legacy": "needs a TLS endpoint to downgrade",
    "tls-expiry": "needs a TLS endpoint",
    "tls-unverified": "needs a TLS endpoint",
    "mixed-content": "only observable on an https:// target",
    "subdomain-dangling": "only runs with --ct-log",
}


def coverage_statement(bot):
    """One row per check id in CHECKS: was it exercised this run, and if not,
    why not. Exercised means it fired, or its group is part of the scenario
    and therefore ran (and found nothing)."""
    fired = bot.fired_check_ids()
    if getattr(bot, "replayed", False):
        scope = set(PASSIVE_SCOPE)
    else:
        scope = set()
        for group in SCENARIOS.get(bot.args.scenario, []):
            scope.update(GROUPS.get(group, []))
    rows = []
    for cid in sorted(CHECKS):
        owasp, sev, title, _impact, _fix = CHECKS[cid]
        tested = cid in fired or cid in scope
        if tested:
            reason = ""
        elif cid in NOT_TESTED_CONDITION:
            reason = NOT_TESTED_CONDITION[cid]
        else:
            reason = (f"not exercised by scenario '{bot.args.scenario}'"
                      if not getattr(bot, "replayed", False)
                      else "not exercised: a passive replay only runs the "
                           "response-only checks")
        rows.append({"check_id": cid, "owasp": owasp, "severity": sev,
                     "title": title, "tested": tested, "reason": reason})
    return rows


def coverage_line(bot, rows):
    done = sum(1 for r in rows if r["tested"])
    return (f"coverage: {done}/{len(rows)} checks exercised, "
            f"{len(NEVER_TESTED)} classes never tested by design")


def scan_quality_lines(bot, use_color):
    """Terminal SCAN QUALITY block."""
    out = [colorize("  SCAN QUALITY", "bold", use_color)]
    if not bot.warnings:
        out.append("    " + colorize("ok  no scan-quality warnings",
                                     "green", use_color))
        return out
    for w in bot.warnings:
        out.append("    " + colorize("!", "MEDIUM", use_color) + " " +
                   f"{w['code']:<22} {w['message']}")
    return out


def json_report(bot):
    coverage = coverage_statement(bot)
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
        "calibration": bot.calibration.profile(),
        "auth_state": bot.auth_state,
        "passive": {"replay": bool(getattr(bot, "replayed", False)),
                    "requests_used": bot.t.used,
                    "zero_requests": bot.t.used == 0,
                    "responses_replayed": len(bot.pages) if
                    getattr(bot, "replayed", False) else 0},
        "warnings": bot.warnings,
        "degraded_checks": bot.degraded,
        "coverage": coverage,
        "coverage_summary": coverage_line(bot, coverage),
        "never_tested": NEVER_TESTED,
        "notes": bot.notes,
        "findings": bot.findings,
        "evidence_records": [{"id": f["id"], "check_id": f["check_id"],
                              "url": f["url"], "param": f["param"],
                              "evidence": f["evidence"]}
                             for f in bot.evidence_records()],
        "endpoints": sorted(bot.endpoints),
        "js_assets": sorted(bot.js_assets),
        "checks_available": len(CHECKS),
        "checks_fired": sorted(bot.fired_check_ids()),
        # Tier A + C output. Anomalies are review material, never findings,
        # so they are reported in their own key and counted in nothing.
        "anomalies": getattr(bot, "anomalies", []) or [],
        "anomaly_requests": getattr(bot, "anomaly_requests", 0),
        "anomaly_routes": getattr(bot, "anomaly_routes", []) or [],
        "tierc": getattr(bot, "tierc", []) or [],
        "tierb": dict(getattr(bot, "tierb", {}) or {}),
    }, indent=2)


# Tier C: human-in-the-loop research pipeline.
# This module never sends a request. It turns anomalies and hand-written
# candidates into dossiers a human can act on, and it enforces the rails
# mechanically: a candidate that needs a destructive action is marked
# OUT OF SCOPE and gets no repro template.

TIERC_MAX_REQUESTS = 8
TIERC_SAFE_METHODS = ("GET", "HEAD", "OPTIONS", "POST")
TIERC_DESTRUCTIVE = ("DELETE", "PUT", "PATCH")
TIERC_METADATA = "169.254.169.254"
TIERC_CANARY_RE = re.compile(r"QX[0-9a-f]{4,}")
TIERC_FLOOD_RE = re.compile(
    r"(?i)(flood|denial[\s-]of[\s-]service|\bdos\b|slowloris|amplif\w+|"
    r"concurren\w*|parallel requests|many requests at once|rapid reset|"
    r"keep[\s-]?alive (storm|abuse)|pummel|pound|threaded for)")

# a body value the scanner itself invented: canaries, the literal CANARY
# placeholder, inert counters, and the dummy login the rate-limit check uses
TIERC_OWNED_VALUE = re.compile(
    r"^(QX[0-9a-f]{2,}|CANARY|0|1|true|false|null|none|test|dummy|inert"
    r"|qx_[a-z0-9_@.]*|qx\.[a-z0-9_@.]+|definitelynotarealpass!1)$", re.I)


def tierc_mask(text):
    """Mask every secret pattern the auth module knows, then key=value
    secrets. Dossiers are written to disk and pasted into tickets, so a
    raw secret must never survive the trip."""
    out = str(text or "")
    for _name, rx, _sev in SECRET_RES:
        out = rx.sub(lambda m: mask_token(m.group(0)), out)
    out = SECRET_RE.sub(lambda m: m.group(1) + "=***REDACTED***", out)
    return out


def tierc_canary(text):
    """Swap the run-unique canary for a literal placeholder so the repro
    template is inert as written."""
    return TIERC_CANARY_RE.sub("CANARY", str(text or ""))


def tierc_safe_id(raw):
    cid = re.sub(r"[^A-Za-z0-9._-]+", "-", str(raw or "")).strip("-")
    return cid or "UNNAMED"


def _body_owned(body):
    """True when every value in the body is a scanner-owned inert value.
    A body the operator would have to fill with real data is not a repro
    template, it is a destructive action waiting to happen."""
    b = str(body or "").strip()
    if not b:
        return True, ""
    if b[0] in "{[":
        try:
            parsed = json.loads(b)
        except Exception:
            return False, "body looks like JSON but does not parse, ownership unverifiable"
        vals = []

        def walk(node):
            if isinstance(node, dict):
                for v in node.values():
                    walk(v)
            elif isinstance(node, (list, tuple)):
                for v in node:
                    walk(v)
            else:
                vals.append(str(node))

        walk(parsed)
    elif "=" in b:
        vals = [kv.split("=", 1)[1] for kv in b.split("&") if "=" in kv]
    else:
        vals = [b]
    for v in vals:
        if not TIERC_OWNED_VALUE.match(v.strip()):
            return False, f"body value {v[:40]!r} is not scanner-owned"
    return True, ""


def tierc_rails(candidate):
    """Read the candidate and decide whether documenting it is inside the
    rails. Returns (out_of_scope, [(rail, detail), ...])."""
    repro = candidate.get("repro") or []
    if not isinstance(repro, list):
        return True, [("malformed", "repro is not a list of requests")]
    hits = []

    if len(repro) > TIERC_MAX_REQUESTS:
        hits.append(("request-count",
                     f"{len(repro)} requests, cap is {TIERC_MAX_REQUESTS}"))

    for i, req in enumerate(repro, 1):
        if not isinstance(req, dict):
            hits.append(("malformed", f"repro[{i}] is not an object"))
            continue
        method = str(req.get("method") or "GET").strip().upper()
        url = str(req.get("url") or "")
        body = req.get("body")
        headers = req.get("headers") or {}
        if method not in TIERC_SAFE_METHODS:
            why = ("destructive method" if method in TIERC_DESTRUCTIVE
                   else "method outside the scanner allowlist")
            hits.append(("destructive-method",
                         f"request {i} uses {method} ({why})"))
        if TIERC_METADATA in url:
            hits.append(("cloud-metadata",
                         f"request {i} targets the cloud metadata service"))
        haystack = " ".join([url, str(body or "")] +
                            [f"{k}: {v}" for k, v in (headers.items()
                                                       if isinstance(headers, dict)
                                                       else [])] +
                            [str(req.get(k) or "")
                             for k in ("notes", "intent", "description")] +
                            [str(candidate.get("notes") or "")])
        fm = TIERC_FLOOD_RE.search(haystack)
        if fm:
            hits.append(("flood-or-concurrency",
                         f"request {i} hints at load or concurrency ({fm.group(0)})"))
        ok, why = _body_owned(body)
        if not ok:
            hits.append(("non-scanner-owned-body",
                         f"request {i}: {why}"))

    return bool(hits), hits


def _evidence_rows(candidate):
    """Every anomaly record or raw excerpt that supports the hypothesis,
    with secrets masked. Returns a list of (source, excerpt) pairs."""
    rows = []
    anom = candidate.get("anomaly")
    if isinstance(anom, dict):
        src = anom.get("route") or candidate.get("url") or "anomaly record"
        for k in ("probe_class", "distance", "status_delta", "headers_added",
                  "headers_removed", "canary_reflected", "note"):
            if k in anom:
                rows.append((f"{src} :: {k}", anom[k]))
        if not rows:
            rows.append((src, json.dumps(anom, sort_keys=True)))
    for ev in candidate.get("evidence") or []:
        if isinstance(ev, dict):
            rows.append((str(ev.get("source") or "excerpt"),
                         ev.get("excerpt", "")))
        else:
            rows.append(("excerpt", ev))
    if not rows:
        for i, req in enumerate(candidate.get("repro") or [], 1):
            if isinstance(req, dict):
                rows.append((f"request {i}",
                             f"{str(req.get('method') or 'GET').upper()} "
                             f"{req.get('url', '')}"))
    return [(tierc_canary(tierc_mask(s)), tierc_canary(tierc_mask(str(x))))
            for s, x in rows]


def _repro_block(candidate):
    """The exact request shape that produced the anomaly, canary swapped for
    the literal placeholder CANARY. Documentation only, never sent."""
    lines = ["## 4. Minimal repro template", "",
             "Run this ONLY on your own staging environment, never against "
             "production and never against a system you do not own.", ""]
    for i, req in enumerate(candidate.get("repro") or [], 1):
        if not isinstance(req, dict):
            continue
        method = str(req.get("method") or "GET").strip().upper()
        url = str(req.get("url") or "")
        lines.append(f"### request {i}: {method}")
        lines.append("")
        lines.append("```http")
        lines.append(f"{method} {tierc_canary(url)} HTTP/1.1")
        host = urllib.parse.urlsplit(url).netloc or "placeholder_website"
        lines.append(f"Host: {host}")
        lines.append("User-Agent: <your own agent string>")
        headers = req.get("headers") or {}
        if isinstance(headers, dict):
            for k, v in headers.items():
                lines.append(f"{k}: {tierc_canary(tierc_mask(v))}")
        body = req.get("body")
        if body:
            lines.append("")
            lines.append(tierc_canary(tierc_mask(body)))
        lines.append("```")
        lines.append("")
    lines.append("CANARY is a literal placeholder. Substitute your own unique "
                 "marker so a response reflection is unambiguous.")
    lines.append("")
    return lines


def tierc_dossier(bot, candidate):
    """Write research/CANDIDATE-<id>.md and return the path written."""
    out_dir = getattr(bot.args, "tierc_dir", None) or "research"
    os.makedirs(out_dir, exist_ok=True)
    cid = tierc_safe_id(candidate.get("id"))
    path = os.path.join(out_dir, f"CANDIDATE-{cid}.md")

    title = str(candidate.get("title") or cid)
    tier = str(candidate.get("tier") or "").strip().upper()
    if candidate.get("source") == "anomaly":
        source = f"Tier {tier or 'A'} anomaly"
        anom = candidate.get("anomaly") or {}
        if anom.get("route"):
            source += f" on route {anom['route']}"
    else:
        source = "hand-written candidate file"

    out_of_scope, hits = tierc_rails(candidate)
    verdict = "OUT OF SCOPE" if out_of_scope else "IN SCOPE"
    now = datetime.now(timezone.utc)
    target = ""
    try:
        target = bot.t.base + bot.t.path
    except Exception:
        target = ""

    L = []
    # 1. header
    L += [f"# CANDIDATE {cid}: {title}", "",
          f"> **{verdict}**" if out_of_scope else
          f"> rails verdict: {verdict}", "",
          "| field | value |", "|---|---|",
          f"| candidate id | `{cid}` |",
          f"| title | {tierc_mask(title)} |",
          f"| date | {now.strftime('%Y-%m-%d')} ({now.strftime('%H:%M:%SZ')}) |",
          f"| source | {source} |",
          f"| rails verdict | {verdict} |",
          f"| out of scope | {'yes' if out_of_scope else 'no'} |",
          f"| requests executed by redteam.py for this dossier | 0 |"]
    if target:
        L.append(f"| scan target | {target} |")
    L.append("")

    # 2. hypothesis
    hyp = str(candidate.get("hypothesis") or "").strip()
    if not hyp:
        hyp = ("No hypothesis recorded yet. Write one sentence naming the "
               "mechanism you believe is present and the observation that "
               "made you believe it.")
    L += ["## 2. Hypothesis", "", tierc_mask(tierc_canary(hyp)), "",
          "This is a hypothesis, not a proven impact. Nothing in this dossier "
          "has been exploited or confirmed on production.", ""]

    # 3. evidence
    L += ["## 3. Evidence", "",
          "Raw values are masked with the same routine the scanner uses for "
          "findings. A value that looks like a secret here is redacted, not "
          "collected.", "",
          "| # | source | excerpt |", "|---|---|---|"]
    rows = _evidence_rows(candidate)
    for i, (src, excerpt) in enumerate(rows, 1):
        L.append(f"| {i} | {src} | `{str(excerpt)[:300]}` |")
    if not rows:
        L.append("| 1 | none | no evidence captured yet |")
    L.append("")

    # 4. minimal repro: written only when the rails allow it. When they do
    # not, the section is absent entirely, not present and empty.
    if not out_of_scope:
        L += _repro_block(candidate)

    # 5. impact scaffold
    L += ["## 5. Impact statement scaffold", "",
          "Fill this in only with what you have actually demonstrated. If a "
          "line stays empty, the impact is unproven, and an unproven impact "
          "is the fastest way to lose a report.", "",
          "1. **What an attacker gains** (one sentence, naming the concrete "
          "capability gained, not the weakness class): "
          "_________________________________________________",
          "2. **What data is reachable** (name the exact data or none, never "
          "`sensitive data`): "
          "_________________________________________________",
          "3. **Blast radius** (how many systems, tenants or accounts, and "
          "what it takes to get there): "
          "_________________________________________________", "",
          "Keep the hypothesis above and the impact below separate. Vendors "
          "routinely reject reports that blur the two, and a rejected report "
          "teaches you nothing about whether you were right.", ""]

    # 6. rails verdict
    L += ["## 6. Rails verdict", ""]
    if out_of_scope:
        L += ["**OUT OF SCOPE.** redteam.py will not document, render or "
              "execute a repro for this candidate, so section 4 above is "
              "absent by design. The rails it violates:", ""]
        for rail, why in hits:
            L.append(f"- **{rail}**: {tierc_mask(why)}")
        L += ["",
              "If you still need this investigated, it has to be done by a "
              "human with written authorisation, on a system you own, with a "
              "change ticket. That process is deliberately outside this tool.",
              ""]
    else:
        L += ["**IN SCOPE.** The candidate is a read-only observation: no "
              "destructive method, no cloud metadata address, no flood or "
              "concurrency hint, no body the scanner does not own, and at "
              f"most {TIERC_MAX_REQUESTS} requests. It is documented, not "
              "executed.", ""]

    # 7. next steps
    L += ["## 7. Next steps", "",
          "1. **Verify on staging.** Reproduce it on your own staging copy "
          "first. If it does not reproduce there, stop here: it was noise.",
          "2. **Check whether a CWE already covers it.** Look it up at "
          "`https://cwe.mitre.org/data/definitions/<id>.html`. Before you "
          "invent a class, remember the rule: **name the mechanism rather "
          "than inventing a class**. HTTP request smuggling has been CWE-444 "
          "since 2008; a new mechanism deserves a new entry, a known "
          "mechanism in a new place does not.",
          "3. **If no entry exists, submit one.** Start at "
          "`https://cwesubmission.mitre.org/` and follow the process in "
          "`https://cwe.mitre.org/community/submissions/overview.html`.",
          "4. **Multi-vendor impact goes to CERT/CC.** Report per "
          "`https://kb.cert.org/vuls/report/` and coordinate via "
          "`https://certcc.github.io/CERT-Guide-to-CVD/tutorials/coord_certcc/`. "
          "Expect pushback: serious multi-vendor findings are routinely "
          "dismissed as features, and reporters sometimes conclude after the "
          "fact that they mis-scoped the impact. That is a reason to scope "
          "honestly up front, not a reason to inflate.",
          "5. **Category CWEs are not for mapping.** Entries in Category 1000 "
          "are view-only, Usage: PROHIBITED for mapping, see "
          "`https://cwe.mitre.org/data/definitions/1035.html`. Never cite a "
          "Category entry as the weakness class of a finding.", ""]

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    return path


def _anomaly_candidate(idx, anom):
    """Turn one Tier A or Tier B anomaly record into a candidate."""
    return {"id": f"ANOM-{idx}",
            "title": f"{anom.get('probe_class', 'anomaly')} on "
                     f"{anom.get('route', 'unknown route')}",
            "hypothesis": ("A response to a benign differential probe differs "
                           "from the baseline in a way that suggests the "
                           "origin trusts an unvalidated input. State the "
                           "mechanism you believe is responsible, then verify "
                           "it on staging before writing any impact claim."),
            "source": "anomaly",
            "tier": anom.get("tier", "A"),
            "anomaly": anom,
            "repro": anom.get("repro") or []}


def load_tierc_candidates(path, cap=50):
    """Read a hand-written candidate file. It is parsed and rendered only:
    nothing in it is ever sent."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise SystemExit(f"--tierc-candidates file not found: {path}")
    except json.JSONDecodeError as e:
        raise SystemExit(f"--tierc-candidates file is not valid JSON: {e}")
    if not isinstance(data, list):
        raise SystemExit("--tierc-candidates must be a JSON list of candidate "
                         "objects")
    if len(data) > cap:
        raise SystemExit(f"--tierc-candidates holds {len(data)} candidates, "
                         f"cap is {cap}")
    out = []
    for i, c in enumerate(data, 1):
        if not isinstance(c, dict):
            raise SystemExit(f"--tierc-candidates entry {i} is not an object")
        repro = c.get("repro") or []
        if not isinstance(repro, list):
            raise SystemExit(f"--tierc-candidates entry {i} has a non-list repro")
        for j, req in enumerate(repro, 1):
            if not isinstance(req, dict):
                raise SystemExit(f"--tierc-candidates entry {i} repro[{j}] "
                                 "is not an object")
        out.append({**c, "source": "candidate-file"})
    return out


def run_tierc(bot):
    """Scenario tierc. Sends nothing: the transport is frozen before any
    candidate is read, so a bug here still cannot produce traffic."""
    bot.t.frozen = True
    bot.tierc = []
    cfile = getattr(bot.args, "tierc_candidates", None)
    if cfile:
        cands = load_tierc_candidates(cfile)
    else:
        cands = [_anomaly_candidate(i, a)
                 for i, a in enumerate(bot.anomalies or [], 1)]
    out_of_scope = 0
    for cand in cands:
        path = tierc_dossier(bot, cand)
        oos, hits = tierc_rails(cand)
        out_of_scope += 1 if oos else 0
        bot.tierc.append({"id": tierc_safe_id(cand.get("id")),
                          "title": str(cand.get("title") or ""),
                          "path": path,
                          "rails": "; ".join(f"{r}: {w}" for r, w in hits)
                                   or "no rail violated",
                          "out_of_scope": oos})
    # Report the transport count honestly: Tier C's own phase sends nothing,
    # but an anomaly-sourced run may have discovered first, and a scan that
    # says "0 requests" when it sent some is worse than useless.
    bot.note(f"tier C: {len(bot.tierc)} dossier(s) written, {out_of_scope} "
             f"out of scope, {bot.t.used} request(s) sent by the whole run "
             f"(the dossier phase itself sends none)")


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


def _sev_filter_buttons():
    """Built outside the report f-string on purpose: a nested f-string with
    escaped quotes is only legal on Python 3.12+, and this project targets
    3.10+."""
    out = []
    for s in ["ALL"] + list(SEV_ORDER):
        cls = "on" if s == "ALL" else ""
        out.append('<button class="%s" onclick="ff(\'%s\',this)">%s</button>'
                   % (cls, s, s))
    return "".join(out)


def html_report(bot):
    counts = bot.counts()
    score = bot.score()
    sev_css = {"CRITICAL": "var(--cr)", "HIGH": "var(--hi)", "MEDIUM": "var(--me)",
               "LOW": "var(--lo)", "INFO": "var(--in)"}
    shown = sorted(bot.scored(), key=lambda f: (SEV_ORDER[f["severity"]],
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
    cov = "".join(
        f"<tr><td>{esc(r['check_id'])}</td><td>{esc(r['owasp'])}</td>"
        f"<td>{esc(r['severity'])}</td>"
        f"<td class='{'ok' if r['tested'] else ''}'>"
        f"{'exercised' if r['tested'] else 'not tested'}</td>"
        f"<td class='muted'>{esc(r['reason'])}</td></tr>"
        for r in coverage_statement(bot))
    warn_rows = "".join(
        f"<tr><td class='bad'>{esc(w['code'])}</td><td>{esc(w['message'])}</td></tr>"
        for w in bot.warnings)
    warn_block = (f"<table><tr><th>Code</th><th>What it means for this scan</th>"
                  f"</tr>{warn_rows}</table>" if bot.warnings else
                  '<div class="muted ok">No scan-quality warnings: pages were '
                  'crawled, responses were not all 401/403, and the budget '
                  'held.</div>')
    never = "".join(f"<tr><td>{esc(n['class'])}</td><td class='muted'>"
                    f"{esc(n['reason'])}</td></tr>" for n in NEVER_TESTED)
    ev_rows = "".join(
        f"<tr><td>{esc(f['check_id'])}</td><td>{esc(f['param'] or '')}</td>"
        f"<td class='muted'>{esc(f['evidence'][:220])}</td></tr>"
        for f in bot.evidence_records())
    ev_block = (f"<table><tr><th>Check</th><th>Param</th><th>Record</th></tr>"
                f"{ev_rows}</table>" if ev_rows else
                '<div class="muted">No evidence records for this run.</div>')
    recon = "".join(f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>"
                    for k, v in bot.recon)
    notes = "".join(f"<li>{esc(n)}</li>" for n in bot.notes[:40])
    cal = bot.calibration.profile()
    auth = bot.auth_state
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
<div class="filt">{_sev_filter_buttons()}
</div>
{''.join(rows) or '<div class="muted">Nothing to report. Automated coverage is a subset of a real assessment: finish with manual access-control, business-logic and abuse-case testing.</div>'}
</div></div>
<h2>Scan quality</h2>
{warn_block}
<p class="muted">Soft-404 calibration: <b>{esc(str(cal['mode']))}</b>, learned
status <b>{esc(str(cal['status']))}</b>, body about
<b>{esc(str(cal['length']))}B</b> (+/-{esc(str(cal['length_tolerance']))}),
similarity floor {esc(str(cal['similarity_min']))},
{esc(str(cal['probes_sent']))} probe(s) sent. {esc(cal['detail'])}</p>
<p class="muted">Authenticated session:
<span class="{'ok' if auth.get('state') == 'verified' else 'bad'}">{esc(str(auth.get('state')))}</span>
({esc(str(auth.get('verify_url') or 'not checked'))}). {esc(auth.get('reason') or '')}</p>
<h2>Evidence records (not scored)</h2>
{ev_block}
<h2>OWASP Top 10:2025 mapping</h2>
<table><tr><th>ID</th><th>Category</th></tr>{owasp_rows}</table>
<div class="two">
<div><h2>Check coverage</h2>
<table><tr><th>Check</th><th>OWASP</th><th>Severity</th><th>Result</th>
<th>Why not, when not</th></tr>{cov}</table></div>
<div><h2>Recon</h2><table><tr><th>Item</th><th>Value</th></tr>{recon}</table>
<h2>Engine notes</h2><ul class="muted">{notes or '<li>none</li>'}</ul></div>
</div>
<h2>Never tested by design</h2>
<p class="muted">These classes are outside an automated, non-destructive pass.
A green run says nothing about them.</p>
<table><tr><th>Class</th><th>Why this tool does not test it</th></tr>{never}</table>
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
    "sweep": [check_global_sweep],
    "exposures": [check_exposures, check_stacktrace, check_graphql],
    "injection": [check_injection],
    "auth": [check_auth, check_ratelimit],
    "client": [check_client],
    "methods": [check_methods],
    "anomaly": [check_anomaly],
    "tierc": [run_tierc],
"tierb": [check_desync_cells, check_unicode_oracles,
              check_delimiter_confusion, check_api_states],
}

# A passive replay can only judge what a stored response already contains,
# so it runs exactly these: header policy, cookie policy, sourcemap
# references, secrets, and the global sweep. Nothing here sends a request.
PER_RESPONSE_RUNNERS = [check_headers, check_cookies, check_client]
WHOLE_SET_RUNNERS = [check_secrets, check_global_sweep]
PASSIVE_SCOPE = frozenset(GROUPS["headers"] + GROUPS["cookies"] +
                          GROUPS["secrets"] + GROUPS["client"] +
                          ["exp-sourcemap", "global-secret-sweep"])


def run_passive_replay(bot):
    """M7: judge stored responses only. bot.t.used must stay 0 throughout."""
    files = getattr(bot.args, "passive_html", None) or []
    bot.load_passive_files(files)
    bot.enter_replay()
    bot.calibration.learn()          # reuses a stored response, sends nothing
    judged = 0
    try:
        for url, r in list(bot.pages.items()):
            if r is None:
                continue
            judged += 1
            bot.replay_base = url
            for fn in PER_RESPONSE_RUNNERS:
                try:
                    fn(bot)
                except BudgetExceeded:
                    raise
                except Exception as e:
                    bot.degrade(fn.__name__, f"{type(e).__name__}: {e}")
        bot.replay_base = None
        for fn in WHOLE_SET_RUNNERS:
            try:
                fn(bot)
            except BudgetExceeded:
                raise
            except Exception as e:
                bot.degrade(fn.__name__, f"{type(e).__name__}: {e}")
        # re-test inside the replay: a verify closure must never reach the
        # transport, it answers from the stored response
        try:
            bot.verify_findings()
        except BudgetExceeded:
            raise
        except Exception as e:
            bot.degrade("verify_findings", f"{type(e).__name__}: {e}")
    finally:
        bot.exit_replay()
    used = bot.t.used
    if used:
        bot.note(f"passive replay contract violated: {used} request(s) were "
                 f"sent, it must stay at 0")
    bot.add("global-secret-sweep", url=bot.t.base, param="passive-replay",
            internal=True, severity="INFO",
            evidence=f"passive replay judged {judged} stored response(s) with "
                     f"the response-only checks, requests sent: {used}")
    bot.recon.append(("passive replay", f"{judged} responses, {used} requests"))
    return used


def scan_quality(bot):
    """M20: turn this run's shape into explicit, machine-readable warnings."""
    statuses = bot.status_counts
    if bot.responses_seen and statuses and all(s in (401, 403) for s in statuses):
        bot.warn("all_unauthorized",
                 f"every one of the {bot.responses_seen} responses was 401 or "
                 f"403, so nothing was actually tested: fix the session or the "
                 f"credentials and re-run")
    soft, live = bot.soft404_audit()
    if soft and not live:
        bot.warn("everything_soft_404",
                 f"all {soft} captured responses match the learned not-found "
                 f"profile (HTTP {bot.calibration.status}): the crawl found no "
                 f"real content")
    live_pages = [u for u, r in bot.pages.items() if r.status < 400]
    if not live_pages:
        bot.warn("no_pages_crawled",
                 f"no response under HTTP 400 was captured out of "
                 f"{len(bot.pages)} attempted: the target may be down, "
                 f"misrouted, or entirely behind auth")
    if bot.stopped:
        bot.warn("budget_exhausted",
                 f"the request budget ran out before the run finished: "
                 f"{bot.stopped}")
    if bot.degraded:
        bot.warn("checks_degraded",
                 f"{len(bot.degraded)} check(s) hit the guarded() error path "
                 f"and did not finish: {'; '.join(bot.degraded[:3])}")


def build_parser():
    p = argparse.ArgumentParser(
        prog="redteam.py",
        description="Authorized red team simulator for a website YOU own. "
                    "Finds vulnerabilities, prints the exact fix.",
        epilog="Exit codes: 3 = internal error or a scan-quality warning "
               "under --strict-warnings, 2 = critical findings, "
               "1 = high findings, 0 = clean.")
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
    p.add_argument("--passive", action="store_true",
                   help="passive replay: judge stored responses and "
                        "--passive-html files, issue zero requests")
    p.add_argument("--passive-html", action="append", default=[],
                   metavar="FILE",
                   help="saved HTML to replay offline, repeatable")
    p.add_argument("--tierb", action="store_true",
                   help="also run the Tier B surface-hunting modules "
                        "(anomalies only, they never change the score)")
    p.add_argument("--desync-probe", action="store_true",
                   help="walk the CL/TE/0 length-interpretation cells with a "
                        "canary (Tier B; off by default, sends nothing)")
    p.add_argument("--allow-h2-probe", action="store_true",
                   help="relax reporting for the H2 desync cell; still sends "
                        "nothing, because http.client is HTTP/1.1 only")
    p.add_argument("--desync-path",
                   help="path for the desync cells (default: the target path)")
    p.add_argument("--delimiter-path",
                   help="path for the delimiter-confusion probes (default: "
                        "the first crawled GET path)")
    p.add_argument("--api-spec",
                   help="local JSON OpenAPI 3 document for the API state walk")
    p.add_argument("--allow-spec-post", action="store_true",
                   help="allow POST (never PUT/PATCH/DELETE) against spec "
                        "operations marked post, with dummy bodies only")
    p.add_argument("--anomaly", action="store_true",
                   help="run the Tier A anomaly engine regardless of scenario")
    p.add_argument("--anomaly-cap", type=int, default=5, metavar="N",
                   help="max anomalies reported per route (clamped to 20)")
    p.add_argument("--anomaly-keep-all", action="store_true",
                   help="skip the anomaly noise filter, for debugging")
    p.add_argument("--tierc-candidates", metavar="FILE",
                   help="tierc: JSON candidate file to document (never "
                        "executed)")
    p.add_argument("--tierc-dir", default="research", metavar="DIR",
                   help="tierc: directory for generated dossiers")
    p.add_argument("--tierc-from-anomalies", action="store_true",
                   help="tierc: run the anomaly engine first, then write one "
                        "dossier per anomaly")
    p.add_argument("--strict-warnings", action="store_true",
                   help="any scan-quality warning turns an otherwise clean "
                        "run into exit code 3")
    p.add_argument("--auth-verify-url",
                   help="URL fetched once to decide whether --cookie is really "
                        "authenticated (default: the target)")
    p.add_argument("--auth-marker",
                   help="string that only appears on a logged-in page, used by "
                        "the auth verify predicate")
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
    """M18 exit-code contract: 0 clean, 1 any HIGH, 2 any CRITICAL, 3 an
    internal error escaping the run (or any warning under --strict-warnings).
    SystemExit still propagates: those are operator errors, not scan results.
    """
    try:
        return _run(args)
    except SystemExit:
        raise
    except Exception as e:
        sys.stderr.write(f"internal error: {type(e).__name__}: {e}\n")
        return 3


def _run(args):
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
    if args.passive:
        mode = "passive-replay"
    elif args.scenario == "tierc":
        # Tier C is documentation-only: it needs no ownership flag because it
        # never sends a request, so it must not be demoted to passive recon.
        mode = "research"
    elif not args.i_own_this:
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
        who = getattr(fn, "__name__", "check")
        try:
            fn(bot)
        except BudgetExceeded as e:
            bot.stopped = str(e)
        except OutOfScope as e:
            bot.note(f"scope violation blocked: {e}")
            bot.degrade(who, "out-of-scope request blocked")
        except Exception as e:
            bot.note(f"check degraded ({type(e).__name__}): {e}")
            bot.degrade(who, f"{type(e).__name__}: {e}")

    # Tier C with a candidate file is documentation-only: discovery would
    # send requests to learn nothing the dossier uses. Every other scenario
    # discovers first, then runs its groups.
    tierc_docs_only = (args.scenario == "tierc"
                       and bool(getattr(args, "tierc_candidates", None)))
    if args.passive:
        run_passive_replay(bot)
    elif tierc_docs_only:
        bot.note("tier C: candidate file supplied, discovery skipped so the "
                 "whole run sends zero requests")
    else:
        guarded(lambda b: b.discover())
        guarded(lambda b: b.verify_auth())

    # A passive replay has already judged everything it can judge, inside the
    # replay sandbox. Running the scenario loop afterwards would put the full
    # check set back on a live transport, which is exactly what --passive
    # exists to prevent.
    if args.passive:
        pass
    elif not tierc_docs_only:
        groups = list(SCENARIOS[args.scenario])
        # --anomaly forces the Tier A engine on regardless of the scenario,
        # and never replaces the scenario's own groups
        if getattr(args, "anomaly", False) and "anomaly" not in groups:
            groups.append("anomaly")
        if getattr(args, "tierb", False) and "tierb" not in groups:
            groups.append("tierb")
        if bot.stopped is None:
            for group in groups:
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
    else:
        # documentation only: the dossier writer still has to run
        for fn in RUNNERS["tierc"]:
            guarded(fn)
    bot.downgrade_cookie_confidence()
    scan_quality(bot)

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
    if args.strict_warnings and bot.warnings:
        return 3
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
