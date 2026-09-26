# SPEC: placeholder_website Red Team Bot (redteam.py)

Single-file, stdlib-only, Python 3.14. Simulates attacks against a site YOU own so
you can find and fix the holes yourself. Authorized-testing only, enforced in code.

## 0. Non-negotiable safety rails (enforced before ANY network call)

1. Scope gate: every request URL host must match an entry in --allow (exact host
   or *.suffix). Violation = abort, no request sent.
2. Ownership flag: --i-own-this required for active scenarios. Without it the bot
   runs PASSIVE recon only (headers/TLS/robots of the single target URL).
3. No private/third-party targets: IP-literal hosts rejected unless --local
   (127.0.0.1/localhost/::1 only).
4. Throttle: global token bucket, default 5 req/s (--rps), +-random jitter,
   hard cap --max-requests (default 500). Cap hit = graceful stop + report.
5. Non-destructive payloads only: canaries, error-signature strings, benign
   probes. No floods, no time-based DoS, no data modification, no credential
   guessing (lockout/rate-limit test uses N=10 gentle requests max), GET/HEAD
   default, POST only against discovered form endpoints with benign bodies.
6. Identifiable UA: "placeholder_websiteRedTeamBot/1.0 (+authorized self-testing)".
7. robots.txt respected during discovery unless --ignore-robots (logged in report).

## 1. CLI

  python3 redteam.py --target https://placeholder_website.example --allow placeholder_website.example \
      --i-own-this [--scenario recon|headers|misconfig|injection|auth|full] \
      [--rps 5] [--max-requests 500] [--local] [--cookie 'sess=...'] \
      [--report out/report.html] [--json out/report.json] [--list-checks] [--quiet]

Defaults: scenario=full, report+json written under ./rt-report-<timestamp>/.

## 2. Pipeline

scope gate -> Transport (throttled http.client, redirects traced, TLS via ssl)
-> discovery (robots, sitemap, same-host links, forms, params)
-> checks (modules below, each returns Finding[])
-> verify pass (every CRITICAL/HIGH re-tested once; unconfirmed downgraded)
-> dedupe by (check_id, url, param)
-> score + report (terminal, JSON, self-contained HTML).

## 3. Finding schema

{id, check_id, title, severity: CRITICAL|HIGH|MEDIUM|LOW|INFO, owasp: "A02:2025",
 confidence: high|medium|low, verified: bool, url, param?, evidence (req/resp
 excerpt, <=500 chars), fix (literal config/code/step), refs: [url...]}

## 4. Checks v1 (mapped OWASP Top 10:2025, catalog completed from RESEARCH.md)

- recon/info: DNS+IP, tech fingerprint, server banner, security.txt, 404 leakage
- headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options/frame-ancestors,
  Referrer-Policy, Permissions-Policy, COOP/CORP, X-XSS-Protection=0 rule,
  Cache-Control on sensitive paths, Expect-CT/HPKP presence (must be absent)
- cors: Origin https://evil.example reflection, ACAO + credentials, preflight
- cookies: Secure/HttpOnly/SameSite, cookie scope, JWT decode (alg, exp, none)
- tls: protocol version, cert chain/expiry, weak-cipher signal (ssl module)
- misconfig exposure: /.git/HEAD, /.env, /backup*, /web.config, source maps,
  directory listing, /server-status, /phpinfo, /swagger, /graphql, /api/docs,
  .DS_Store, wp-config.bak-style names, debug endpoints, stack-trace reflection
- injection: reflected XSS canary (unique token, context-aware detection),
  SQLi error signatures (mysql/mssql/oracle/postgres strings), boolean-diff
  marker, command-injection benign echo marker, path traversal (../../etc/passwd
  signature read on OWN server only)
- redirects: open redirect via //evil, /\\evil, url-param chain
- clickjacking: frame-ability of a real page (header + meta check)
- rate-limit: gentle N=10 burst on a sensitive endpoint, 429/lockout expected
- auth (needs --cookie): session fixation signal, IDOR pattern hint on numeric
  ids (comparison only, no data exfil), missing auth on obvious admin paths

## 5. Report

- terminal: severity-ordered table, score /100, top-3 attacker narrative
- JSON: machine-readable findings array + run meta (target, time, counts, caps)
- HTML: self-contained, severity color coding, per-finding evidence + exact fix,
  OWASP 2025 mapping table, "fix order" section. Zero persona, no meta text.

Score: start 100, subtract CRITICAL 25 / HIGH 12 / MEDIUM 5 / LOW 2 (INFO 0),
floor 0. Verified findings count, unverified count at half weight.

## 6. QA (proof of work)

Local vulnerable harness (scratch dir, stdlib http.server subclass): missing
headers, reflected param, error-prone fake SQL endpoint, exposed .git/HEAD,
directory listing, permissive CORS, clickjackable page, no rate limit. Bot runs
against http://127.0.0.1:8931 with --local --i-own-this; every check class must
fire at least once (assert in QA script). Then a clean-config run must score high.

## 7. Non-goals

No exploitation/payload execution beyond benign detection, no brute force, no
DoS, no subdomain takeover automation (report-level guidance only), no WAF
evasion, no third-party targets, ever.
