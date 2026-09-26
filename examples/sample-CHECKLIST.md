# Security fix checklist

Target: http://127.0.0.1:8931/  |  score 0.0/100  |  7 critical, 14 high, 20 medium, 10 low, 3 info

Work top to bottom. Re-run the bot after each fix and watch the score move.

## ✖ CRITICAL

- [ ] **OS command injection** (A05) `http://127.0.0.1:8931/search?q=hello [q]`
      fix: never pass input to a shell; call fixed executables with argument arrays, allowlist inputs
- [ ] **Cloud credentials file exposed** (A02) `http://127.0.0.1:8931/.aws/credentials`
      fix: remove the file, rotate those credentials immediately, use an instance role instead of keys on disk
- [ ] **Environment file exposed** (A02) `http://127.0.0.1:8931/.env`
      fix: move .env outside the web root, deny dotfiles, then rotate EVERY secret it ever contained
- [ ] **Private key file exposed on the server** (A04) `http://127.0.0.1:8931/id_rsa`
      fix: remove the key from the web root immediately and rotate it (reissue the certificate / API key), store keys outside docroot
- [ ] **JWT signed with a guessable secret** (A04) `http://127.0.0.1:8931/ [jwt]`
      fix: switch to RS256/ES256 or a 256-bit random secret, store it in a secret manager, rotate it
- [ ] **Secret or live API key shipped to the browser** (A02) `http://127.0.0.1:8931/assets/app.js [AWS access key ID]`
      fix: pull the key out of the client bundle at once, rotate it, issue a scoped server-side replacement, restrict the old key
- [ ] **Secret or live API key shipped to the browser** (A02) `http://127.0.0.1:8931/assets/app.js [Stripe live secret]`
      fix: pull the key out of the client bundle at once, rotate it, issue a scoped server-side replacement, restrict the old key
## ▲ HIGH

- [ ] **Admin surface reachable without login** (A01) `http://127.0.0.1:8931/admin`
      fix: deny by default: authenticate every route, then authorize by role, server-side
- [ ] **Admin surface reachable without login** (A01) `http://127.0.0.1:8931/account`
      fix: deny by default: authenticate every route, then authorize by role, server-side
- [ ] **Session cookie issued over HTTP** (A04) `http://127.0.0.1:8931/ [sessionid]`
      fix: serve the site over HTTPS only and set Secure on every session cookie
- [ ] **Session cookie issued over HTTP** (A04) `http://127.0.0.1:8931/ [auth]`
      fix: serve the site over HTTPS only and set Secure on every session cookie
- [ ] **CORS reflects arbitrary Origin** (A01) `http://127.0.0.1:8931/`
      fix: allowlist exact origins server-side, never echo the request Origin; keep Access-Control-Allow-Credentials off unless required
- [ ] **Stack trace or debug page exposed** (A10) `http://127.0.0.1:8931/qx-err-49afc947`
      fix: return generic errors with a correlation ID, keep traces in protected logs, disable debug mode in production
- [ ] **Admin interface reachable from the internet** (A02) `http://127.0.0.1:8931/phpmyadmin/`
      fix: bind admin panels to localhost or a VPN, add IP allowlisting plus MFA, remove them from public DNS
- [ ] **Backup or archive file exposed** (A02) `http://127.0.0.1:8931/backup.zip`
      fix: delete backups from the web root, store them outside docroot, deny *.bak *.old *.zip *.sql *.tar.gz
- [ ] **Git repository exposed on the server** (A02) `http://127.0.0.1:8931/.git/HEAD`
      fix: remove .git from deployment artifacts, deny dotfiles at the server: location ~ /\.git { deny all; }
- [ ] **Site served over plain HTTP** (A04) `http://127.0.0.1:8931/`
      fix: redirect all HTTP to HTTPS and serve only TLS 1.2+, e.g. nginx: return 301 https://$host$request_uri;
- [ ] **SQL injection (database error revealed)** (A05) `http://127.0.0.1:8931/search?q=hello [q]`
      fix: use parameterized prepared statements for every value, allowlist identifiers, least-privilege DB account
- [ ] **Path traversal** (A05) `http://127.0.0.1:8931/download?file=readme.txt [file]`
      fix: canonicalize and verify the resolved path stays under the allowed base dir, allowlist filenames
- [ ] **Reflected cross-site scripting** (A05) `http://127.0.0.1:8931/download?file=readme.txt [file]`
      fix: context-aware output encoding (framework auto-escape), avoid innerHTML, add CSP as a second layer
- [ ] **Reflected cross-site scripting** (A05) `http://127.0.0.1:8931/search?q=hello [q]`
      fix: context-aware output encoding (framework auto-escape), avoid innerHTML, add CSP as a second layer
## ● MEDIUM

- [ ] **Page can be framed (clickjacking)** (A02) `http://127.0.0.1:8931/`
      fix: add_header X-Frame-Options "DENY" always; and CSP frame-ancestors 'none'
- [ ] **Session cookie without HttpOnly** (A07) `http://127.0.0.1:8931/ [sessionid]`
      fix: add HttpOnly to all session cookies
- [ ] **Session cookie without HttpOnly** (A07) `http://127.0.0.1:8931/ [auth]`
      fix: add HttpOnly to all session cookies
- [ ] **State-changing form without CSRF token** (A01) `http://127.0.0.1:8931/transfer [account,amount]`
      fix: add a per-session CSRF token (constant-time compare) and SameSite cookies; never rely on secrecy of URLs
- [ ] **State-changing form without CSRF token** (A01) `http://127.0.0.1:8931/login [username,password]`
      fix: add a per-session CSRF token (constant-time compare) and SameSite cookies; never rely on secrecy of URLs
- [ ] **Directory listing enabled** (A02) `http://127.0.0.1:8931/assets/`
      fix: autoindex off; (nginx) / Options -Indexes (Apache)
- [ ] **API documentation exposed publicly** (A02) `http://127.0.0.1:8931/openapi.json`
      fix: serve OpenAPI/Swagger only in staging or behind auth; block schema paths at the edge
- [ ] **Configuration file exposed** (A02) `http://127.0.0.1:8931/config.json`
      fix: block config filenames at the server and stop shipping them in builds
- [ ] **Debug/monitoring endpoint exposed** (A02) `http://127.0.0.1:8931/server-status`
      fix: disable actuator/phpinfo/server-status style endpoints in production, bind them to localhost or auth
- [ ] **Source map published** (A08) `http://127.0.0.1:8931/assets/app.js.map`
      fix: strip sourceMappingURL from shipped JS or serve .map files only for internal builds
- [ ] **GraphQL introspection enabled in production** (A02) `http://127.0.0.1:8931/graphql`
      fix: disable introspection in production (Apollo: introspection: false; Hasura/GraphQL Yoga: disable for anon roles)
- [ ] **Sensitive page is cacheable** (A02) `http://127.0.0.1:8931/login`
      fix: add_header Cache-Control "no-store, private" always; on login/account/API responses
- [ ] **Content-Security-Policy missing** (A02) `http://127.0.0.1:8931/`
      fix: start report-only: Content-Security-Policy-Report-Only: default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; report-uri /csp-report, then enforce
- [ ] **X-Content-Type-Options missing** (A02) `http://127.0.0.1:8931/`
      fix: add_header X-Content-Type-Options "nosniff" always;
- [ ] **Untrusted Host/X-Forwarded-Host reaches output** (A07) `http://127.0.0.1:8931/`
      fix: build URLs from a configured canonical origin, never from request headers; reject unknown Host values at the proxy
- [ ] **JWT has no expiration claim** (A07) `http://127.0.0.1:8931/ [jwt]`
      fix: set short exp (minutes to hours), validate exp/nbf/iss/aud, back long sessions with refresh tokens
- [ ] **Write methods accepted (PUT/DELETE)** (A02) `http://127.0.0.1:8931/`
      fix: reject non-GET/POST at the edge, require auth and CSRF on any allowed write method
- [ ] **HTTP TRACE enabled** (A02) `http://127.0.0.1:8931/`
      fix: disable TRACE at the server/proxy: nginx does not enable it by default, apache: TraceEnable off
- [ ] **Open redirect** (A06) `http://127.0.0.1:8931/redirect?to=/home [to]`
      fix: allowlist redirect targets (path-only or known hosts), reject scheme-relative and absolute URLs
- [ ] **Possible SQL injection (boolean differential)** (A05) `http://127.0.0.1:8931/item?id=1 [id]`
      fix: same fix as error-based SQLi: parameterized queries everywhere
## ○ LOW

- [ ] **Session cookie without SameSite** (A07) `http://127.0.0.1:8931/ [sessionid]`
      fix: add SameSite=Lax (or Strict for state-changing flows)
- [ ] **Session cookie without SameSite** (A07) `http://127.0.0.1:8931/ [auth]`
      fix: add SameSite=Lax (or Strict for state-changing flows)
- [ ] **Dependency manifest exposed** (A03) `http://127.0.0.1:8931/package.json`
      fix: deny package manifests at the edge; run npm audit / osv-scanner to check those versions yourself first
- [ ] **Server version disclosed in banner** (A03) `http://127.0.0.1:8931/`
      fix: nginx: server_tokens off;, or proxy_hide_header Server; then set a generic Server value at the edge
- [ ] **Permissions-Policy missing** (A02) `http://127.0.0.1:8931/`
      fix: add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;
- [ ] **Referrer-Policy missing** (A02) `http://127.0.0.1:8931/`
      fix: add_header Referrer-Policy "strict-origin-when-cross-origin" always;
- [ ] **Framework fingerprint header present** (A02) `http://127.0.0.1:8931/`
      fix: suppress it: nginx proxy_hide_header X-Powered-By;, or framework config expose_php=Off / X-Powered-By off
- [ ] **No rate limit observed on login** (A07) `http://127.0.0.1:8931/login`
      fix: layer limits (edge + app): e.g. 4/min then 10/10min then 20/hour per IP+account, count failures, add CAPTCHA
- [ ] **robots.txt reveals sensitive paths** (A02) `http://127.0.0.1:8931/robots.txt`
      fix: remove secret paths from robots.txt, block them at the server instead
- [ ] **Third-party script without Subresource Integrity** (A08) `http://127.0.0.1:8931/ [https://cdn.example.org/lib.js]`
      fix: add integrity="sha384-..." and crossorigin to every cross-origin script/link, or self-host the asset
## • INFO

- [ ] **Cross-Origin-Opener-Policy missing** (A02) `http://127.0.0.1:8931/`
      fix: add_header Cross-Origin-Opener-Policy "same-origin" always;
- [ ] **Cross-Origin-Resource-Policy missing** (A02) `http://127.0.0.1:8931/`
      fix: add_header Cross-Origin-Resource-Policy "same-site" always; (test PDFs first)
- [ ] **security.txt missing** (RFC 9116) `http://127.0.0.1:8931/.well-known/security.txt`
      fix: publish /.well-known/security.txt with Contact: mailto:you@domain and Policy: link
