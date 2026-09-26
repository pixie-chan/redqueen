> Copied from the local corpus at `~/research/redteam-bot/RESEARCH.md`.
> Raw delegated tranches (4 files, 137KB) stay local in
> `~/research/redteam-bot/tranches/`.

# Cybersecurity Research for the placeholder_website Red Team Bot

Purpose: authorize-and-attack-own-site research. Every load-bearing claim carries a
source URL. Tranche 0 = verified by me directly against primary sources today.
Tranches 1-4 = delegated research, merged in when they land.

## Tranche 0 - primary-source verification (solo)

### OWASP Top 10:2025 (VERIFIED, primary source: https://top10.owasp.org/2025/en/)

| ID | Name |
|----|------|
| A01:2025 | Broken Access Control |
| A02:2025 | Security Misconfiguration |
| A03:2025 | Software Supply Chain Failures |
| A04:2025 | Cryptographic Failures |
| A05:2025 | Injection |
| A06:2025 | Insecure Design |
| A07:2025 | Authentication Failures |
| A08:2025 | Software or Data Integrity Failures |
| A09:2025 | Security Logging and Alerting Failures |
| A10:2025 | Mishandling of Exceptional Conditions |

Also verified: 2025 is the current release (owasp.org/projects/top-ten).
Delta vs 2021 (SSRF was A10 in 2021, supply chain is new at A03) to be confirmed
by tranche 1 against the OWASP introduction page.

### HTTP security headers, literal recommended values
(VERIFIED, primary source: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)

| Header | Recommended value | Purpose |
|--------|-------------------|---------|
| Strict-Transport-Security | max-age=63072000; includeSubDomains; preload | HTTPS-only, HSTS preload eligible |
| X-Content-Type-Options | nosniff | blocks MIME sniffing |
| X-Frame-Options | DENY (or CSP frame-ancestors) | clickjacking |
| Referrer-Policy | strict-origin-when-cross-origin | referrer leak control |
| X-XSS-Protection | 0 (or omit entirely) | legacy filter can CREATE XSS |
| Content-Security-Policy | complex, start report-only then enforce | XSS/data injection |
| Access-Control-Allow-Origin | explicit origins, never blanket * for authed data | CORS |
| Cross-Origin-Opener-Policy | same-origin | Spectre-class isolation |
| Cross-Origin-Embedder-Policy | require-corp | cross-origin load gating |
| Cross-Origin-Resource-Policy | same-site | response hijack gating |
| Cache-Control (sensitive) | no-store | no caching of secrets |
| Expect-CT | do NOT use (obsolete) | |
| Public-Key-Pins | do NOT use (removed from Chromium 2018) | |

Nginx placement: add_header "X-Frame-Options" "DENY" always; (the `always` flag
matters: without it nginx only sends it on success codes).
Apache: Header unset X-Frame-Options + Header always set ... (both tables or you get duplicates).
Testing reference: Mozilla Observatory (named by the cheat sheet itself).

### WSTG
- Official project URL guess https://owasp.org/www-project-web-security-testing-guide/latest/ returned 404 today.
  Correct root to be confirmed by tranche 1.

## Tranche 1 - OWASP taxonomy + WSTG mapping (delegated, pending)
## Tranche 2 - scanner toolchain + architecture (delegated, pending)
## Tranche 3 - attack checks and detection signatures (delegated, pending)
## Tranche 4 - hardening/defense fixes (delegated, pending)
