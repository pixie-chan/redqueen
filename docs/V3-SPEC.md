# Red Queen v2.0 build contract (R2 + Tier A/B/C)

Pinned interfaces for the opencode harness. Symbols below were read from the
live `redteam.py` v1.1.0; keep them stable.

## Invariants (all prompts)

- Python 3.10+, **stdlib only** in `redteam.py` (no pip imports at runtime).
- Build order is fixed: `parts/p1_head.py` … `p11_main.py`, assembled by
  `./build.sh` (NEVER `cat parts/*.py`: shell glob puts p10 before p1_head).
- No em dashes (U+2014) in any string, comment, docstring or report text.
- Target site is always `placeholder_website` in fixtures; never a real name.
- Safety rails unchanged: allowlist scope gate, `--i-own-this` for active
  groups, 5 req/s + jitter, `--max-requests` budget, benign payloads only
  (canaries, error signatures, echo markers, read-only differentials, arithmetic
  markers), no brute force, no DoS, no data writes, secrets redacted.
- Every new behaviour ships with a QA gate in `qa/qa.py` (the existing 16 must
  still pass unchanged), and the harness gains whatever endpoints the new
  checks need (`qa/harness_a.py`, `harness_b.py`, `harness_c.py`).

## Current shapes you must extend (do not redesign)

- `CHECKS[cid] = (owasp, severity, title, impact, fix)` (parts/p2_checks_a.py,
  p2_checks_b.py)
- `GROUPS[group] = [cid, ...]`, `SCENARIOS[name] = [group, ...]`
  (parts/p2_checks_b.py)
- `RUNNERS[group] = [check_fn(bot), ...]` (parts/p11_main.py)
- `bot.add(check_id, url="", param=None, severity=None, evidence="", fix=None,
  confidence="high", detail=None, verify=None)` with dedupe key
  `(check_id, url-path, param)` and secret redaction (parts/p4_bot.py)
- `bot.get(url, headers=None, method="GET", body=None, follow=True)` returns
  `Resp(status, headers, body, url, redirects, elapsed)`; `budget` and
  `throttle` live in `Transport` (parts/p3_transport.py)
- Outputs: `terminal_report(bot, use_color)`, `html_report(bot)`,
  `json_report(bot)`, `write_checklist(bot, out_dir)` (parts/p9, p10)
- `qa/qa.py` = `qa_a.py` + `qa_b.py` (concatenated); sets `WEAK_EXPECT`,
  `WEAK_NA`, `STRONG_ALLOWED`, `PASSIVE_ALLOWED`, `TLS_EXPECT`, `gate()`,
  `run_bot()`, `start()`, `stop()`.

## R2: robustness release (prompt 1)

| id | feature | contract |
|---|---|---|
| M5 | soft-404 autocalibration | `parts/p6_tls_exposure.py`: replace `soft404`/`is_soft404` with `Calibration` class: probe N=5 random paths under the target root plus the real target, learn (status, length bucket ±15%, normalized body similarity ≥ 0.90) as a `not_found` profile; `is_not_found(resp)` returns True on status match OR (status 200 and length-bucket and similarity match). Store the learned profile in `bot.recon` and JSON as `calibration`. Must NOT send probes when `--i-own-this` is absent (passive mode): reuse a single fetched response then. |
| M4 | negative matchers | add `internal=True` and `negative=True` kwargs to `bot.add` findings: `internal` findings are evidence-only and never counted in `counts()` or the score; `negative=True` marks a check whose presence is the signal (e.g. "no Cache-Control" is already positive; use negative for a matcher that fires when something is ABSENT). Minimum: support `internal` fully, and use it for M7/M8 evidence records. |
| M8 | global matchers | after discovery, run one sweep over every captured `bot.pages` response body/headers with the existing `SECRET_RES` patterns plus: `-----BEGIN [A-Z ]*PRIVATE KEY-----`, `AKIA[0-9A-Z]{16}`, `sk_live_`, `ghp_`, `xox[baprs]-`, `AIza[0-9A-Za-z_-]{35}`, and stack-trace signatures. New check id `global-secret-sweep` (A02, HIGH, CRITICAL if private key). Dedupes against `secret-leak` findings by (value-hash, url). |
| M7 | passive replay | `--passive` mode: run response-only checks (headers, cookies, secrets, sourcemap, global sweep) over `bot.pages` and any `--passive-html FILE` inputs, issuing ZERO requests (assert `bot.t.used == 0` at the end of a passive replay; a QA gate asserts this). |
| M20 | scan-quality warnings | `bot.warnings` list; emit `all_unauthorized` (every request 401/403), `everything_soft_404` (calibration says every route is 404-shaped), `no_pages_crawled`, `budget_exhausted`, `checks_degraded` (a `guarded()` catch added a note). JSON gets `warnings`; terminal gets a `SCAN QUALITY` block; HTML gets a section. `--strict-warnings` makes any warning change the exit code to 2. |
| M21 | coverage accounting | new module `coverage_statement(bot) -> list[dict]` returning every check id in `CHECKS` with `tested: bool` (fired this run OR explicitly in a per-scenario NOT-TESTED map), plus a static `NEVER_TESTED` list of classes with reasons: DoS/resource-exhaustion, API6 business flows, DOM/browser-only XSS, smuggling escalation, cross-account mutation without two owner accounts, HTTP/2 CONTINUATION-flood and Rapid Reset active probing. Emit in JSON as `coverage` and in HTML as a table; terminal prints a one-line count. |
| M18 | exit-code contract | final `run()` returns: 0 clean; 1 any HIGH; 2 any CRITICAL; 3 internal error (unexpected exception escaping `run`); with `--strict-warnings`, warnings raise a clean run to 3. Keep "assertion gate failure" out of this (it is the QA suite's own rc, not the bot's). |
| M14 | auth verify predicate | `--auth-verify-url URL` (default: base target): after the first authenticated request, fetch a cheap authenticated page and require an authenticated marker: absence of `login`/`signin` form fields, presence of a session cookie echo, or HTTP 200 with a logged-in-only string the user passes via `--auth-marker TEXT`. Store `bot.auth_state = "verified" | "unverified"` with the reason; JSON field `auth_state`. Unverified auth downgrades every finding that used `--cookie` to `confidence="medium"`. |

## Tier A: anomaly engine (prompt 2)

New group `anomaly`, scenario `anomaly`, off unless `--scenario anomaly` or
`--anomaly`. Findings are NOT vulnerabilities: they go to `bot.anomalies`
(neVER into `bot.findings`, never into `counts()` or the score). Exit code
unaffected. New report section in all three outputs.

1. Baseline per crawled route: status, length, sorted header-name set,
   content-type, `body_fp` = sha256 of the normalized body (strip
   `QX[a-f0-9]+` canaries, digits ≥3, whitespace runs).
2. Differential probes per route, each with a per-run unique canary
   `QX<hex>`: `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL` (canary in
   the value), path + `.css`/`.png` suffix, `%2e`/`.`/`;`/extra-`?` delimiter
   variants, method variant on GET-safe routes only (HEAD, then OPTIONS), and
   content-type variant (`text/plain`) on the same GET. Never POST/PUT/DELETE.
3. Distance: `difflib.SequenceMatcher(None, norm(a), norm(b)).ratio()` on
   normalized bodies; headers compared as set difference.
4. Anomaly record: `{route, probe_class, distance, status_delta, headers_added,
   headers_removed, canary_reflected, note}`.
5. Rank by distance ascending (most different first), cap 5 per route
   (`--anomaly-cap N`, default 5, max 20).
6. Filter: drop anomalies where `canary_reflected` is False AND distance > 0.15
   (pure noise), drop anything matching the learned soft-404 profile.
7. Every anomaly carries `confidence="low"` and the literal line
   `INTERESTING, NOT A VULNERABILITY: needs human review`.
8. QA: harness gets one route that reflects an unkeyed header into the
   response (cache-poisoning oracle) and one that 404s everything; assert the
   engine flags the first and stays silent (or flags only low-distance noise)
   on the second; assert 0 findings-severity changes and 0 extra requests
   beyond the probe budget.

## Tier B: empty-taxonomy surface hunting (prompt 3)

New group `tierb`, scenario `tierb`.

1. Desync cell prober (`check_desync_cells`): probe the four length-interpretation
   cells CL, TE, 0, H2 in that order, ONE keep-alive connection per cell, two
   requests max per cell, zero-length body on the follow-up, unique canary per
   run. Success = the follow-up response contains the earlier canary or a
   status/body change beyond the calibrated soft-404 profile. Hard caps: ≤ 8
   requests total, `Content-Length` and `Transfer-Encoding` never combined
   with a real body, no chunked floods, no request that mutates state, abort
   immediately on first confirmed desync and report it. Note in the finding
   detail: H2 cells require an HTTP/2 client (`http.client` is HTTP/1.1) so the
   H2 cell is reported as `detection-only` unless `--allow-h2-probe` is given,
   in which case it is still not sent (mark `skipped: needs h2 client`).
2. Unicode normalization oracles (`check_unicode_oracles`): for every reflected
   parameter, send Kelvin sign U+212A, fullwidth Latin `A` U+FF21, and a
   combining sequence, once each; compare the response's received bytes against
   `unicodedata.normalize("NFKC", sent)`. Anomaly (not finding) when the
   server's stored form differs from the sent form in a way that changes an
   identity comparison. Cap 12 requests.
3. Delimiter confusion (`check_delimiter_confusion`): append `;`, `?`, `#`, a
   trailing dot, and a `%2e` segment to one crawled path; report when the
   response differs from baseline beyond calibration (cache-vs-origin path
   disagreement is the signal). Cap 10 requests.
4. API state machine walk (`check_api_states`, needs `--api-spec FILE` JSON
   or an exposed OpenAPI doc already found by `exp-api-docs`): for each
   documented path with `{param}`, synthesize ONE inert value (`0`, `1`, or a
   `QX<hex>` string), request it unauthenticated, compare to the anonymous
   baseline; report as an authorization differential (confidence medium), never
   as a proven BOLA. Never send DELETE/PUT/PATCH; POST bodies only if the spec
   marks the operation and `--allow-spec-post` is given, with a body of
   scanner-owned dummy values only. Cap 30 requests.
5. Every Tier B output that is not a confirmed desync goes to `bot.anomalies`
   with `tier="B"`, never to findings. The one exception: a confirmed desync
   cross-contamination IS a finding (`desync-confirmed`, CWE-444, A01).

## Tier C: research pipeline (prompt 4)

Human-in-the-loop tooling, no exploitation. New scenario `tierc`, which never
sends attack traffic (it works on Tier A/B anomalies and a candidate file).

1. `tierc_dossier(bot, candidate)` writes `research/CANDIDATE-<id>.md` with
   sections: hypothesis, evidence table (anomalies + raw excerpts, secrets
   redacted), minimal repro template (the exact two-request shape that showed
   the anomaly, with canary placeholders), impact-statement scaffold, rails
   check (assert the repro needs no destructive action; if it does, the dossier
   is marked `OUT OF SCOPE` and stops), and a next-steps checklist:
   staging verification, CWE lookup at
   `https://cwe.mitre.org/data/definitions/<id>.html`, new-CWE submission
   pointers (`https://cwesubmission.mitre.org/`,
   `https://cwe.mitre.org/community/submissions/overview.html`), CERT/CC
   reporting (`https://kb.cert.org/vuls/report/`,
   `https://certcc.github.io/CERT-Guide-to-CVD/tutorials/coord_certcc/`), and
   a reminder that Category CWE entries are Usage: PROHIBITED for mapping
   (`https://cwe.mitre.org/data/definitions/1035.html`).
2. `--tierc-candidates FILE`: a JSON list of hand-written candidates
   (`{id, title, hypothesis, repro: [{method, url, headers, body}]}`) that are
   rendered into dossiers without being executed. The bot NEVER runs them.
3. Report: HTML section listing dossier paths + the rails verdict per
   candidate; JSON field `tierc`.
4. QA: a unit test feeds one candidate file, asserts a dossier file is written
   containing the four required link families, asserts `bot.t.used == 0`
   (nothing was sent), and asserts an out-of-scope candidate is marked.

## Release order and gates

1. R2 (prompt 1) → `python3 qa/qa.py` must stay 16/16 PASS plus the new R2
   gates; `build.sh` reports compile OK; `redteam.py --list-checks` shows the
   new count.
2. Tier A (prompt 2) → existing 16 gates unchanged, +4 anomaly gates.
3. Tier B (prompt 3) → +5 gates, and the desync cap asserted (≤ 8 requests).
4. Tier C (prompt 4) → +3 gates, zero-request assertion.
5. Update README + docs (check count, scenarios table, safety rails table) and
   bump VERSION to 2.0.0. Never push `main`; branch is `trunk`.
