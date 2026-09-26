PROMPT 2 of 4 · Red Queen v2.0 · Tier A anomaly engine
(paste this whole file into your opencode/muse-spark harness)

You are adding the Tier A anomaly engine to a stdlib-only Python web security
scanner called redteam.py. Work ONLY in /home/zen/projects/redteam-bot.

READ FIRST, in this order:
1. docs/V3-SPEC.md  (the pinned contract; this task is the "Tier A" section
   plus the Invariants section)
2. parts/p1_head.py, parts/p2_checks_a.py, parts/p2_checks_b.py
3. parts/p3_transport.py, parts/p4_bot.py
4. parts/p9_report_text.py, parts/p10_report_html.py, parts/p11_main.py
5. qa/qa_a.py, qa/qa_b.py, qa/harness_a.py, qa/harness_b.py, qa/harness_c.py

ARCHITECTURE RULES:
- redteam.py is ASSEMBLED from parts/ by ./build.sh in a fixed order.
  NEVER `cat parts/*.py`. Edit parts/, then run ./build.sh.
- stdlib only at runtime (difflib, re, hashlib, unicodedata are all fine).
- Python 3.10+ compatible.
- NEVER write an em dash (U+2014) anywhere.
- The target site is always placeholder_website in fixtures and strings.
- The existing 16 QA gates must still pass UNCHANGED.

THE CENTRAL RULE OF THIS FEATURE: an anomaly is NOT a vulnerability. Anomalies
go into a new bot.anomalies list. They never enter bot.findings, never affect
counts(), never affect the score, and never affect the exit code. Every
anomaly record carries confidence "low" and this exact sentence in its text:
INTERESTING, NOT A VULNERABILITY: needs human review.

WHAT TO IMPLEMENT:

New registry group "anomaly" in parts/p2_checks_b.py GROUPS, new scenario
"anomaly" in SCENARIOS, and a new check function check_anomaly(bot) in a new
file parts/p9b_anomaly.py. Add that file to build.sh's explicit cat list
between p8_auth.py and p9_report_text.py, and register
RUNNERS["anomaly"] = [check_anomaly] in parts/p11_main.py.

The engine, in order:
1. Baseline. For every route in bot.pages, record: status, body length, the
   sorted set of response header names, content-type, and body_fp = sha256 of
   the normalized body. Normalization replaces QX[a-f0-9]+ canaries with a
   fixed token, collapses digit runs of 3 or more, and collapses whitespace
   runs. Reuse the existing title_of() and norm() helpers where they fit.
2. Differential probes, each carrying a per-run unique canary QX followed by
   hex from bot.canary, capped at 9 requests per route and 120 requests for
   the whole engine, and skipped entirely unless the scenario includes the
   anomaly group:
   a. header canary: same GET with X-Forwarded-Host, X-Original-URL and
      X-Rewrite-URL each set to the canary host, one request each.
   b. path suffix: the same path plus .css, then plus .png, then plus .js.
   c. delimiter variants on the path: a trailing ";", a trailing "?", a
      trailing dot, and a "%2e" segment, one request each.
   d. method variants: HEAD, then OPTIONS on the same path.
   e. content-type variant: the same GET with Accept: text/plain.
   Never send POST, PUT, PATCH or DELETE. Never send a body.
3. Distance. For each probe response compute
   difflib.SequenceMatcher(None, norm(probe_body), norm(baseline_body)).ratio()
   and the set difference of header names in both directions.
4. Record. bot.anomalies gets one dict per probe:
   {route, probe_class, distance, status_delta, headers_added,
    headers_removed, canary_reflected, note}
   where canary_reflected is True when the canary string appears anywhere in
   the probe response body or headers, and distance is rounded to 3 decimals.
5. Filter. Drop a record when the calibration profile from R2 says the response
   is a not-found shape, and drop a record when canary_reflected is False AND
   distance > 0.15. Keep everything else.
6. Rank. Sort ascending by distance (most different first) and cap at 5 per
   route, overridable with --anomaly-cap N (default 5, clamp maximum 20).
7. Output. A new report section in all three outputs: terminal gets an
   ANOMALIES (needs review) block after the findings table, report.json gets
   an "anomalies" array, report.html gets a dedicated section with the same
   severity-filter treatment as findings. CHECKLIST.md gets a separate
   "Anomalies to review (not vulnerabilities)" section at the end.

NEW FLAGS: --anomaly (force the engine on regardless of scenario),
--anomaly-cap N, --anomaly-keep-all (skip the noise filter, for debugging).

TESTS AND GATES (add to qa/qa_b.py and harness endpoints as needed):
1. The harness gains a route /cacheable that reflects X-Forwarded-Host into the
   response body, and a mode where every unknown path returns the same 404 page.
   Assert the engine produces at least one anomaly with canary_reflected True
   on /cacheable.
2. Assert that on the all-404 harness the engine produces no anomaly with
   distance below 0.15 (noise floor respected).
3. Assert bot.anomalies never appears in findings: run the weak harness with
   --scenario full --anomaly and assert the report score and counts are
   identical to the same run without --anomaly.
4. Assert the request budget: the engine's own request count is reported in
   report.json as "anomaly_requests" and never exceeds 120, and per-route
   probes never exceed 9.
5. Assert every anomaly record contains the literal sentence
   "INTERESTING, NOT A VULNERABILITY" and confidence "low".
6. Assert --anomaly-cap 2 caps the per-route list at 2.

ACCEPTANCE:
- ./build.sh prints compile OK.
- python3 qa/qa.py prints ALL QA GATES PASS and exits 0, original 16 gates plus
  your new ones.
- python3 redteam.py --list-checks shows the anomaly scenario listed.
- grep -c $'—' parts/*.py redteam.py returns 0.
- No commit, no push. Leave the worktree dirty.

Report back: the per-file diff summary, the full qa.py output, the JSON shape of
two example anomalies, and anything you could not implement and why.
