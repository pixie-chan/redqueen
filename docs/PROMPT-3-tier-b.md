PROMPT 3 of 4 · Red Queen v2.0 · Tier B empty-taxonomy surface hunting
(paste this whole file into your opencode/muse-spark harness)

You are adding Tier B (systematic novel-surface exploration) to a stdlib-only
Python web security scanner called redteam.py. Work ONLY in
/home/zen/projects/redteam-bot.

READ FIRST:
1. docs/V3-SPEC.md  (the pinned contract; this task is the "Tier B" section
   plus the Invariants section)
2. parts/p1_head.py, parts/p2_checks_a.py, parts/p2_checks_b.py
3. parts/p3_transport.py, parts/p4_bot.py
4. parts/p6_tls_exposure.py (the norm() helper and calibration live near here)
5. parts/p9_report_text.py, parts/p10_report_html.py, parts/p11_main.py
6. qa/qa_a.py, qa/qa_b.py, qa/harness_a.py, qa/harness_b.py, qa/harness_c.py

ARCHITECTURE RULES:
- redteam.py is ASSEMBLED from parts/ by ./build.sh. NEVER `cat parts/*.py`.
  Edit parts/, then run ./build.sh. New modules go in new parts files, and you
  must add each new file to build.sh's explicit cat list in the right position.
- stdlib only at runtime. Python 3.10+ compatible.
- NEVER write an em dash (U+2014) anywhere.
- The target site is always placeholder_website in fixtures and strings.
- The existing 16 QA gates must still pass UNCHANGED.

WHY THIS FEATURE EXISTS: HTTP request smuggling has existed under CWE-444 since
2008, so the novel part is never a new class name, it is a new MECHANISM. The
modern length-interpretation taxonomy has four cells: Content-Length, Transfer-
Encoding, implicit zero, and HTTP/2's own length. TE.0 was found by asking "why
does no TE.0 exist?" and then validating the candidate against a live target.
So this engine enumerates untested cells rather than replaying the classic
CL.TE probe.

THE CENTRAL RULE: everything here emits ANOMALIES (bot.anomalies, tier "B"),
never findings, with ONE exception: a confirmed desync cross-contamination IS a
finding (check id desync-confirmed, OWASP A01, CRITICAL, CWE-444). Anomalies
never affect counts(), the score, or the exit code, and every anomaly carries
confidence "low" and the literal sentence
INTERESTING, NOT A VULNERABILITY: needs human review.

NEW REGISTRY GROUP "tierb", NEW SCENARIO "tierb", and four new check functions
in a new file parts/p8b_tierb.py (add that file to build.sh after p8_auth.py and
before p9_report_text.py, and register the four functions in
RUNNERS["tierb"]).

MODULE 1: check_desync_cells(bot), the four-cell prober.
- For each cell in this order: CL (Content-Length), TE (Transfer-Encoding:
  chunked), 0 (implicit zero: a GET with a Content-Length header and no body),
  H2 (HTTP/2 length).
- One keep-alive connection per cell. At most two requests per cell: a setup
  request whose body embeds a unique per-run canary (QX + hex from
  bot.canary), then a follow-up GET with a zero-length body.
- Success = the follow-up response contains the earlier canary, OR its
  normalized body differs from the calibrated not-found profile by more than
  0.15, OR its status differs from the follow-up baseline by more than the
  calibration tolerance.
- HARD CAPS: at most 8 requests for the whole module. Content-Length and
  Transfer-Encoding are never both sent with a real body. Never send a chunked
  body larger than 64 bytes. Never mutate state. Abort the module immediately
  on the first confirmed desync and report it once as desync-confirmed.
- The H2 cell cannot be sent: Python's http.client speaks HTTP/1.1 only.
  Record it as an anomaly with note "skipped: needs an HTTP/2 client" instead
  of sending anything, unless the user passes --allow-h2-probe, which only
  relaxes the reporting and still sends nothing.
- Add the flag --desync-probe: without it the module reports a single anomaly
  saying the desync cells were not probed (it never probes by default).

MODULE 2: check_unicode_oracles(bot).
- For every reflected query parameter discovered by the crawler, send three
  values once each: U+212A KELVIN SIGN, U+FF21 FULLWIDTH LATIN CAPITAL LETTER A,
  and a base+e+U+0301 combining acute sequence. Cap: 12 requests total.
- Compare the reflected bytes against unicodedata.normalize("NFKC", sent).
- Emit an anomaly when the server's stored or echoed form differs from the
  sent form in a way that would change an identity comparison, with the note
  naming the exact codepoints involved.

MODULE 3: check_delimiter_confusion(bot).
- Pick one crawled GET path. Append, one request each: ";", "?", "#", a
  trailing dot, and a "%2e" segment. Cap 10 requests.
- Emit an anomaly when the response differs from that path's baseline beyond
  the calibration profile, with the note "cache and origin may disagree on the
  path" when the statuses match but the bodies differ, or "status changed for a
  delimited variant" otherwise.

MODULE 4: check_api_states(bot).
- Needs --api-spec FILE pointing at a JSON OpenAPI 3 document, or reuses the
  document exp-api-docs already found this run.
- For each path template containing a {param}, synthesize exactly ONE inert
  value: try "0", then "1", then a "QX"+hex string. Request it unauthenticated,
  and compare to the anonymous baseline for the collection path.
- Report an authorization differential as an anomaly with confidence "medium"
  and a note that says explicitly: not a proven BOLA, needs a second
  owner-provided account to confirm.
- NEVER send DELETE, PUT or PATCH. POST is allowed only when the spec marks the
  operation AND --allow-spec-post is given, and then only with a body of
  scanner-owned dummy values. Cap 30 requests.

OUTPUTS:
- Anomalies from these modules get tier "B" and appear in the same report
  sections as Tier A anomalies, with a tier column.
- desync-confirmed appears as a normal finding with a full fix string:
  "end to end HTTP/2 or a single strict HTTP/1.1 parser, reject duplicate
  Content-Length and Transfer-Encoding, and validate rewritten requests
  against RFC 9112 before forwarding".

TESTS AND GATES (add to qa/qa_b.py and harness endpoints in
qa/harness_a.py/harness_b.py as needed):
1. A harness route that echoes a smuggled canary (a deliberately broken
   handler that returns the previous request's body marker) makes
   desync-confirmed fire, and the module's total request count is asserted to
   be at most 8 (report it as desync_requests in report.json).
2. Without --desync-probe, no desync request is sent at all (assert
   desync_requests == 0 and only the "not probed" anomaly is present).
3. The H2 cell is never sent: assert the anomaly note contains
   "needs an HTTP/2 client".
4. check_unicode_oracles on a harness page that reflects a value produces at
   most 12 requests and the anomaly record names the codepoints.
5. check_api_states against a harness-served OpenAPI document produces an
   anomaly for each {param} path and never sends a mutating method (assert
   method set in the report is only GET, plus POST only under the flag).
6. Tier A and Tier B anomalies together do not change the findings count, the
   score, or the exit code relative to the same run without the tierb scenario.

ACCEPTANCE:
- ./build.sh prints compile OK.
- python3 qa/qa.py prints ALL QA GATES PASS and exits 0, original 16 gates plus
  yours.
- python3 redteam.py --list-checks shows the tierb scenario.
- grep -c $'—' parts/*.py redteam.py returns 0.
- No commit, no push. Leave the worktree dirty.

Report back: the per-file diff summary, the full qa.py output, the JSON of one
desync-confirmed finding and one tierb anomaly, and anything you could not
implement and why.
