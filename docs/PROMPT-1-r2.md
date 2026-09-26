PROMPT 1 of 4 · Red Queen v2.0 · R2 robustness release
(paste this whole file into your opencode/muse-spark harness)

You are implementing release R2 of a stdlib-only Python web security scanner
called redteam.py. Work ONLY in /home/zen/projects/redteam-bot.

READ FIRST, in this order, and obey the interfaces you find:
1. docs/V3-SPEC.md  (the pinned contract for R2 + Tiers A/B/C; this task is
   R2 only, the "R2: robustness release" table plus the Invariants section)
2. parts/p1_head.py, parts/p2_checks_a.py, parts/p2_checks_b.py
3. parts/p3_transport.py, parts/p4_bot.py
4. parts/p6_tls_exposure.py, parts/p8_auth.py
5. parts/p9_report_text.py, parts/p10_report_html.py, parts/p11_main.py
6. qa/qa_a.py, qa/qa_b.py, qa/harness_a.py, qa/harness_b.py, qa/harness_c.py

ARCHITECTURE RULES (breaking these breaks the build):
- redteam.py is ASSEMBLED from parts/ in a fixed order by ./build.sh.
  NEVER use `cat parts/*.py`: the shell glob sorts p10/p11 before p1_head and
  the assembled file is broken. Edit files under parts/, then run ./build.sh.
- stdlib only at runtime. No pip, no third-party imports in redteam.py.
- Python 3.10+ compatible. The bot runs on 3.11 and 3.14.
- NEVER write an em dash (U+2014) anywhere. Use commas, colons, parens.
- The target site is always named placeholder_website in fixtures and strings.
  Never put a real site name anywhere.
- The existing 16 QA gates must still pass UNCHANGED. New work adds gates.

WHAT TO IMPLEMENT (R2, from the contract table; do not invent extra scope):

M5 soft-404 autocalibration. In parts/p6_tls_exposure.py replace the current
soft404()/is_soft404() pair with a Calibration class. It probes N=5 random
paths under the target root plus the real target URL, learns a "not found"
profile (status code, length within about 15 percent, normalized body
similarity at or above 0.90 via difflib.SequenceMatcher), and exposes
is_not_found(resp). Expose the learned profile on bot.recon and in report.json
under a "calibration" key. In passive mode (no --i-own-this) do NOT send
calibration probes: reuse a single already-fetched response instead.

M4 negative and internal findings. Extend bot.add() in parts/p4_bot.py with
internal=False and negative=False keyword arguments. internal=True means the
finding is evidence only: it is stored, appears in the report, but is excluded
from counts(), the score and the exit code. negative=True marks a finding whose
signal is the ABSENCE of something; it behaves like a normal finding for
scoring. Use internal for M7 and M8 evidence records.

M8 global matchers. After discovery, sweep every captured response in
bot.pages (bodies and headers) once with these patterns: a private key header
(-----BEGIN [A-Z ]*PRIVATE KEY-----), AWS key id (AKIA[0-9A-Z]{16}), Stripe live
(sk_live_), GitHub token (ghp_), Slack token (xox[baprs]-), Google key
(AIza[0-9A-Za-z_-]{35}), and the existing stack-trace signatures. New check id
global-secret-sweep: OWASP A02, HIGH by default, CRITICAL when a private key
matches. Deduplicate against existing secret-leak findings by a hash of
(secret value, url) so the same secret in the same page is reported once. Reuse
mask_token() from parts/p8_auth.py for evidence so raw values never appear.

M7 passive replay. Add --passive. In that mode run the response-only checks
(headers, cookies, secrets, sourcemap, global sweep) over bot.pages and over any
files given by --passive-html FILE, and issue ZERO new requests. At the end of a
passive replay assert bot.t.used == 0 and record that in the report.

M20 scan-quality warnings. Add bot.warnings (a list of dicts with a code and a
human message). Emit these codes: all_unauthorized (every response was 401 or
403), everything_soft_404 (the calibration profile says every crawled route is
404-shaped), no_pages_crawled, budget_exhausted, checks_degraded (any check that
hit the guarded() exception path in run()). Add --strict-warnings: when set, any
warning present makes an otherwise clean run return exit code 3. Render
warnings in the terminal report (a SCAN QUALITY block), in report.json (a
"warnings" array) and in report.html (its own section).

M21 coverage accounting. Add a new module function coverage_statement(bot)
returning a list of dicts, one per check id in CHECKS: {check_id, owasp,
severity, tested, reason}. tested is True when the check fired this run or is
listed in a per-scenario not-tested map. Also return a static NEVER_TESTED list
of vulnerability classes with a one-line reason each: DoS and resource
exhaustion, API6 sensitive business flows, DOM and browser-only XSS, request
smuggling escalation (cache poisoning that stores payloads, response queue
poisoning), cross-account mutation without two owner-provided accounts, and
active probing of HTTP/2 CONTINUATION flood or Rapid Reset. Emit coverage in
report.json ("coverage") and report.html (a table). The terminal prints one
line: "coverage: N/M checks exercised, K classes never tested by design".

M18 exit-code contract. In run() return: 0 clean, 1 any HIGH finding, 2 any
CRITICAL finding, 3 internal error or (with --strict-warnings) any warning.
Keep the QA suite's own return code concept separate; do not add a code for it.

M14 auth verify predicate. Add --auth-verify-url URL (default: the target) and
--auth-marker TEXT. After the first request that uses --cookie, fetch the verify
URL once and decide: authenticated when there is no login/signin form in the
body AND (the --auth-marker string is present OR a session cookie is echoed).
Store bot.auth_state as "verified" or "unverified" plus a reason, put
auth_state in report.json, and when auth_state is unverified downgrade every
finding that used the cookie to confidence "medium" (existing findings already
carry a confidence field, do not remove it).

TESTS AND GATES (add to qa/qa_b.py, and harness endpoints in
qa/harness_a.py/harness_b.py if needed):
1. calibration learns a profile on the harness and is_not_found() returns True
   for a harness 404 and False for a harness 200 page.
2. a global-secret-sweep finding fires on a harness page containing
   -----BEGIN OPENSSH PRIVATE KEY----- and the evidence contains no raw key
   material beyond the masked form.
3. a --passive run over a saved harness HTML file ends with requests_used == 0.
4. warnings array appears in report.json, and a run that triggers
   no_pages_crawled exits 3 under --strict-warnings and 0 without it.
5. coverage in report.json lists every check id exactly once, and every
   NEVER_TESTED entry has a non-empty reason.
6. an --auth-verify-url run with no --cookie and a harness /login page reports
   auth_state unverified with a reason.

ACCEPTANCE (all must be true when you finish):
- ./build.sh prints "compile OK".
- python3 qa/qa.py prints ALL QA GATES PASS and exits 0, with the original 16
  gates still present and passing, plus your new gates.
- python3 redteam.py --list-checks still works and now lists 64 checks
  (63 + global-secret-sweep).
- grep -c $'—' parts/*.py redteam.py returns 0 (no em dashes).
- git status shows only intended files changed. Do NOT commit, do NOT push.
  Leave the worktree dirty so the change can be reviewed.

Report back: the exact diff summary per file, the full output of
`python3 qa/qa.py`, and anything in the contract you could not implement and
why.
