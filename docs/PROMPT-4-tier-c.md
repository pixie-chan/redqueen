PROMPT 4 of 4 · Red Queen v2.0 · Tier C research pipeline + release wrap-up
(paste this whole file into your opencode/muse-spark harness)

You are adding Tier C (a human-in-the-loop research pipeline) to a stdlib-only
Python web security scanner called redteam.py, and then finishing the v2.0
release. Work ONLY in /home/zen/projects/redteam-bot.

READ FIRST:
1. docs/V3-SPEC.md  (the pinned contract; this task is the "Tier C" section,
   the "Release order and gates" section, and the Invariants section)
2. parts/p1_head.py, parts/p2_checks_a.py, parts/p2_checks_b.py
3. parts/p4_bot.py (the Bot class and bot.add / bot.anomalies conventions)
4. parts/p9_report_text.py, parts/p10_report_html.py, parts/p11_main.py
5. qa/qa_a.py, qa/qa_b.py, qa/unit_sources.py, qa/harness_a.py, qa/harness_b.py

ARCHITECTURE RULES:
- redteam.py is ASSEMBLED from parts/ by ./build.sh. NEVER `cat parts/*.py`.
  New modules go in new parts files and must be added to build.sh's explicit
  cat list in the right position.
- stdlib only at runtime. Python 3.10+ compatible.
- NEVER write an em dash (U+2014) anywhere.
- The target site is always placeholder_website in fixtures and strings.
- The existing 16 QA gates must still pass UNCHANGED.

THE POINT OF TIER C: it does not attack. It turns anomalies and hand-written
hypotheses into a dossier a human can act on, and it enforces the rails
mechanically. The real-world lesson it encodes: even serious multi-vendor
findings get pushed back (one vendor called SMTP smuggling a feature, not a
vulnerability), the case was escalated to CERT/CC via VINCE, and the reporters
later concluded they had mis-scoped the impact. So the dossier must separate
hypothesis from proven impact, and must refuse to document a repro that would
need a destructive action.

MODULE 1: dossier writer. New file parts/p9c_tierc.py with
tierc_dossier(bot, candidate) -> str (the path written). It writes
research/CANDIDATE-<id>.md containing, in this order:
1. A header: candidate id, title, date, whether it came from a Tier A or B
   anomaly or from a hand-written candidate file.
2. Hypothesis, in one paragraph.
3. Evidence table: each anomaly record or raw response excerpt that supports
   the hypothesis, with every secret value replaced by the masked form that
   mask_token() in parts/p8_auth.py already produces.
4. Minimal repro template: the exact request shape that produced the anomaly,
   with the canary replaced by the literal placeholder CANARY, and a note
   saying the operator must run it only on their own staging.
5. Impact statement scaffold with three fill-in prompts: what an attacker
   gains, what data is reachable, what the blast radius is.
6. Rails verdict. Read the candidate for any destructive marker: DELETE, PUT,
   PATCH, a body that is not scanner-owned, a URL containing 169.254.169.254,
   a flood or concurrency hint, or more than 8 requests. If any is present,
   write OUT OF SCOPE in the header, explain which rail it violates, and STOP:
   do not write a repro template for it.
7. Next steps checklist, as literal text: verify on staging; check whether a
   CWE already covers it at https://cwe.mitre.org/data/definitions/<id>.html
   (note that smuggling has been CWE-444 since 2008, so name the mechanism
   rather than inventing a class); if no entry exists, submit one via
   https://cwesubmission.mitre.org/ following
   https://cwe.mitre.org/community/submissions/overview.html; for multi-vendor
   impact, report to CERT/CC per https://kb.cert.org/vuls/report/ and
   https://certcc.github.io/CERT-Guide-to-CVD/tutorials/coord_certcc/; and
   remember that Category CWE entries are Usage PROHIBITED for mapping, see
   https://cwe.mitre.org/data/definitions/1035.html.

MODULE 2: candidate file input. Add --tierc-candidates FILE. FILE is a JSON
list of candidate objects: {id, title, hypothesis, repro: [{method, url,
headers, body}]}. The scanner RENDERS dossiers from these candidates. It must
NEVER execute a repro: no request in a candidate file is ever sent, no matter
how safe it looks. Assert this in a QA gate by counting bot.t.used.

MODULE 3: scenario and reporting. New scenario "tierc" that sends no attack
traffic at all. When it runs without --tierc-candidates, it writes one
dossier per Tier A/B anomaly found this run (id ANOM-<n>). report.json gets a
"tierc" array with {id, title, path, rails, out_of_scope}. report.html gets a
section listing the dossiers and the rails verdict per candidate, with no
inline code execution. The terminal prints a short TIER C line with the number
of dossiers and how many were out of scope.

RELEASE WRAP-UP (do this last, after the gates pass):
- Bump VERSION in parts/p1_head.py to 2.0.0.
- Update README.md: the new check count, the new scenarios in the scenarios
  table, the new flags, the safety rails table gains a row for anomaly/desync
  caps, and a short honest paragraph that the anomaly engine reports
  "interesting, needs review" items, never vulnerabilities, with the published
  expectation that roughly two in three anomalies are noise.
- Update docs/ARCHITECTURE.md and docs/build-arch-html.py only if the group or
  scenario counts they display changed. Keep the industrial dossier visual
  system (graphite and amber, Archivo and JetBrains Mono) exactly as is.
- Add a CHANGELOG.md entry for 2.0.0 listing R2 plus Tiers A, B and C.

TESTS AND GATES (add to qa/qa_b.py or a new qa/unit_tierc.py invoked from
qa_b.py the way unit_sources.py is invoked):
1. A candidate file with one benign candidate produces a dossier file on disk
   that contains all four required link families (cwe.mitre.org,
   cwesubmission.mitre.org, kb.cert.org, the CERT guide) and the phrase
   "name the mechanism rather than inventing a class".
2. bot.t.used == 0 after a --tierc-candidates run: nothing was executed.
3. A candidate whose repro contains "DELETE" is marked OUT OF SCOPE and the
   dossier does NOT contain a repro template section.
4. --scenario tierc without a candidate file writes one dossier per anomaly
   and its tierc array in report.json matches the number of files written.
5. A dossier never contains a raw secret: feed a candidate with an AKIA
   example value and assert the written file has the masked form only.
6. VERSION is 2.0.0 and --list-checks exits 0.

ACCEPTANCE:
- ./build.sh prints compile OK.
- python3 qa/qa.py prints ALL QA GATES PASS and exits 0, original 16 gates
  plus yours.
- grep -c $'—' parts/*.py redteam.py README.md CHANGELOG.md returns 0.
- No commit, no push. Leave the worktree dirty.

Report back: the per-file diff summary, the full qa.py output, the text of one
generated dossier (trimmed), and anything you could not implement and why.
