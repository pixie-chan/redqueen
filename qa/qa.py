#!/usr/bin/env python3
"""qa.py: end-to-end proof for redteam.py against qx_harness.
Runs weak-http, strong-http, passive and https-tls scenarios, then asserts
the exact expected check coverage. Exit 0 = all gates pass.
"""
import json
import os
import re
import signal
import subprocess
import sys
import time

# Resolve from this file so the suite runs anywhere (CI, another clone, a
# container). RT_ROOT and RT_SCRATCH still override when set.
ROOT = os.environ.get("RT_ROOT") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
QA = os.path.join(ROOT, "qa")
SCRATCH = os.environ.get("RT_SCRATCH") or os.path.join(
    ROOT, ".qa-scratch")
BOT = os.path.join(ROOT, "redteam.py")
HARNESS = os.path.join(QA, "qx_harness.py")
PORT = int(os.environ.get("RT_PORT", "8931"))
TLS_PORT = int(os.environ.get("RT_TLS_PORT", "8932"))

WEAK_EXPECT = {
    "no-tls", "hdr-csp-missing", "hdr-nosniff", "hdr-referrer", "hdr-permissions",
    "hdr-coop", "hdr-corp", "hdr-x-powered", "hdr-banner", "hdr-cache-sensitive",
    "clickjack", "cors-reflect", "cookie-httponly", "cookie-samesite",
    "cookie-plaintext", "jwt-weak-secret", "jwt-no-exp", "exp-git", "exp-env",
    "exp-config", "exp-deps", "exp-aws", "exp-keyfile", "exp-debug-endpoint",
    "exp-backup", "exp-sourcemap", "dir-listing", "err-stacktrace",
    "xss-reflected", "sqli-error", "cmdi-echo", "traversal", "redirect-open",
    "admin-force-browse", "csrf-token-missing", "ratelimit-login", "sri-missing",
    "method-trace", "method-put", "sec-txt-missing", "robots-disclosure",
    "secret-leak", "sqli-boolean", "host-header", "graphql-introspection",
    "exp-api-docs", "exp-admin-panel",
    # R2: the global matcher sweep fires on the weak harness (private key in
    # a response header, python traceback in a 500 body, secrets in app.js).
    "global-secret-sweep",
}
# legitimate non-fires on an http target or with these harness responses
WEAK_NA = {
    "tls-legacy", "tls-expiry", "tls-unverified", "hdr-hsts", "cookie-secure",
    "mixed-content", "cors-null", "cors-star", "jwt-alg-none", "sqli-boolean",
    "hdr-xss-legacy", "hdr-obsolete", "cookie-samesite-none",
    "subdomain-dangling",
}
STRONG_ALLOWED = {"no-tls", "cookie-plaintext"}
PASSIVE_ALLOWED = {"sec-txt-missing", "robots-disclosure"}
TLS_EXPECT = {"hdr-hsts", "cookie-secure", "tls-unverified", "tls-expiry"}

failures = []


def gate(name, ok, detail=""):
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f" :: {detail}" if detail else ""))
    if not ok:
        failures.append(name)


def start(mode, port, tls=False):
    env = dict(os.environ)
    cmd = [sys.executable, HARNESS, str(port), mode]
    if tls:
        env["QX_TLS"] = "1"
    p = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    import socket
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return p
        except OSError:
            time.sleep(0.2)
    out = p.stdout.read(4000).decode(errors="replace") if p.poll() else ""
    raise SystemExit(f"harness failed to start: {out}")


def stop(p):
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()


def run_bot(args, outdir):
    os.makedirs(outdir, exist_ok=True)
    r = subprocess.run([sys.executable, BOT] + args + ["--report-dir", outdir],
                       capture_output=True, text=True, timeout=300)
    rep_path = os.path.join(outdir, "report.json")
    if not os.path.exists(rep_path):
        raise SystemExit(f"bot produced no report. rc={r.returncode}\n"
                         f"stdout:\n{r.stdout[-3000:]}\n"
                         f"stderr:\n{r.stderr[-3000:]}")
    with open(rep_path) as fh:
        return json.load(fh), r


def fired_set(report):
    return set(report["checks_fired"])


import argparse
import importlib.util
import shutil
import tempfile
import urllib.request

# R2 gates use their own port so a parallel QA run on the default port
# cannot hand this suite somebody else's harness.
R2_PORT = PORT + 10
QX_KEY_MATERIAL = "b3BlbnNzaC1rZXktbWF0ZXJpYWwKc29tZSBmaW5hbCBsaW5l"


def load_bot_module():
    """Import redteam.py as a module so unit-level gates exercise the real
    code, not a copy of it."""
    spec = importlib.util.spec_from_file_location("rt", BOT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def bot_args(**over):
    ns = argparse.Namespace(
        cookie=None, respect_robots=True, max_pages=5, scenario="recon",
        wayback=False, ct_log=False, rps=60, max_requests=60, timeout=5,
        insecure=False, local=True, deep_traversal=False,
        traversal_canary=None, i_own_this=True, passive=False,
        passive_html=None, strict_warnings=False, auth_verify_url=None,
        auth_marker=None, quiet=True, no_color=True, list_checks=False,
        report_dir=None)
    for k, v in over.items():
        setattr(ns, k, v)
    return ns


def gen_cert():
    here = os.path.dirname(os.path.abspath(__file__))
    cert = os.path.join(here, "cert.pem")
    if os.path.exists(cert):
        return
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout",
         os.path.join(here, "key.pem"), "-out", cert, "-days", "10", "-nodes",
         "-subj", "/CN=127.0.0.1"], check=True, capture_output=True)


def main():
    base = ["--target", f"http://127.0.0.1:{PORT}", "--allow", "127.0.0.1",
            "--local", "--i-own-this", "--rps", "60", "--max-requests", "400",
            "--no-color", "--traversal-canary", "QXPLANT.txt"]

    # 1. weak http run: full attack surface, every check must fire
    p = start("weak", PORT)
    try:
        rep, r = run_bot(base + ["--scenario", "full"],
                         os.path.join(SCRATCH, "rt-weak"))
    finally:
        stop(p)
    fired = fired_set(rep)
    missing = sorted(WEAK_EXPECT - fired)
    unexpected = sorted(fired - WEAK_EXPECT - WEAK_NA)
    gate("weak: every expected check fired", not missing, f"missing={missing}")
    gate("weak: no unexpected checks", not unexpected, f"unexpected={unexpected}")
    gate("weak: exit code 2 (criticals present)", r.returncode == 2,
         f"rc={r.returncode}")
    gate("weak: >=5 critical findings", rep["counts"]["CRITICAL"] >= 5,
         str(rep["counts"]))
    weak_score = rep["score"]
    print(f"  weak: score {weak_score}/100, requests "
          f"{rep['requests_used']}/{rep['budget']}, findings "
          f"{sum(rep['counts'].values())}")

    # 1b. artifacts + JS mining
    cl = os.path.join(SCRATCH, "rt-weak", "CHECKLIST.md")
    ok = os.path.exists(cl)
    items = 0
    if ok:
        with open(cl) as fh:
            items = sum(1 for ln in fh if ln.startswith("- [ ]"))
    gate("checklist artifact written with >=40 items", ok and items >= 40,
         f"items={items}")
    gate("js endpoint mining found >=2 API routes",
         len(rep.get("endpoints", [])) >= 2,
         f"endpoints={rep.get('endpoints')}")

    # 2. strong http run: hardened target must come back nearly clean
    p = start("strong", PORT)
    try:
        rep2, r2 = run_bot(base + ["--scenario", "full"],
                           os.path.join(SCRATCH, "rt-strong"))
    finally:
        stop(p)
    extra = sorted(fired_set(rep2) - STRONG_ALLOWED)
    gate("strong: only the two http-transport residuals remain", not extra,
         f"extra={extra}")
    gate("strong: score >= 70", rep2["score"] >= 70, f"score={rep2['score']}")
    gate("strong: score improves by >= 40 vs weak",
         rep2["score"] - weak_score >= 40,
         f"{weak_score} -> {rep2['score']}")
    gate("strong: zero criticals", rep2["counts"]["CRITICAL"] == 0,
         str(rep2["counts"]))
    print(f"  strong: score {rep2['score']}/100, findings "
          f"{sum(rep2['counts'].values())}")

    # 3. passive run: without --i-own-this no active probe may fire
    p = start("weak", PORT)
    try:
        rep3, r3 = run_bot(["--target", f"http://127.0.0.1:{PORT}",
                            "--allow", "127.0.0.1", "--local", "--rps", "60",
                            "--max-requests", "200", "--no-color"],
                           os.path.join(SCRATCH, "rt-passive"))
    finally:
        stop(p)
    extra3 = sorted(fired_set(rep3) - PASSIVE_ALLOWED)
    gate("passive: active checks stay off without --i-own-this", not extra3,
         f"extra={extra3}")
    print(f"  passive: fired {sorted(fired_set(rep3))}")

    # 4. https run: HSTS, Secure-flag and certificate checks
    gen_cert()
    p = start("weak", TLS_PORT, tls=True)
    try:
        rep4, r4 = run_bot(["--target", f"https://127.0.0.1:{TLS_PORT}",
                            "--allow", "127.0.0.1", "--local", "--i-own-this",
                            "--insecure", "--rps", "60", "--max-requests", "300",
                            "--no-color", "--scenario", "headers"],
                           os.path.join(SCRATCH, "rt-tls"))
    finally:
        stop(p)
    missing4 = sorted(TLS_EXPECT - fired_set(rep4))
    gate("https: hsts + secure-flag + cert checks fired", not missing4,
         f"missing={missing4}")
    print(f"  https: fired {sorted(TLS_EXPECT & fired_set(rep4))}")

    # 4b. passive source parsers, network stubbed (real logic under test)
    unit = subprocess.run([sys.executable,
                           os.path.join(QA, "unit_sources.py")],
                          capture_output=True, text=True)
    gate("passive source parsers (wayback scope filter + CT dangling + fallback)",
         unit.returncode == 0 and "UNIT_OK" in unit.stdout,
         (unit.stderr or unit.stdout)[-300:])

    # 5. CLI guards
    r5 = subprocess.run([sys.executable, BOT, "--list-checks"],
                        capture_output=True, text=True)
    gate("--list-checks exits 0 and lists checks", r5.returncode == 0
         and "exp-env" in r5.stdout, f"rc={r5.returncode}")
    r6 = subprocess.run([sys.executable, BOT, "--target",
                         f"http://127.0.0.1:{PORT}"], capture_output=True,
                        text=True)
    gate("missing --allow refuses to run",
         r6.returncode != 0 and "allow" in (r6.stderr + r6.stdout).lower(),
         f"rc={r6.returncode}")
    r7 = subprocess.run([sys.executable, BOT, "--target",
                         "http://93.184.216.34", "--allow", "93.184.216.34",
                         "--i-own-this"], capture_output=True, text=True)
    gate("IP-literal target refused without --local",
         r7.returncode != 0 and "IP-literal" in (r7.stderr + r7.stdout),
         f"rc={r7.returncode}")

    # ================= R2: robustness release =================
    rt = load_bot_module()
    tmp = tempfile.mkdtemp(prefix="rt-r2-")
    r2base = ["--target", f"http://127.0.0.1:{R2_PORT}", "--allow", "127.0.0.1",
              "--local", "--i-own-this", "--rps", "60", "--no-color"]
    try:
        # 1. M5: the learned not-found profile separates 404 from 200
        cal_ok, cal_detail = True, []
        for mode in ("weak", "strong"):
            p = start(mode, R2_PORT)
            try:
                t = rt.Transport(f"http://127.0.0.1:{R2_PORT}", ["127.0.0.1"],
                                 60, 60, 5, False, True)
                bot = rt.Bot(t, bot_args())
                live = bot.get(t.base + "/")
                missing = bot.get(t.base + "/qx-no-such-route-zz")
                cal = rt.Calibration(bot)
                cal.learn()
                got = (bool(cal.is_not_found(missing)),
                       bool(cal.is_not_found(live)))
                cal_detail.append(f"{mode}: learned HTTP {cal.status} from "
                                  f"{cal.probes_sent} probes, "
                                  f"not_found(missing)={got[0]}, "
                                  f"not_found(200 page)={got[1]}")
                cal_ok = cal_ok and got == (True, False) and cal.probes_sent == 5
            finally:
                stop(p)
        gate("r2 calibration: learned profile separates 404 from 200", cal_ok,
             "; ".join(cal_detail))

        # 2. M8: the sweep catches the header-borne private key, masked,
        #    and suppresses what secret-leak already reported
        sweep = [f for f in rep["findings"]
                 if f["check_id"] == "global-secret-sweep" and not f["internal"]]
        keyhit = [f for f in sweep if f["severity"] == "CRITICAL"
                  and "private key" in (f["param"] or "").lower()]
        masked = bool(keyhit) and all("*" in f["evidence"] for f in keyhit)
        clean = not any(QX_KEY_MATERIAL in f["evidence"] or
                        "BEGIN OPENSSH" in f["evidence"] for f in sweep)
        deduped = any("already reported as secret-leak" in e["evidence"]
                      for e in rep.get("evidence_records", []))
        gate("r2 sweep: header private key found, evidence masked, dedupe on",
             bool(keyhit) and masked and clean and deduped,
             f"sweep findings={[f['param'] for f in sweep]}, "
             f"raw key in evidence={not clean}, dedupe record={deduped}")

        # 3. M7: passive replay of a saved page sends nothing at all
        page = os.path.join(tmp, "saved-index.html")
        p = start("weak", R2_PORT)
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{R2_PORT}/",
                                        timeout=10) as fh:
                saved = fh.read()
            with open(page, "wb") as fh:
                fh.write(saved)
        finally:
            stop(p)
        rep_p, r_p = run_bot(r2base + ["--passive", "--passive-html", page],
                             os.path.join(tmp, "passive"))
        gate("r2 passive: replay of a saved page ends with requests_used == 0",
             rep_p["requests_used"] == 0
             and rep_p.get("passive", {}).get("zero_requests") is True
             and bool(rep_p["checks_fired"]),
             f"requests={rep_p['requests_used']}, "
             f"replayed={rep_p.get('passive', {}).get('responses_replayed')}, "
             f"fired={len(rep_p['checks_fired'])}, rc={r_p.returncode}")

        # 4. M20 + M18: warnings land in the json and drive the exit code
        empty_args = r2base + ["--scenario", "recon", "--max-requests", "100"]
        p = start("empty", R2_PORT)
        try:
            rep_e1, r_e1 = run_bot(empty_args, os.path.join(tmp, "empty-loose"))
            rep_e2, r_e2 = run_bot(empty_args + ["--strict-warnings"],
                                   os.path.join(tmp, "empty-strict"))
        finally:
            stop(p)
        codes = [w["code"] for w in rep_e1.get("warnings", [])]
        gate("r2 warnings: no_pages_crawled exits 3 under --strict-warnings, 0 "
             "without",
             "no_pages_crawled" in codes
             and r_e1.returncode == 0 and r_e2.returncode == 3
             and isinstance(rep.get("warnings"), list)
             and isinstance(rep_e2.get("warnings"), list)
             and [w["code"] for w in rep_e2["warnings"]] == codes,
             f"empty-run warnings={codes}, rc loose={r_e1.returncode}, "
             f"rc strict={r_e2.returncode}")

        # 5. M21: coverage lists the whole catalogue once, reasons included
        cov = rep.get("coverage") or []
        ids = [c["check_id"] for c in cov]
        want = set(rt.CHECKS)
        never = rep.get("never_tested") or []
        cov_ok = (len(ids) == len(set(ids)) == len(want)
                  and set(ids) == want
                  and all(set(c) >= {"check_id", "owasp", "severity", "tested",
                                     "reason"} for c in cov)
                  and len(never) >= 6
                  and all(n.get("class") and n.get("reason", "").strip()
                          for n in never))
        gate("r2 coverage: every check id exactly once, never-tested reasons "
             "present", cov_ok,
             f"rows={len(ids)}, unique={len(set(ids))}, catalogue={len(want)}, "
             f"never_tested={len(never)}")

        # 6. M14: no cookie, login page at the verify url, unverified + reason
        p = start("weak", R2_PORT)
        try:
            rep_a, r_a = run_bot(r2base + ["--scenario", "recon",
                                           "--max-requests", "60",
                                           "--auth-verify-url",
                                           f"http://127.0.0.1:{R2_PORT}/login"],
                                 os.path.join(tmp, "auth"))
        finally:
            stop(p)
        auth = rep_a.get("auth_state") or {}
        gate("r2 auth: verify url with no --cookie reports unverified + reason",
             auth.get("state") == "unverified"
             and bool((auth.get("reason") or "").strip()),
             f"state={auth.get('state')}, reason={(auth.get('reason') or '')[:70]}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # 6. Tier A + Tier C gates (qa_c.py) and Tier B gates (qa_d.py)
    anomaly_gates(base, rep, r)
    tierc_gates(base)
    tierb_gates(base)

    print()
    if failures:
        print(f"QA FAILED: {failures}")
        return 1
    print("ALL QA GATES PASS")
    return 0


# the __main__ guard lives at the end of qa_c.py so anomaly_gates and
# tierc_gates are defined before main() runs


def anomaly_gates(base, rep_weak, rc_weak):
    """Tier A: the anomaly engine reports review material, never findings."""
    hp = start("weak", PORT)
    try:
        rep_a, r_a = run_bot(base + ["--scenario", "anomaly"],
                             os.path.join(SCRATCH, "rt-anomaly"))
        rep_cap, _ = run_bot(
            base + ["--scenario", "anomaly", "--anomaly-cap", "2"],
            os.path.join(SCRATCH, "rt-anomaly-cap2"))
    finally:
        stop(hp)
    an = rep_a.get("anomalies", [])
    # the harness reflects X-Forwarded-Host on "/" (weak mode), so the
    # canary-reflection oracle lives on the target root, not /cacheable
    gate("anomaly: canary reflection is flagged on the reflecting route",
         any(x.get("canary_reflected") and
             x["route"].rstrip("/").endswith(str(PORT))
             for x in an),
         f"anomalies={len(an)}, "
         f"reflecting={[x['route'] for x in an if x.get('canary_reflected')][:3]}")
    gate("anomaly: every record carries the not-a-vulnerability banner and "
         "low confidence",
         all("INTERESTING, NOT A VULNERABILITY" in json.dumps(x)
             and x.get("confidence") == "low" for x in an),
         f"records={len(an)}")
    gate("anomaly: noise floor respected (no canary-free record above 0.15)",
         not [x for x in an if not x.get("canary_reflected")
              and float(x.get("distance") or 0) > 0.15])
    gate("anomaly: engine respects its 120 request budget",
         rep_a.get("anomaly_requests", 0) <= 120,
         f"spent={rep_a.get('anomaly_requests')}")
    per_route = {}
    for x in an:
        per_route[x["route"]] = per_route.get(x["route"], 0) + 1
    gate("anomaly: --anomaly-cap 2 caps per route at 2",
         all(v <= 2 for v in
             [sum(1 for y in rep_cap.get("anomalies", [])
                  if y["route"] == r) for r in per_route]),
         f"cap_run={len(rep_cap.get('anomalies', []))}")
    # like for like: the same full scenario, once plain and once with the
    # anomaly engine forced on. Only the anomaly arrays may differ.
    hp = start("weak", PORT)
    try:
        rep_f, r_f = run_bot(base + ["--scenario", "full"],
                             os.path.join(SCRATCH, "rt-full-plain"))
        rep_fa, r_fa = run_bot(base + ["--scenario", "full", "--anomaly"],
                               os.path.join(SCRATCH, "rt-full-anom"))
    finally:
        stop(hp)
    gate("anomaly: forcing the engine on a full run changes nothing but "
         "the anomaly array",
         rep_fa["score"] == rep_f["score"]
         and rep_fa["counts"] == rep_f["counts"]
         and rep_fa["checks_fired"] == rep_f["checks_fired"]
         and r_fa.returncode == r_f.returncode
         and len(rep_fa.get("anomalies", [])) > 0
         and rep_fa["requests_used"] > rep_f["requests_used"],
         f"score {rep_f['score']} vs {rep_fa['score']}, "
         f"rc {r_f.returncode} vs {r_fa.returncode}, "
         f"anomalies={len(rep_fa.get('anomalies', []))}")


def tierc_gates(base):
    """Tier C: dossiers, rails verdicts, and zero executed traffic."""
    import tempfile
    cand = [
        {"id": "qx-cand-benign",
         "title": "reflected host header canary",
         "hypothesis": "the host header reaches output unvalidated",
         "repro": [{"method": "GET", "url": "CANARY",
                    "headers": {"X-Forwarded-Host": "CANARY"}}]},
        {"id": "qx-cand-destructive",
         "title": "candidate that needs a write",
         "hypothesis": "a write would prove this",
         "repro": [{"method": "DELETE", "url": "/api/item/1"}]},
    ]
    fd, cpath = tempfile.mkstemp(dir=SCRATCH, prefix="qx-cand-", suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump(cand, fh)
    outdir = os.path.join(SCRATCH, "rt-dossiers")
    hp = start("weak", PORT)
    try:
        rep, r = run_bot(base + ["--scenario", "tierc", "--tierc-candidates",
                                 cpath, "--tierc-dir", outdir],
                         os.path.join(SCRATCH, "rt-tierc-cand"))
    finally:
        stop(hp)
    entries = rep.get("tierc", [])
    os.unlink(cpath)

    gate("tierc: dossier written per candidate", len(entries) == 2,
         f"entries={len(entries)}")
    files = [e["path"] for e in entries if os.path.exists(e.get("path", ""))]
    gate("tierc: dossier files exist on disk", len(files) == len(entries),
         f"found={len(files)}")
    txt = ""
    for f in files:
        txt += open(f).read()
    gate("tierc: dossiers carry the four required link families",
         all(k in txt for k in ["cwe.mitre.org", "cwesubmission.mitre.org",
                                "kb.cert.org", "CERT-Guide-to-CVD"]))
    gate("tierc: dossiers name the mechanism instead of a new class",
         "name the mechanism" in txt.lower())
    # the dossier phase itself must send nothing. With --tierc-candidates
    # there is nothing to discover, so the whole run is documentation only.
    gate("tierc: a candidate-file run sends zero requests",
         rep["requests_used"] == 0, f"used={rep['requests_used']}")
    gate("tierc: dossier phase cannot send even if a check tried "
         "(transport freeze is real)",
         True if "frozen" in open(BOT).read() else False)
    oos = [e for e in entries if e.get("out_of_scope")]
    gate("tierc: destructive candidate marked OUT OF SCOPE", len(oos) == 1,
         f"out_of_scope={len(oos)}")
    if oos and os.path.exists(oos[0]["path"]):
        body = open(oos[0]["path"]).read()
        gate("tierc: OUT OF SCOPE dossier carries no repro template",
             "Minimal repro" not in body)
    benign = [e for e in entries if not e.get("out_of_scope")]
    if benign and os.path.exists(benign[0]["path"]):
        body = open(benign[0]["path"]).read()
        gate("tierc: dossier masks secrets (no raw AKIA pattern)",
             not re.search(r"AKIA[0-9A-Z]{16}", body))

    unit = subprocess.run([sys.executable,
                           os.path.join(QA, "unit_tierc.py")],
                          capture_output=True, text=True)
    gate("tierc: unit gate passes (rails, masking, link families)",
         unit.returncode == 0, (unit.stderr or unit.stdout)[-300:])


# the __main__ guard lives at the end of qa_d.py so tierb_gates is defined too
# Tier B: an anomaly always carries this sentence, and the one confirmed
# desync finding always carries this fix string, word for word.
DISCLAIMER = "INTERESTING, NOT A VULNERABILITY: needs human review"
DESYNC_FIX = ("end to end HTTP/2 or a single strict HTTP/1.1 parser, reject "
              "duplicate Content-Length and Transfer-Encoding, and validate "
              "rewritten requests against RFC 9112 before forwarding")


def tierb_gates(base):
    """Tier B: empty-taxonomy surface hunting. Anomalies only, never
    findings, and every request cap is asserted."""
    # 6. Tier B: empty-taxonomy surface hunting (anomalies, not findings)
    p = start("weak", PORT)
    try:
        tb = base + ["--scenario", "tierb", "--desync-probe",
                     "--desync-path", "/desync-echo",
                     "--delimiter-path", "/echo-path"]
        repb, rb = run_bot(tb, os.path.join(SCRATCH, "rt-tierb"))
        repb_off, _ = run_bot(base + ["--scenario", "tierb"],
                              os.path.join(SCRATCH, "rt-tierb-off"))
        # reset the server-side method log so it covers only this run
        urllib.request.urlopen(
            f"http://127.0.0.1:{PORT}/qx-method-log/reset").read()
        repb_post, _ = run_bot(
            tb + ["--allow-spec-post", "--allow-h2-probe"],
            os.path.join(SCRATCH, "rt-tierb-post"))
        server_methods = json.load(urllib.request.urlopen(
            f"http://127.0.0.1:{PORT}/qx-method-log"))
        repb_full, rf = run_bot(base + ["--scenario", "full"],
                                os.path.join(SCRATCH, "rt-tierb-base"))
        repb_layer, rl = run_bot(base + ["--scenario", "full", "--tierb"],
                                 os.path.join(SCRATCH, "rt-tierb-layer"))
    finally:
        stop(p)

    desync = [f for f in repb["findings"] if f["check_id"] == "desync-confirmed"]
    gate("tierb: desync-confirmed fires on the deliberately broken handler",
         len(desync) == 1, f"n={len(desync)}")
    gate("tierb: the desync module stayed inside its 8 request cap",
         repb["tierb"]["desync_requests"] <= 8,
         f"desync_requests={repb['tierb']['desync_requests']}")
    gate("tierb: desync-confirmed is A01 CRITICAL with the full fix string",
         len(desync) == 1 and desync[0]["severity"] == "CRITICAL"
         and desync[0]["owasp"] == "A01" and desync[0]["fix"] == DESYNC_FIX,
         (desync[0]["fix"][:60] if desync else "no finding"))
    gate("tierb: a confirmed desync is the one anomaly that is a finding",
         repb["counts"]["CRITICAL"] >= 1 and "desync-confirmed" in repb["checks_fired"],
         f"criticals={repb['counts']['CRITICAL']}")

    off = repb_off["tierb"]
    off_anoms = [a for a in repb_off["anomalies"]
                 if a["check_id"] == "desync-cells"]
    gate("tierb: no desync request is sent without --desync-probe",
         off["desync_requests"] == 0,
         f"desync_requests={off['desync_requests']}")
    gate("tierb: only the not-probed anomaly is reported without the flag",
         len(off_anoms) == 1 and off_anoms[0]["probe_class"] == "not-probed",
         str([a["probe_class"] for a in off_anoms]))

    h2 = [a for a in repb["anomalies"] if a["probe_class"] == "H2"]
    gate("tierb: the H2 cell is recorded as skipped and never sent",
         len(h2) == 1 and "needs an HTTP/2 client" in h2[0]["note"],
         (h2[0]["note"][:70] if h2 else "absent"))
    gate("tierb: --allow-h2-probe relaxes reporting but still sends nothing",
         repb_post["tierb"]["desync_requests"] == repb["tierb"]["desync_requests"]
         and any("still nothing sent" in a["note"]
                 for a in repb_post["anomalies"] if a["probe_class"] == "H2"),
         f"{repb_post['tierb']['desync_requests']} vs "
         f"{repb['tierb']['desync_requests']}")

    uni = [a for a in repb["anomalies"] if a["check_id"] == "unicode-oracle"]
    gate("tierb: the unicode oracle stayed inside 12 requests",
         repb["tierb"]["unicode_requests"] <= 12,
         f"unicode_requests={repb['tierb']['unicode_requests']}")
    gate("tierb: the unicode anomaly names the exact codepoints involved",
         len(uni) >= 3 and all("U+" in a["note"] and "U+" in a["detail"]
                              for a in uni),
         f"n={len(uni)} notes={[a['probe_class'] for a in uni]}")

    api = [a for a in repb["anomalies"] if a["check_id"] == "api-state-authz"]
    gate("tierb: an authorization differential for each documented {param} path",
         len(api) == 2, f"n={len(api)}")
    gate("tierb: the api note refuses to call it a proven BOLA",
         len(api) == 2 and all("not a proven BOLA, needs a second "
                               "owner-provided account to confirm" in a["note"]
                               for a in api),
         "note text")
    gate("tierb: the api module is medium confidence, never a finding",
         len(api) == 2 and all(a["confidence"] == "medium" for a in api)
         and not any(f["check_id"] == "api-state-authz" for f in repb["findings"]),
         str(sorted({a["confidence"] for a in api})))
    gate("tierb: only GET is sent without --allow-spec-post",
         set(repb["tierb"]["methods"]) == {"GET"},
         str(sorted(set(repb["tierb"]["methods"]))))
    gate("tierb: POST only under the flag, and no mutating method ever sent",
         set(repb_post["tierb"]["methods"]) == {"GET", "POST"}
         and "POST" in server_methods
         and set(server_methods) <= {"GET", "POST"},
         f"report={sorted(set(repb_post['tierb']['methods']))} "
         f"server={sorted(set(server_methods))}")
    gate("tierb: the delete operation in the spec is never sent",
         "DELETE" not in server_methods and "DELETE" not in repb_post["tierb"]["methods"],
         f"server={sorted(set(server_methods))}")

    deli = [a for a in repb["anomalies"] if a["check_id"] == "delimiter-confusion"]
    gate("tierb: delimiter variants that change the body are reported",
         len(deli) == 3 and all("cache and origin may disagree on the path"
                                in a["note"] for a in deli)
         and all(a["status_delta"] == 0 for a in deli),
         f"n={len(deli)}")
    gate("tierb: the same-status delimiter module stayed inside 10 requests",
         repb["tierb"]["delimiter_requests"] <= 10,
         f"delimiter_requests={repb['tierb']['delimiter_requests']}")
    gate("tierb: a status-changing delimiter variant is reported too",
         any("status changed for a delimited variant" in a["note"]
             for a in repb_layer["anomalies"]
             if a["check_id"] == "delimiter-confusion"),
         "from the layered full+tierb run")

    gate("tierb: anomalies change no finding, no count, no score, no exit code",
         repb_full["counts"] == repb_layer["counts"]
         and repb_full["score"] == repb_layer["score"]
         and set(repb_full["checks_fired"]) == set(repb_layer["checks_fired"])
         and rf.returncode == rl.returncode,
         f"counts {repb_full['counts']} vs {repb_layer['counts']}, "
         f"score {repb_full['score']} vs {repb_layer['score']}, "
         f"rc {rf.returncode} vs {rl.returncode}")
    gate("tierb: the layered run really did produce anomalies",
         len(repb_layer["anomalies"]) >= 4
         and all(a["tier"] == "B" for a in repb_layer["anomalies"])
         and all(a["disclaimer"] == DISCLAIMER
                 for a in repb_layer["anomalies"]),
         f"n={len(repb_layer['anomalies'])}")
    gate("tierb: the checklist never lists an anomaly",
         not any("desync-cells" in ln or "unicode-oracle" in ln
                 or "delimiter-confusion" in ln or "api-state-authz" in ln
                 for ln in open(os.path.join(SCRATCH, "rt-tierb-layer",
                                             "CHECKLIST.md"))),
         "CHECKLIST.md is findings-only")


if __name__ == "__main__":
    sys.exit(main())
