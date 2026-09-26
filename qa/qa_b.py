

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
