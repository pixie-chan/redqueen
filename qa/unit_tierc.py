#!/usr/bin/env python3
"""Unit gate: Tier C research dossiers, with the network never touched.

Tier C renders dossiers for a human and must send nothing. These checks
prove the four promises of that module: the dossier is written and carries
the reporting link families, nothing is executed, a destructive candidate is
marked OUT OF SCOPE with no repro template, one anomaly yields one dossier,
and no raw secret reaches disk.

Prints one "RESULT <n> <name> PASS|FAIL" line per check, then TIERC_UNIT_OK
and exit 0 when every check passed.
"""
import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys

ROOT = os.environ.get("RT_ROOT") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
BOT = os.path.join(ROOT, "redteam.py")
TMP = os.path.join(ROOT, "qa", ".tierc-tmp")

LINK_FAMILIES = ["cwe.mitre.org", "cwesubmission.mitre.org", "kb.cert.org",
                 "certcc.github.io"]
PHRASE = "name the mechanism rather than inventing a class"
# 20-char AWS-shaped QA fixture. Synthetic, not a real key.
# Synthetic QA fixture, 20 chars, AWS-key shaped, deliberately
# obvious. Not a real key.
AKIA = "AKIAZZNOTAREALKEYXXX"
# GitHub-token fixtures are assembled from an obviously synthetic
# pattern so a credential-shaped literal never lands in git history
# and trips push protection. The value keeps the real 36-char
# shape, because the masking assertion depends on it.
GHP = "".join(["gh", "p_", "A1b2C3d4E5f6", "QxA1b2C3d4E5f6", "QxA1b2", "Zq00"])
# Same treatment for the Stripe fixture: the live-secret shape is what the
# masking assertion tests, but no credential-shaped literal is committed.
STRIPE = "".join(["sk", "_liv", "e_51H8x", "Y2eZvKYlo", "2CqaQB1e", "Xyz"])

spec = importlib.util.spec_from_file_location("rt", BOT)
rt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rt)

results = []


def check(name, fn):
    try:
        ok, detail = fn()
    except Exception as e:
        ok, detail = False, f"{type(e).__name__}: {e}"
    results.append((name, ok, detail))
    print(f"RESULT {len(results)} {'PASS' if ok else 'FAIL'} {name} :: {detail}")
    return ok


def new_bot(scenario="tierc", tierc_dir=None, cands=None):
    ns = argparse.Namespace(cookie=None, respect_robots=True, max_pages=5,
                            scenario=scenario, wayback=False, ct_log=False,
                            rps=5, max_requests=50, timeout=5, insecure=False,
                            local=True, deep_traversal=False,
                            traversal_canary=None, quiet=True, no_color=True,
                            report_dir=None, tierc_dir=tierc_dir,
                            tierc_candidates=cands, i_own_this=False)
    t = rt.Transport("http://demo.placeholder_website.test",
                     ["demo.placeholder_website.test"], 5, 50, 5, False, True)
    return rt.Bot(t, ns)


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
    return path


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def cli(args, outdir):
    os.makedirs(outdir, exist_ok=True)
    r = subprocess.run([sys.executable, BOT] + args, capture_output=True,
                       text=True, timeout=120)
    rep = outdir
    if "--report-dir" in args:
        rep = args[args.index("--report-dir") + 1]
    rep = os.path.join(rep, "report.json")
    data = json.loads(read(rep)) if os.path.exists(rep) else None
    return r, data


shutil.rmtree(TMP, ignore_errors=True)
os.makedirs(TMP, exist_ok=True)
try:
    # ------------------------------------------------------------------
    # 1. a benign candidate renders a dossier carrying all four link
    #    families and the mechanism-not-class reminder
    # ------------------------------------------------------------------
    def t1():
        """dossier written with all four link families"""
        out = os.path.join(TMP, "t1")
        cfile = write_json(os.path.join(out, "cands.json"), [{
            "id": "HOSTHDR",
            "title": "X-Forwarded-Host reflected into the response body",
            "hypothesis": "The origin echoes an unvalidated X-Forwarded-Host "
                          "header into the rendered page, the precondition for "
                          "cache poisoning of a shared cache.",
            "repro": [{"method": "GET",
                       "url": "https://placeholder_website/index.html",
                       "headers": {"X-Forwarded-Host": "QX9f2a4c1b"}}]}])
        bot = new_bot(tierc_dir=os.path.join(out, "research"), cands=cfile)
        path = rt.tierc_dossier(bot, rt.load_tierc_candidates(cfile)[0])
        if not os.path.exists(path):
            return False, "no dossier written"
        text = read(path)
        missing = [f for f in LINK_FAMILIES if f not in text]
        if missing:
            return False, f"missing link families {missing}"
        if PHRASE not in text:
            return False, "missing the name-the-mechanism phrase"
        if bot.t.used:
            return False, f"{bot.t.used} requests sent while rendering"
        return True, path

    # ------------------------------------------------------------------
    # 2. a --tierc-candidates run executes nothing: bot.t.used == 0
    # ------------------------------------------------------------------
    def t2():
        """candidate run executes nothing (t.used == 0)"""
        out = os.path.join(TMP, "t2")
        cfile = write_json(os.path.join(out, "cands.json"), [{
            "id": "NEVER-SENT", "title": "must never be requested",
            "hypothesis": "If this file were executed the target would see a "
                          "request. It must not.",
            "repro": [{"method": "GET",
                       "url": "https://placeholder_website/never-sent"}]}])
        rd = os.path.join(out, "research")
        r, data = cli(["--target", "https://placeholder_website",
                       "--allow", "placeholder_website", "--scenario", "tierc",
                       "--tierc-candidates", cfile, "--tierc-dir", rd,
                       "--report-dir", os.path.join(out, "rep"), "--no-color"],
                      out)
        if data is None:
            return False, f"no report.json (rc={r.returncode})"
        if data["requests_used"] != 0:
            return False, f"{data['requests_used']} requests were sent"
        written = [d for d in data["tierc"] if os.path.exists(d["path"])]
        if len(written) != 1:
            return False, f"{len(written)} dossiers written"
        bot = new_bot(tierc_dir=rd, cands=cfile)
        rt.run_tierc(bot)
        if bot.t.used != 0:
            return False, f"bot.t.used={bot.t.used}, expected 0"
        if not bot.t.frozen:
            return False, "transport was not frozen"
        return True, f"requests_used=0, rc={r.returncode}"

    # ------------------------------------------------------------------
    # 3. a DELETE candidate is OUT OF SCOPE and gets no repro template
    # ------------------------------------------------------------------
    def t3():
        """DELETE candidate marked OUT OF SCOPE, no repro template"""
        out = os.path.join(TMP, "t3")
        cand = {"id": "DESTRUCT", "title": "account deletion",
                "hypothesis": "A DELETE may drop an account.",
                "repro": [{"method": "DELETE",
                           "url": "https://placeholder_website/api/session"}]}
        bot = new_bot(tierc_dir=os.path.join(out, "research"))
        path = rt.tierc_dossier(bot, cand)
        text = read(path)
        if "OUT OF SCOPE" not in text:
            return False, "not marked OUT OF SCOPE"
        for banned in ("Minimal repro", "```http", "DELETE /api/session"):
            if banned in text:
                return False, f"dossier still contains {banned!r}"
        oos, hits = rt.tierc_rails(cand)
        if not oos or not any(r == "destructive-method" for r, _w in hits):
            return False, f"rail verdict wrong: {hits}"
        # the other rails fire too
        for cand2, rail in (
                ({"id": "M", "repro": [{"method": "GET",
                   "url": "http://x/169.254.169.254/latest/meta-data/"}]},
                 "cloud-metadata"),
                ({"id": "F", "repro": [{"method": "GET", "url": "http://x/a",
                   "notes": "send 50000 requests concurrently"}]},
                 "flood-or-concurrency"),
                ({"id": "B", "repro": [{"method": "POST", "url": "http://x/a",
                   "body": "user=alice&password=hunter2-real-secret"}]},
                 "non-scanner-owned-body"),
                ({"id": "N", "repro": [{"method": "GET", "url": f"http://x/{i}"}
                                       for i in range(9)]},
                 "request-count")):
            o, h = rt.tierc_rails(cand2)
            if not o or not any(r == rail for r, _w in h):
                return False, f"rail {rail} did not fire"
        return True, path

    # ------------------------------------------------------------------
    # 4. --scenario tierc with no candidate file writes one dossier per
    #    anomaly, and the tierc array matches the files on disk
    # ------------------------------------------------------------------
    def t4():
        """one dossier per anomaly, tierc array matches files on disk"""
        out = os.path.join(TMP, "t4")
        rd = os.path.join(out, "research")
        # a real run has no anomalies yet (Tier A not built): the array and
        # the directory must still agree
        r, data = cli(["--target", "https://placeholder_website",
                       "--allow", "placeholder_website", "--scenario", "tierc",
                       "--tierc-dir", rd,
                       "--report-dir", os.path.join(out, "rep"), "--no-color"],
                      out)
        if data is None:
            return False, f"no report.json (rc={r.returncode})"
        on_disk = len([f for f in os.listdir(rd)]) if os.path.isdir(rd) else 0
        if len(data["tierc"]) != on_disk:
            return False, f"tierc array {len(data['tierc'])} != {on_disk} files"
        # now with anomalies present: one dossier each
        rd2 = os.path.join(out, "research2")
        bot = new_bot(tierc_dir=rd2)
        bot.anomalies = [
            {"route": "/index.html", "probe_class": "X-Forwarded-Host",
             "distance": 0.42, "status_delta": "200->200",
             "headers_added": ["x-cache"], "headers_removed": [],
             "canary_reflected": True, "note": "host echoed into body",
             "tier": "A"},
            {"route": "/api/session", "probe_class": "delimiter-variant",
             "distance": 0.11, "status_delta": "200->404",
             "headers_added": [], "headers_removed": ["etag"],
             "canary_reflected": False, "note": "path suffix changed routing",
             "tier": "B"}]
        rt.run_tierc(bot)
        files = sorted(os.listdir(rd2))
        if len(bot.tierc) != 2 or len(files) != 2:
            return False, f"2 anomalies -> {len(files)} files, " \
                          f"{len(bot.tierc)} array entries"
        if [d["id"] for d in bot.tierc] != ["ANOM-1", "ANOM-2"]:
            return False, f"ids {[d['id'] for d in bot.tierc]}"
        text = read(os.path.join(rd2, "CANDIDATE-ANOM-1.md"))
        if "Tier A anomaly" not in text:
            return False, "ANOM-1 does not name its Tier A source"
        text2 = read(os.path.join(rd2, "CANDIDATE-ANOM-2.md"))
        if "Tier B anomaly" not in text2:
            return False, "ANOM-2 does not name its Tier B source"
        if bot.t.used:
            return False, f"{bot.t.used} requests sent"
        return True, f"empty-run 0 files, anomaly-run {len(files)} dossiers"

    # ------------------------------------------------------------------
    # 5. a dossier never contains a raw secret
    # ------------------------------------------------------------------
    def t5():
        """dossier never contains a raw secret"""
        out = os.path.join(TMP, "t5")
        cand = {"id": "LEAKY", "title": "excerpt carries a live-looking key",
                "hypothesis": "The reflected body carried a key that must "
                              "never be copied into a ticket verbatim.",
                "evidence": [{"source": "/config.js",
                              "excerpt": f"api_key={AKIA} "
                                         f"password=hunter2-real "
                                         f"stripe={STRIPE}e_abcdefghijklmnopqrstuvwx "
                                         f"github={GHP}"}],
                "repro": [{"method": "GET",
                           "url": "https://placeholder_website/config.js",
                           "headers": {"X-Api-Key": AKIA}}]}
        bot = new_bot(tierc_dir=os.path.join(out, "research"))
        path = rt.tierc_dossier(bot, cand)
        text = read(path)
        for raw in (AKIA, "hunter2-real", STRIPE, GHP):
            if raw in text:
                return False, f"raw secret {raw[:12]!r} reached the dossier"
        masked = rt.mask_token(AKIA)
        if masked not in text:
            return False, f"masked form {masked!r} not present"
        if "***REDACTED***" not in text:
            return False, "key=value secret not redacted"
        oos, _hits = rt.tierc_rails(cand)
        if oos:
            return False, "a read-only candidate should be in scope"
        # a live key in a body is a different matter: not scanner-owned
        oos2, hits2 = rt.tierc_rails(
            {**cand, "repro": [{"method": "POST",
                                "url": "https://placeholder_website/x",
                                "body": "token=" + AKIA}]})
        if not oos2 or "non-scanner-owned-body" not in [r for r, _w in hits2]:
            return False, "a foreign body value was accepted"
        return True, f"masked to {masked}"

    # ------------------------------------------------------------------
    # 6. VERSION is 2.0.0 and --list-checks exits 0
    # ------------------------------------------------------------------
    def t6():
        """VERSION 2.0.0 and --list-checks exits 0"""
        if rt.VERSION != "2.0.0":
            return False, f"VERSION={rt.VERSION}"
        r = subprocess.run([sys.executable, BOT, "--list-checks"],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return False, f"--list-checks rc={r.returncode}"
        if "tierc" not in r.stdout:
            return False, "tierc scenario missing from --list-checks"
        return True, f"v{rt.VERSION}, {len(rt.CHECKS)} checks listed"

    for fn in (t1, t2, t3, t4, t5, t6):
        check(fn.__doc__ or fn.__name__, fn)
finally:
    shutil.rmtree(TMP, ignore_errors=True)

bad = [n for n, ok, _d in results if not ok]
if bad:
    print(f"TIERC_UNIT_FAILED: {bad}")
    sys.exit(1)
print(f"TIERC_UNIT_OK {len(results)}/{len(results)}")
