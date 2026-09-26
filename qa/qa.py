#!/usr/bin/env python3
"""qa.py: end-to-end proof for redteam.py against qx_harness.
Runs weak-http, strong-http, passive and https-tls scenarios, then asserts
the exact expected check coverage. Exit 0 = all gates pass.
"""
import json
import os
import signal
import subprocess
import sys
import time

ROOT = "/home/zen/projects/redteam-bot"
QA = os.path.join(ROOT, "qa")
SCRATCH = "/home/zen/.hermes/cache/scratch"
BOT = os.path.join(ROOT, "redteam.py")
HARNESS = os.path.join(QA, "qx_harness.py")
PORT = 8931
TLS_PORT = 8932

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

    print()
    if failures:
        print(f"QA FAILED: {failures}")
        return 1
    print("ALL QA GATES PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
