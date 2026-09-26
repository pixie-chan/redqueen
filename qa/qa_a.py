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
