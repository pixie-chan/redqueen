#!/usr/bin/env python3
"""Unit gate: passive source parsers with the network fully stubbed.
Proves wayback scope-filtering and CT dangling-subdomain logic without
touching the internet. Exit 0 = pass."""
import argparse
import importlib.util
import json
import os
import socket
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "rt", os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "redteam.py"))
rt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rt)

ns = argparse.Namespace(cookie=None, respect_robots=True, max_pages=5,
                        scenario="recon", wayback=True, ct_log=True, rps=5,
                        max_requests=50, timeout=5, insecure=False,
                        local=True, deep_traversal=False,
                        traversal_canary=None)
t = rt.Transport("http://demo.placeholder_website.test", ["demo.placeholder_website.test"],
                 5, 50, 5, False, False)
bot = rt.Bot(t, ns)

# wayback: in-scope queued, out-of-scope dropped
rows = [["original"],
        ["http://demo.placeholder_website.test/keep", "http://evil.example/drop"]]
t.request_external = lambda url, cap=0, timeout=0: (
    200, json.dumps(rows).encode())
bot._wayback()
assert "http://demo.placeholder_website.test/keep" in bot.urls, "in-scope url not queued"
assert "http://evil.example/drop" not in bot.urls, "out-of-scope url leaked"

# ct-log: wildcard stripped, unresolved name reported, resolved name quiet
crt = [{"name_value":
        "ghost.demo.placeholder_website.test\nwww.demo.placeholder_website.test\n*.demo.placeholder_website.test"}]
t.request_external = lambda url, cap=0, timeout=0: (
    200, json.dumps(crt).encode())


def fake_gai(host, port=None, **kw):
    if str(host).startswith("ghost"):
        raise socket.gaierror(-2, "Name or service not known")
    return [("127.0.0.1", 2, 3, "", ("127.0.0.1", 80))]


with mock.patch("socket.getaddrinfo", side_effect=fake_gai):
    bot._ct_log()
assert any(f["check_id"] == "subdomain-dangling" and "ghost" in f["url"]
           for f in bot.findings), "dangling subdomain not reported"
assert not any("www." in f["url"] for f in bot.findings
               if f["check_id"] == "subdomain-dangling"), \
    "resolving name falsely flagged"

# certspotter fallback path: crt.sh raises, certspotter answers
bot2 = rt.Bot(t, ns)
calls = []


def fail_crt_then_ok(url, cap=0, timeout=0):
    calls.append(url)
    if "crt.sh" in url:
        raise RuntimeError("HTTP 502")
    return 200, json.dumps(
        [{"dns_names": ["a.demo.placeholder_website.test", "evil.example"]}]).encode()


t.request_external = fail_crt_then_ok
with mock.patch("socket.getaddrinfo",
                side_effect=lambda *a, **k: (_ for _ in ()).throw(
                    socket.gaierror(-2, "NXDOMAIN"))):
    bot2._ct_log()
assert len(calls) == 2 and "certspotter" in calls[1], "fallback not used"
assert any("a.demo.placeholder_website.test" in f["url"] for f in bot2.findings), \
    "certspotter names not processed"
assert not any("evil.example" in f["url"] for f in bot2.findings), \
    "foreign domain leaked from certspotter"
print("UNIT_OK")
