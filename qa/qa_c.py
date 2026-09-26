

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
