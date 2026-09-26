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
