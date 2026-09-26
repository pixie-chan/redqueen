

# Tier C: human-in-the-loop research pipeline.
# This module never sends a request. It turns anomalies and hand-written
# candidates into dossiers a human can act on, and it enforces the rails
# mechanically: a candidate that needs a destructive action is marked
# OUT OF SCOPE and gets no repro template.

TIERC_MAX_REQUESTS = 8
TIERC_SAFE_METHODS = ("GET", "HEAD", "OPTIONS", "POST")
TIERC_DESTRUCTIVE = ("DELETE", "PUT", "PATCH")
TIERC_METADATA = "169.254.169.254"
TIERC_CANARY_RE = re.compile(r"QX[0-9a-f]{4,}")
TIERC_FLOOD_RE = re.compile(
    r"(?i)(flood|denial[\s-]of[\s-]service|\bdos\b|slowloris|amplif\w+|"
    r"concurren\w*|parallel requests|many requests at once|rapid reset|"
    r"keep[\s-]?alive (storm|abuse)|pummel|pound|threaded for)")

# a body value the scanner itself invented: canaries, the literal CANARY
# placeholder, inert counters, and the dummy login the rate-limit check uses
TIERC_OWNED_VALUE = re.compile(
    r"^(QX[0-9a-f]{2,}|CANARY|0|1|true|false|null|none|test|dummy|inert"
    r"|qx_[a-z0-9_@.]*|qx\.[a-z0-9_@.]+|definitelynotarealpass!1)$", re.I)


def tierc_mask(text):
    """Mask every secret pattern the auth module knows, then key=value
    secrets. Dossiers are written to disk and pasted into tickets, so a
    raw secret must never survive the trip."""
    out = str(text or "")
    for _name, rx, _sev in SECRET_RES:
        out = rx.sub(lambda m: mask_token(m.group(0)), out)
    out = SECRET_RE.sub(lambda m: m.group(1) + "=***REDACTED***", out)
    return out


def tierc_canary(text):
    """Swap the run-unique canary for a literal placeholder so the repro
    template is inert as written."""
    return TIERC_CANARY_RE.sub("CANARY", str(text or ""))


def tierc_safe_id(raw):
    cid = re.sub(r"[^A-Za-z0-9._-]+", "-", str(raw or "")).strip("-")
    return cid or "UNNAMED"


def _body_owned(body):
    """True when every value in the body is a scanner-owned inert value.
    A body the operator would have to fill with real data is not a repro
    template, it is a destructive action waiting to happen."""
    b = str(body or "").strip()
    if not b:
        return True, ""
    if b[0] in "{[":
        try:
            parsed = json.loads(b)
        except Exception:
            return False, "body looks like JSON but does not parse, ownership unverifiable"
        vals = []

        def walk(node):
            if isinstance(node, dict):
                for v in node.values():
                    walk(v)
            elif isinstance(node, (list, tuple)):
                for v in node:
                    walk(v)
            else:
                vals.append(str(node))

        walk(parsed)
    elif "=" in b:
        vals = [kv.split("=", 1)[1] for kv in b.split("&") if "=" in kv]
    else:
        vals = [b]
    for v in vals:
        if not TIERC_OWNED_VALUE.match(v.strip()):
            return False, f"body value {v[:40]!r} is not scanner-owned"
    return True, ""


def tierc_rails(candidate):
    """Read the candidate and decide whether documenting it is inside the
    rails. Returns (out_of_scope, [(rail, detail), ...])."""
    repro = candidate.get("repro") or []
    if not isinstance(repro, list):
        return True, [("malformed", "repro is not a list of requests")]
    hits = []

    if len(repro) > TIERC_MAX_REQUESTS:
        hits.append(("request-count",
                     f"{len(repro)} requests, cap is {TIERC_MAX_REQUESTS}"))

    for i, req in enumerate(repro, 1):
        if not isinstance(req, dict):
            hits.append(("malformed", f"repro[{i}] is not an object"))
            continue
        method = str(req.get("method") or "GET").strip().upper()
        url = str(req.get("url") or "")
        body = req.get("body")
        headers = req.get("headers") or {}
        if method not in TIERC_SAFE_METHODS:
            why = ("destructive method" if method in TIERC_DESTRUCTIVE
                   else "method outside the scanner allowlist")
            hits.append(("destructive-method",
                         f"request {i} uses {method} ({why})"))
        if TIERC_METADATA in url:
            hits.append(("cloud-metadata",
                         f"request {i} targets the cloud metadata service"))
        haystack = " ".join([url, str(body or "")] +
                            [f"{k}: {v}" for k, v in (headers.items()
                                                       if isinstance(headers, dict)
                                                       else [])] +
                            [str(req.get(k) or "")
                             for k in ("notes", "intent", "description")] +
                            [str(candidate.get("notes") or "")])
        fm = TIERC_FLOOD_RE.search(haystack)
        if fm:
            hits.append(("flood-or-concurrency",
                         f"request {i} hints at load or concurrency ({fm.group(0)})"))
        ok, why = _body_owned(body)
        if not ok:
            hits.append(("non-scanner-owned-body",
                         f"request {i}: {why}"))

    return bool(hits), hits


def _evidence_rows(candidate):
    """Every anomaly record or raw excerpt that supports the hypothesis,
    with secrets masked. Returns a list of (source, excerpt) pairs."""
    rows = []
    anom = candidate.get("anomaly")
    if isinstance(anom, dict):
        src = anom.get("route") or candidate.get("url") or "anomaly record"
        for k in ("probe_class", "distance", "status_delta", "headers_added",
                  "headers_removed", "canary_reflected", "note"):
            if k in anom:
                rows.append((f"{src} :: {k}", anom[k]))
        if not rows:
            rows.append((src, json.dumps(anom, sort_keys=True)))
    for ev in candidate.get("evidence") or []:
        if isinstance(ev, dict):
            rows.append((str(ev.get("source") or "excerpt"),
                         ev.get("excerpt", "")))
        else:
            rows.append(("excerpt", ev))
    if not rows:
        for i, req in enumerate(candidate.get("repro") or [], 1):
            if isinstance(req, dict):
                rows.append((f"request {i}",
                             f"{str(req.get('method') or 'GET').upper()} "
                             f"{req.get('url', '')}"))
    return [(tierc_canary(tierc_mask(s)), tierc_canary(tierc_mask(str(x))))
            for s, x in rows]


def _repro_block(candidate):
    """The exact request shape that produced the anomaly, canary swapped for
    the literal placeholder CANARY. Documentation only, never sent."""
    lines = ["## 4. Minimal repro template", "",
             "Run this ONLY on your own staging environment, never against "
             "production and never against a system you do not own.", ""]
    for i, req in enumerate(candidate.get("repro") or [], 1):
        if not isinstance(req, dict):
            continue
        method = str(req.get("method") or "GET").strip().upper()
        url = str(req.get("url") or "")
        lines.append(f"### request {i}: {method}")
        lines.append("")
        lines.append("```http")
        lines.append(f"{method} {tierc_canary(url)} HTTP/1.1")
        host = urllib.parse.urlsplit(url).netloc or "placeholder_website"
        lines.append(f"Host: {host}")
        lines.append("User-Agent: <your own agent string>")
        headers = req.get("headers") or {}
        if isinstance(headers, dict):
            for k, v in headers.items():
                lines.append(f"{k}: {tierc_canary(tierc_mask(v))}")
        body = req.get("body")
        if body:
            lines.append("")
            lines.append(tierc_canary(tierc_mask(body)))
        lines.append("```")
        lines.append("")
    lines.append("CANARY is a literal placeholder. Substitute your own unique "
                 "marker so a response reflection is unambiguous.")
    lines.append("")
    return lines


def tierc_dossier(bot, candidate):
    """Write research/CANDIDATE-<id>.md and return the path written."""
    out_dir = getattr(bot.args, "tierc_dir", None) or "research"
    os.makedirs(out_dir, exist_ok=True)
    cid = tierc_safe_id(candidate.get("id"))
    path = os.path.join(out_dir, f"CANDIDATE-{cid}.md")

    title = str(candidate.get("title") or cid)
    tier = str(candidate.get("tier") or "").strip().upper()
    if candidate.get("source") == "anomaly":
        source = f"Tier {tier or 'A'} anomaly"
        anom = candidate.get("anomaly") or {}
        if anom.get("route"):
            source += f" on route {anom['route']}"
    else:
        source = "hand-written candidate file"

    out_of_scope, hits = tierc_rails(candidate)
    verdict = "OUT OF SCOPE" if out_of_scope else "IN SCOPE"
    now = datetime.now(timezone.utc)
    target = ""
    try:
        target = bot.t.base + bot.t.path
    except Exception:
        target = ""

    L = []
    # 1. header
    L += [f"# CANDIDATE {cid}: {title}", "",
          f"> **{verdict}**" if out_of_scope else
          f"> rails verdict: {verdict}", "",
          "| field | value |", "|---|---|",
          f"| candidate id | `{cid}` |",
          f"| title | {tierc_mask(title)} |",
          f"| date | {now.strftime('%Y-%m-%d')} ({now.strftime('%H:%M:%SZ')}) |",
          f"| source | {source} |",
          f"| rails verdict | {verdict} |",
          f"| out of scope | {'yes' if out_of_scope else 'no'} |",
          f"| requests executed by redteam.py for this dossier | 0 |"]
    if target:
        L.append(f"| scan target | {target} |")
    L.append("")

    # 2. hypothesis
    hyp = str(candidate.get("hypothesis") or "").strip()
    if not hyp:
        hyp = ("No hypothesis recorded yet. Write one sentence naming the "
               "mechanism you believe is present and the observation that "
               "made you believe it.")
    L += ["## 2. Hypothesis", "", tierc_mask(tierc_canary(hyp)), "",
          "This is a hypothesis, not a proven impact. Nothing in this dossier "
          "has been exploited or confirmed on production.", ""]

    # 3. evidence
    L += ["## 3. Evidence", "",
          "Raw values are masked with the same routine the scanner uses for "
          "findings. A value that looks like a secret here is redacted, not "
          "collected.", "",
          "| # | source | excerpt |", "|---|---|---|"]
    rows = _evidence_rows(candidate)
    for i, (src, excerpt) in enumerate(rows, 1):
        L.append(f"| {i} | {src} | `{str(excerpt)[:300]}` |")
    if not rows:
        L.append("| 1 | none | no evidence captured yet |")
    L.append("")

    # 4. minimal repro: written only when the rails allow it. When they do
    # not, the section is absent entirely, not present and empty.
    if not out_of_scope:
        L += _repro_block(candidate)

    # 5. impact scaffold
    L += ["## 5. Impact statement scaffold", "",
          "Fill this in only with what you have actually demonstrated. If a "
          "line stays empty, the impact is unproven, and an unproven impact "
          "is the fastest way to lose a report.", "",
          "1. **What an attacker gains** (one sentence, naming the concrete "
          "capability gained, not the weakness class): "
          "_________________________________________________",
          "2. **What data is reachable** (name the exact data or none, never "
          "`sensitive data`): "
          "_________________________________________________",
          "3. **Blast radius** (how many systems, tenants or accounts, and "
          "what it takes to get there): "
          "_________________________________________________", "",
          "Keep the hypothesis above and the impact below separate. Vendors "
          "routinely reject reports that blur the two, and a rejected report "
          "teaches you nothing about whether you were right.", ""]

    # 6. rails verdict
    L += ["## 6. Rails verdict", ""]
    if out_of_scope:
        L += ["**OUT OF SCOPE.** redteam.py will not document, render or "
              "execute a repro for this candidate, so section 4 above is "
              "absent by design. The rails it violates:", ""]
        for rail, why in hits:
            L.append(f"- **{rail}**: {tierc_mask(why)}")
        L += ["",
              "If you still need this investigated, it has to be done by a "
              "human with written authorisation, on a system you own, with a "
              "change ticket. That process is deliberately outside this tool.",
              ""]
    else:
        L += ["**IN SCOPE.** The candidate is a read-only observation: no "
              "destructive method, no cloud metadata address, no flood or "
              "concurrency hint, no body the scanner does not own, and at "
              f"most {TIERC_MAX_REQUESTS} requests. It is documented, not "
              "executed.", ""]

    # 7. next steps
    L += ["## 7. Next steps", "",
          "1. **Verify on staging.** Reproduce it on your own staging copy "
          "first. If it does not reproduce there, stop here: it was noise.",
          "2. **Check whether a CWE already covers it.** Look it up at "
          "`https://cwe.mitre.org/data/definitions/<id>.html`. Before you "
          "invent a class, remember the rule: **name the mechanism rather "
          "than inventing a class**. HTTP request smuggling has been CWE-444 "
          "since 2008; a new mechanism deserves a new entry, a known "
          "mechanism in a new place does not.",
          "3. **If no entry exists, submit one.** Start at "
          "`https://cwesubmission.mitre.org/` and follow the process in "
          "`https://cwe.mitre.org/community/submissions/overview.html`.",
          "4. **Multi-vendor impact goes to CERT/CC.** Report per "
          "`https://kb.cert.org/vuls/report/` and coordinate via "
          "`https://certcc.github.io/CERT-Guide-to-CVD/tutorials/coord_certcc/`. "
          "Expect pushback: serious multi-vendor findings are routinely "
          "dismissed as features, and reporters sometimes conclude after the "
          "fact that they mis-scoped the impact. That is a reason to scope "
          "honestly up front, not a reason to inflate.",
          "5. **Category CWEs are not for mapping.** Entries in Category 1000 "
          "are view-only, Usage: PROHIBITED for mapping, see "
          "`https://cwe.mitre.org/data/definitions/1035.html`. Never cite a "
          "Category entry as the weakness class of a finding.", ""]

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    return path


def _anomaly_candidate(idx, anom):
    """Turn one Tier A or Tier B anomaly record into a candidate."""
    return {"id": f"ANOM-{idx}",
            "title": f"{anom.get('probe_class', 'anomaly')} on "
                     f"{anom.get('route', 'unknown route')}",
            "hypothesis": ("A response to a benign differential probe differs "
                           "from the baseline in a way that suggests the "
                           "origin trusts an unvalidated input. State the "
                           "mechanism you believe is responsible, then verify "
                           "it on staging before writing any impact claim."),
            "source": "anomaly",
            "tier": anom.get("tier", "A"),
            "anomaly": anom,
            "repro": anom.get("repro") or []}


def load_tierc_candidates(path, cap=50):
    """Read a hand-written candidate file. It is parsed and rendered only:
    nothing in it is ever sent."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise SystemExit(f"--tierc-candidates file not found: {path}")
    except json.JSONDecodeError as e:
        raise SystemExit(f"--tierc-candidates file is not valid JSON: {e}")
    if not isinstance(data, list):
        raise SystemExit("--tierc-candidates must be a JSON list of candidate "
                         "objects")
    if len(data) > cap:
        raise SystemExit(f"--tierc-candidates holds {len(data)} candidates, "
                         f"cap is {cap}")
    out = []
    for i, c in enumerate(data, 1):
        if not isinstance(c, dict):
            raise SystemExit(f"--tierc-candidates entry {i} is not an object")
        repro = c.get("repro") or []
        if not isinstance(repro, list):
            raise SystemExit(f"--tierc-candidates entry {i} has a non-list repro")
        for j, req in enumerate(repro, 1):
            if not isinstance(req, dict):
                raise SystemExit(f"--tierc-candidates entry {i} repro[{j}] "
                                 "is not an object")
        out.append({**c, "source": "candidate-file"})
    return out


def run_tierc(bot):
    """Scenario tierc. Sends nothing: the transport is frozen before any
    candidate is read, so a bug here still cannot produce traffic."""
    bot.t.frozen = True
    bot.tierc = []
    cfile = getattr(bot.args, "tierc_candidates", None)
    if cfile:
        cands = load_tierc_candidates(cfile)
    else:
        cands = [_anomaly_candidate(i, a)
                 for i, a in enumerate(bot.anomalies or [], 1)]
    out_of_scope = 0
    for cand in cands:
        path = tierc_dossier(bot, cand)
        oos, hits = tierc_rails(cand)
        out_of_scope += 1 if oos else 0
        bot.tierc.append({"id": tierc_safe_id(cand.get("id")),
                          "title": str(cand.get("title") or ""),
                          "path": path,
                          "rails": "; ".join(f"{r}: {w}" for r, w in hits)
                                   or "no rail violated",
                          "out_of_scope": oos})
    # Report the transport count honestly: Tier C's own phase sends nothing,
    # but an anomaly-sourced run may have discovered first, and a scan that
    # says "0 requests" when it sent some is worse than useless.
    bot.note(f"tier C: {len(bot.tierc)} dossier(s) written, {out_of_scope} "
             f"out of scope, {bot.t.used} request(s) sent by the whole run "
             f"(the dossier phase itself sends none)")
