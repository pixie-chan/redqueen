# redteam.py v1.1.0 · Architecture

How the bot works and how its codebase is put together. Six focused diagrams,
each with one claim. Rendered PNGs live in `diagrams/` (Mermaid source in each
`diagrams/*.mmd`).

## 1. Run flow · what happens when you execute one scan

Scope gate first, reports always ship, even on early stop.

```mermaid
flowchart TD
    A["CLI<br/>--target --allow --i-own-this<br/>--scenario --wayback --ct-log"] --> G{"scope gate<br/>host in allowlist?"}
    G -- "no" --> K["request never sent"]
    G -- "no --i-own-this" --> P["passive mode<br/>recon groups only"]
    G -- "yes" --> T["Transport<br/>5 req/s + jitter, budget 500,<br/>1 retry, redirect re-check"]
    T --> D["Discovery<br/>3 passes + optional passive sources"]
    D --> R["Scenario runners<br/>12 check groups, 63 checks"]
    R --> V["Verify pass<br/>CRITICAL/HIGH re-tested once"]
    V --> Z["Dedupe + score out of 100"]
    Z --> O["terminal + report.html<br/>+ report.json + CHECKLIST.md"]
    P --> O
    K --> O
```

## 2. Discovery engine · how it finds pages, APIs and secrets to probe

Three crawl passes, then optional passive sources; every input lands in the
same stores the checks read from.

```mermaid
flowchart LR
    S["seed<br/>target URL"] --> P1["pass 1: BFS crawl<br/>robots.txt, sitemap + gzip,<br/>forms, query params,<br/>same-origin JS urls"]
    P1 --> P2["pass 2: JS mining<br/>fetch bundles, extract<br/>/api routes + params"]
    P2 --> P3["pass 3:<br/>probe mined routes"]
    P1 --> WB{"--wayback?"}
    WB -- "on" --> W1["Wayback CDX<br/>scope filter"] --> P4["re-crawl<br/>historical urls"]
    P1 --> CT{"--ct-log?"}
    CT -- "on" --> C1["crt.sh to Cert Spotter<br/>DNS resolve"]
    C1 --> CF["dangling subdomain<br/>findings (report only)"]
    P3 --> ST["stores<br/>pages, params,<br/>forms, endpoints"]
    P4 --> ST
```

## 3. Codebase · 12 build slices assemble into one dependency-free file

```mermaid
flowchart TD
    A1["parts/p1 head + constants (70)"] --> A2["parts/p2a CHECKS registry (81)"]
    A2 --> A2b["parts/p2b registry + groups + scenarios (145)"]
    A2b --> A3["parts/p3 Transport: scope, throttle, retry (226)"]
    A3 --> A4["parts/p4 Bot engine: discovery, JS mining, wayback, ct-log (418)"]
    A4 --> A5["parts/p5 headers, CORS, cookies, JWT, host (229)"]
    A5 --> A6["parts/p6 TLS, exposures, GraphQL (175)"]
    A6 --> A7["parts/p7 injection, methods, stack traces (205)"]
    A7 --> A8["parts/p8 secrets, auth, CSRF, rate limit (193)"]
    A8 --> A9["parts/p9 terminal, JSON, checklist (108)"]
    A9 --> A10["parts/p10 HTML report (156)"]
    A10 --> A11["parts/p11 CLI + runners (149)"]
    A11 --> BS["build.sh: ordered cat + compile check"]
    BS --> RT["redteam.py: 2155 lines, stdlib only"]
    RT --> Q["qa/qa.py: 16 assertion gates"]
    H["qa/qx_harness.py (397): weak / strong / TLS target"] --> Q
    U["qa/unit_sources.py (78): network stubbed"] --> Q
    Q --> EX["examples/: sample reports + checklist"]
    RES["research/redteam-bot/: 150+ sources"] -. grounding .-> RT
```

## 4. Check engine · how one check becomes a verified finding

Registry drives everything: groups, severities, OWASP mapping and fixes.

```mermaid
flowchart TD
    R["CHECKS registry<br/>id to OWASP, severity, impact, exact fix<br/>63 entries"] --> G["GROUPS<br/>12 groups"]
    G --> SC["SCENARIOS<br/>recon, headers, misconfig,<br/>injection, auth, api, full"]
    SC --> RN["RUNNERS dispatch"]
    RN --> F1["check_* functions<br/>call bot.get()"]
    F1 --> AD["bot.add()<br/>dedupe key: check + path + param,<br/>secrets redacted"]
    AD --> VF{"verify pass<br/>CRITICAL or HIGH?"}
    VF -- "re-tested" --> OK["verified"]
    VF -- "not reproduced" --> DN["downgrade one level,<br/>confidence low"]
    VF -- "lower severity" --> F2["findings[]"]
    OK --> F2
    DN --> F2
    F2 --> SC2["score = 100 minus<br/>weighted severities"]
    F2 --> O["terminal, HTML,<br/>JSON, CHECKLIST.md"]
```

## 5. Safety rails · why the bot cannot wander off or hurt your site

Every request passes the gates in order; forbidden payload classes are not
implemented at all.

```mermaid
flowchart TD
    Q["outgoing request"] --> G1{"host matches<br/>--allow?"}
    G1 -- "no" --> K1["blocked: never sent"]
    G1 -- "yes" --> G2{"budget left?"}
    G2 -- "no" --> K2["BudgetExceeded:<br/>stop, report ships"]
    G2 -- "yes" --> G3["throttle<br/>5 req/s + jitter"]
    G3 --> G4{"robots disallow?<br/>(crawl phase)"}
    G4 -- "yes" --> K3["path skipped"]
    G4 -- "no" --> PL["payload policy"]
    PL --> OKA["ALLOWED<br/>canaries, echo markers,<br/>error signatures, benign GET/POST"]
    PL --> NOA["NOT IMPLEMENTED<br/>DoS, brute force, data writes,<br/>destructive SQL, shell exec"]
    OWN["--i-own-this required<br/>for active groups"] -. gates .-> G1
```

## 6. QA proof loop · how every change is proven before it ships

```mermaid
flowchart LR
    subgraph TG["qx_harness.py, local only"]
        W1["weak mode:<br/>54 findings planted"]
        S1["strong mode:<br/>hardened"]
        T1["weak + TLS:<br/>self-signed, 10 day cert"]
    end
    W1 --> RA["run: scenario full"]
    S1 --> RB["run: scenario full"]
    T1 --> RC["run: scenario headers"]
    PG["run: passive<br/>no --i-own-this"] --> RD
    UN["unit_sources.py<br/>network stubbed"] --> RE
    RA --> GT["qa.py<br/>16 assertion gates"]
    RB --> GT
    RC --> GT
    RD --> GT
    RE --> GT
    GT --> OKG["ALL PASS<br/>exit 0, samples refreshed"]
    GT -- "any miss" --> FL["QA_RC=1, release blocked"]
```
