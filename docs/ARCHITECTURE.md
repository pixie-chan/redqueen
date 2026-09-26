# redteam.py v1.1.0 · Architecture

How the bot works and how its codebase is put together. Six focused diagrams,
each with one claim.

Color legend used everywhere: blue = engine, amber = gate or decision,
green = allowed / pass, red = blocked, orange = degraded path, violet =
artifact, sky blue = external source, dashed red = forbidden class.

Rendered PNGs live in `diagrams/` (Mermaid source in each `diagrams/*.mmd`,
re-render with `sh docs/render.sh`).

## 1. Run flow · what happens when you execute one scan

Scope gate first, reports always ship, even on early stop.

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontFamily":"DejaVu Sans, Helvetica, sans-serif","fontSize":"14px","lineColor":"#64748b","clusterBkg":"#f8fafc","clusterBorder":"#cbd5e1"}}}%%
flowchart TD
    T["SCAN PIPELINE · redteam.py v1.1.0<br/>blue engine · amber gate · red blocked<br/>orange degraded · violet output"]:::title ~~~ A(["CLI invocation<br/>target · allow · scenario · flags"]):::cli
    A --> G{"scope gate<br/>host in allowlist?"}:::gate
    G -->|no| K(["request never sent"]):::bad
    G -->|"in scope, no flag"| P["passive mode<br/>recon groups only"]:::neutral
    G -->|yes| T2["Transport<br/>5 req/s + jitter · budget 500<br/>1 retry · redirect re-check"]:::engine
    T2 --> D["Discovery<br/>3 passes + optional sources"]:::engine
    D --> R["Runners<br/>12 groups · 63 checks"]:::engine
    R --> V{"verify pass<br/>CRITICAL or HIGH?"}:::gate
    V -->|reproduced| Z["dedupe + score / 100"]:::engine
    V -->|"not reproduced"| DN["downgrade one level<br/>confidence low"]:::warn
    DN --> Z
    Z --> O[/"terminal · report.html<br/>report.json · CHECKLIST.md"/]:::out
    P --> O
    K -.->|"recorded as note"| O

    classDef title fill:#0f172a,stroke:#0f172a,color:#f8fafc
    classDef cli fill:#e0f2fe,stroke:#0284c7,color:#0f172a
    classDef engine fill:#e0e7ff,stroke:#4f46e5,color:#0f172a
    classDef gate fill:#fffbeb,stroke:#d97706,color:#0f172a
    classDef good fill:#dcfce7,stroke:#059669,color:#0f172a
    classDef bad fill:#ffe4e6,stroke:#e11d48,color:#0f172a
    classDef warn fill:#ffedd5,stroke:#ea580c,color:#0f172a
    classDef out fill:#ede9fe,stroke:#7c3aed,color:#0f172a
    classDef neutral fill:#f1f5f9,stroke:#64748b,color:#0f172a
    classDef ext fill:#cffafe,stroke:#0891b2,color:#0f172a
    classDef forbidden fill:#ffe4e6,stroke:#e11d48,color:#0f172a,stroke-dasharray:6 4
```

## 2. Discovery engine · how it finds pages, APIs and secrets to probe

Three crawl passes, then optional passive sources; every input lands in the
same stores the checks read from.

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontFamily":"DejaVu Sans, Helvetica, sans-serif","fontSize":"14px","lineColor":"#64748b","clusterBkg":"#f8fafc","clusterBorder":"#cbd5e1"}}}%%
flowchart LR
    T["DISCOVERY ENGINE<br/>blue process · teal external<br/>orange report-only"]:::title ~~~ S(["seed: target URL"]):::ext
    S --> P1["PASS 1 · BFS crawl<br/>robots · sitemap + gzip<br/>forms · params · JS URLs"]:::engine
    P1 --> P2["PASS 2 · JS mining<br/>fetch same-origin bundles<br/>extract /api routes + params"]:::engine
    P2 --> P3["PASS 3<br/>probe mined routes"]:::engine
    P3 --> ST[("stores<br/>pages · URLs<br/>params · forms · endpoints")]:::engine
    P1 -.->|"optional: Wayback"| W["Wayback CDX<br/>scope filter"]:::ext
    W --> P4["re-crawl<br/>historical URLs"]:::engine
    P4 --> ST
    P1 -.->|"optional: CT logs"| C["crt.sh then Cert Spotter<br/>+ DNS resolve"]:::ext
    C --> F(["dangling subdomain<br/>report only"]):::warn

    classDef title fill:#0f172a,stroke:#0f172a,color:#f8fafc
    classDef cli fill:#e0f2fe,stroke:#0284c7,color:#0f172a
    classDef engine fill:#e0e7ff,stroke:#4f46e5,color:#0f172a
    classDef gate fill:#fffbeb,stroke:#d97706,color:#0f172a
    classDef good fill:#dcfce7,stroke:#059669,color:#0f172a
    classDef bad fill:#ffe4e6,stroke:#e11d48,color:#0f172a
    classDef warn fill:#ffedd5,stroke:#ea580c,color:#0f172a
    classDef out fill:#ede9fe,stroke:#7c3aed,color:#0f172a
    classDef neutral fill:#f1f5f9,stroke:#64748b,color:#0f172a
    classDef ext fill:#cffafe,stroke:#0891b2,color:#0f172a
    classDef forbidden fill:#ffe4e6,stroke:#e11d48,color:#0f172a,stroke-dasharray:6 4
```

## 3. Codebase · 12 build slices assemble into one dependency-free file

| Layer | Files | Lines |
|---|---|---|
| Core | p1 head (70), p2a registry (81), p2b groups + scenarios (145) | 296 |
| Engine | p3 transport (226), p4 bot + discovery (418) | 644 |
| Checks | p5 headers/CORS/JWT (229), p6 TLS/exposures (175), p7 injection (205), p8 secrets/auth (193) | 802 |
| Output | p9 terminal/JSON/checklist (108), p10 HTML report (156) | 264 |
| CLI | p11 runners + parser (149) | 149 |
| **Assembled** | **redteam.py** | **2155** |

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontFamily":"DejaVu Sans, Helvetica, sans-serif","fontSize":"14px","lineColor":"#64748b","clusterBkg":"#f8fafc","clusterBorder":"#cbd5e1"}}}%%
flowchart TD
    T["CODEBASE · 12 slices into 1 file<br/>blue source · amber build/gate · violet artifact · grey QA inputs"]:::title ~~~ C1["CORE<br/>p1 head (70)<br/>p2a registry (81)<br/>p2b groups + scenarios (145)"]:::engine
    C1 --> C2["ENGINE<br/>p3 transport (226)<br/>p4 bot + discovery (418)"]:::engine
    C2 --> C3["CHECKS<br/>p5 headers/CORS/JWT (229)<br/>p6 TLS/exposures (175)<br/>p7 injection (205)<br/>p8 secrets/auth (193)"]:::engine
    C3 --> C4["OUTPUT<br/>p9 terminal/JSON/checklist (108)<br/>p10 HTML report (156)"]:::engine
    C4 --> C5["CLI<br/>p11 runners + parser (149)"]:::engine
    C5 --> BS["build.sh<br/>ordered cat + compile check"]:::gate
    BS -->|assemble| RT["redteam.py<br/>2155 lines · stdlib only"]:::out
    RT --> Q["qa/qa.py<br/>16 assertion gates"]:::gate
    subgraph QA_BOX["QA · proves the build"]
        H["qa/qx_harness.py (397)<br/>weak / strong / TLS target"]:::neutral --> Q
        U["qa/unit_sources.py (78)<br/>network stubbed"]:::neutral --> Q
    end
    Q --> EX[/"examples/<br/>sample reports + checklist"/]:::out
    RES[("research corpus<br/>150+ sources")]:::ext -.->|grounding| RT
    style QA_BOX fill:#f8fafc,stroke:#94a3b8,color:#0f172a,stroke-width:1.5px

    classDef title fill:#0f172a,stroke:#0f172a,color:#f8fafc
    classDef cli fill:#e0f2fe,stroke:#0284c7,color:#0f172a
    classDef engine fill:#e0e7ff,stroke:#4f46e5,color:#0f172a
    classDef gate fill:#fffbeb,stroke:#d97706,color:#0f172a
    classDef good fill:#dcfce7,stroke:#059669,color:#0f172a
    classDef bad fill:#ffe4e6,stroke:#e11d48,color:#0f172a
    classDef warn fill:#ffedd5,stroke:#ea580c,color:#0f172a
    classDef out fill:#ede9fe,stroke:#7c3aed,color:#0f172a
    classDef neutral fill:#f1f5f9,stroke:#64748b,color:#0f172a
    classDef ext fill:#cffafe,stroke:#0891b2,color:#0f172a
    classDef forbidden fill:#ffe4e6,stroke:#e11d48,color:#0f172a,stroke-dasharray:6 4
```

## 4. Check engine · how one check becomes a verified finding

Registry drives everything: groups, severities, OWASP mapping and fixes.

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontFamily":"DejaVu Sans, Helvetica, sans-serif","fontSize":"14px","lineColor":"#64748b","clusterBkg":"#f8fafc","clusterBorder":"#cbd5e1"}}}%%
flowchart TD
    T["CHECK ENGINE · registry to report<br/>blue process + data · amber decision<br/>green verified · orange downgrade"]:::title ~~~ R[("CHECKS registry<br/>63 entries: id · OWASP · severity · fix")]:::engine
    R --> G["GROUPS<br/>12 check groups"]:::engine
    G --> SC["SCENARIOS<br/>recon · headers · misconfig<br/>injection · auth · api · full"]:::engine
    SC --> RN["RUNNERS dispatch"]:::engine
    RN --> F1["check_* functions<br/>bot.get with throttle"]:::engine
    F1 --> AD["bot.add<br/>dedupe: check + path + param<br/>secrets redacted"]:::engine
    AD --> V{"severity is<br/>CRITICAL or HIGH?"}:::gate
    V -->|"lower severity"| F2[("findings list")]:::engine
    V -->|yes| VER{"re-test:<br/>reproduced?"}:::gate
    VER -->|yes| OK["verified"]:::good
    VER -->|no| DN["downgrade one level<br/>confidence low"]:::warn
    OK --> F2
    DN --> F2
    F2 -->|weighs| SC2["score = 100 minus findings<br/>critical 25 · high 12<br/>medium 5 · low 2"]:::out
    F2 -->|formats| O[/"terminal · report.html<br/>report.json · CHECKLIST.md"/]:::out

    classDef title fill:#0f172a,stroke:#0f172a,color:#f8fafc
    classDef cli fill:#e0f2fe,stroke:#0284c7,color:#0f172a
    classDef engine fill:#e0e7ff,stroke:#4f46e5,color:#0f172a
    classDef gate fill:#fffbeb,stroke:#d97706,color:#0f172a
    classDef good fill:#dcfce7,stroke:#059669,color:#0f172a
    classDef bad fill:#ffe4e6,stroke:#e11d48,color:#0f172a
    classDef warn fill:#ffedd5,stroke:#ea580c,color:#0f172a
    classDef out fill:#ede9fe,stroke:#7c3aed,color:#0f172a
    classDef neutral fill:#f1f5f9,stroke:#64748b,color:#0f172a
    classDef ext fill:#cffafe,stroke:#0891b2,color:#0f172a
    classDef forbidden fill:#ffe4e6,stroke:#e11d48,color:#0f172a,stroke-dasharray:6 4
```

## 5. Safety rails · why the bot cannot wander off or hurt your site

Every request passes the gates in order; forbidden payload classes are not
implemented at all.

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontFamily":"DejaVu Sans, Helvetica, sans-serif","fontSize":"14px","lineColor":"#64748b","clusterBkg":"#f8fafc","clusterBorder":"#cbd5e1"}}}%%
flowchart TD
    T["SAFETY RAILS · every request<br/>amber gate · red blocked · orange degraded · green allowed · dashed red forbidden"]:::title ~~~ Q(["outgoing request"]):::cli
    Q --> G1{"host matches allowlist?"}:::gate
    G1 -->|no| K1["blocked<br/>never sent"]:::bad
    G1 -->|yes| G2{"budget left?"}:::gate
    G2 -->|no| K2["budget exhausted<br/>stop · report still ships"]:::warn
    G2 -->|yes| G3["throttle<br/>5 req/s + jitter"]:::engine
    G3 --> G4{"robots disallow?<br/>crawl phase"}:::gate
    G4 -->|yes| K3["path skipped<br/>robots rule"]:::warn
    G4 -->|no| PL{"payload class<br/>benign?"}:::gate
    PL -->|benign| OKA["ALLOWED<br/>canaries · echo markers<br/>error signatures · benign GET/POST"]:::good
    PL -->|destructive| NOA["NOT IMPLEMENTED<br/>DoS · brute force · data writes<br/>destructive SQL · shell exec"]:::forbidden
    OWN["ownership flag required<br/>before active groups run"]:::ext -.-> G1

    classDef title fill:#0f172a,stroke:#0f172a,color:#f8fafc
    classDef cli fill:#e0f2fe,stroke:#0284c7,color:#0f172a
    classDef engine fill:#e0e7ff,stroke:#4f46e5,color:#0f172a
    classDef gate fill:#fffbeb,stroke:#d97706,color:#0f172a
    classDef good fill:#dcfce7,stroke:#059669,color:#0f172a
    classDef bad fill:#ffe4e6,stroke:#e11d48,color:#0f172a
    classDef warn fill:#ffedd5,stroke:#ea580c,color:#0f172a
    classDef out fill:#ede9fe,stroke:#7c3aed,color:#0f172a
    classDef neutral fill:#f1f5f9,stroke:#64748b,color:#0f172a
    classDef ext fill:#cffafe,stroke:#0891b2,color:#0f172a
    classDef forbidden fill:#ffe4e6,stroke:#e11d48,color:#0f172a,stroke-dasharray:6 4
```

## 6. QA proof loop · how every change is proven before it ships

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontFamily":"DejaVu Sans, Helvetica, sans-serif","fontSize":"14px","lineColor":"#64748b","clusterBkg":"#f8fafc","clusterBorder":"#cbd5e1"}}}%%
flowchart LR
    T["QA LOOP · release gate<br/>blue targets · grey stubs · amber gates<br/>green pass · red block"]:::title ~~~ H1["weak harness<br/>54 known findings"]:::engine
    subgraph T_BOX["targets under test"]
        S1["strong harness<br/>hardened"]:::engine
        T1["weak + TLS<br/>10-day self-signed"]:::engine
        PG["passive run<br/>ownership flag off"]:::neutral
        UN["unit_sources.py<br/>network stubbed"]:::neutral
    end
    H1 -->|"vulnerable target"| G{"qa.py<br/>16 assertion gates"}:::gate
    S1 -->|"hardened target"| G
    T1 -->|"TLS target"| G
    PG -->|"passive target"| G
    UN -->|"stubbed network"| G
    G -->|pass| P(["ALL PASS · exit 0<br/>samples refreshed"]):::good
    G -->|fail| X(["FAIL · QA_RC=1<br/>release blocked"]):::bad
    style T_BOX fill:#f8fafc,stroke:#94a3b8,color:#0f172a,stroke-width:1.5px

    classDef title fill:#0f172a,stroke:#0f172a,color:#f8fafc
    classDef cli fill:#e0f2fe,stroke:#0284c7,color:#0f172a
    classDef engine fill:#e0e7ff,stroke:#4f46e5,color:#0f172a
    classDef gate fill:#fffbeb,stroke:#d97706,color:#0f172a
    classDef good fill:#dcfce7,stroke:#059669,color:#0f172a
    classDef bad fill:#ffe4e6,stroke:#e11d48,color:#0f172a
    classDef warn fill:#ffedd5,stroke:#ea580c,color:#0f172a
    classDef out fill:#ede9fe,stroke:#7c3aed,color:#0f172a
    classDef neutral fill:#f1f5f9,stroke:#64748b,color:#0f172a
    classDef ext fill:#cffafe,stroke:#0891b2,color:#0f172a
    classDef forbidden fill:#ffe4e6,stroke:#e11d48,color:#0f172a,stroke-dasharray:6 4
```
