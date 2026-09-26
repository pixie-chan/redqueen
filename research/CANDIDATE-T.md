# CANDIDATE T: t

> rails verdict: IN SCOPE

| field | value |
|---|---|
| candidate id | `T` |
| title | t |
| date | 2026-09-26 (13:02:59Z) |
| source | hand-written candidate file |
| rails verdict | IN SCOPE |
| out of scope | no |
| requests executed by redteam.py for this dossier | 0 |
| scan target | http://x/ |

## 2. Hypothesis

h

This is a hypothesis, not a proven impact. Nothing in this dossier has been exploited or confirmed on production.

## 3. Evidence

Raw values are masked with the same routine the scanner uses for findings. A value that looks like a secret here is redacted, not collected.

| # | source | excerpt |
|---|---|---|
| 1 | /c.js | `api_key=***REDACTED***` |

## 4. Minimal repro template

Run this ONLY on your own staging environment, never against production and never against a system you do not own.

CANARY is a literal placeholder. Substitute your own unique marker so a response reflection is unambiguous.

## 5. Impact statement scaffold

Fill this in only with what you have actually demonstrated. If a line stays empty, the impact is unproven, and an unproven impact is the fastest way to lose a report.

1. **What an attacker gains** (one sentence, naming the concrete capability gained, not the weakness class): _________________________________________________
2. **What data is reachable** (name the exact data or none, never `sensitive data`): _________________________________________________
3. **Blast radius** (how many systems, tenants or accounts, and what it takes to get there): _________________________________________________

Keep the hypothesis above and the impact below separate. Vendors routinely reject reports that blur the two, and a rejected report teaches you nothing about whether you were right.

## 6. Rails verdict

**IN SCOPE.** The candidate is a read-only observation: no destructive method, no cloud metadata address, no flood or concurrency hint, no body the scanner does not own, and at most 8 requests. It is documented, not executed.

## 7. Next steps

1. **Verify on staging.** Reproduce it on your own staging copy first. If it does not reproduce there, stop here: it was noise.
2. **Check whether a CWE already covers it.** Look it up at `https://cwe.mitre.org/data/definitions/<id>.html`. Before you invent a class, remember the rule: **name the mechanism rather than inventing a class**. HTTP request smuggling has been CWE-444 since 2008; a new mechanism deserves a new entry, a known mechanism in a new place does not.
3. **If no entry exists, submit one.** Start at `https://cwesubmission.mitre.org/` and follow the process in `https://cwe.mitre.org/community/submissions/overview.html`.
4. **Multi-vendor impact goes to CERT/CC.** Report per `https://kb.cert.org/vuls/report/` and coordinate via `https://certcc.github.io/CERT-Guide-to-CVD/tutorials/coord_certcc/`. Expect pushback: serious multi-vendor findings are routinely dismissed as features, and reporters sometimes conclude after the fact that they mis-scoped the impact. That is a reason to scope honestly up front, not a reason to inflate.
5. **Category CWEs are not for mapping.** Entries in Category 1000 are view-only, Usage: PROHIBITED for mapping, see `https://cwe.mitre.org/data/definitions/1035.html`. Never cite a Category entry as the weakness class of a finding.

