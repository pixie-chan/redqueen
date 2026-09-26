# Changelog

All notable changes to redteam.py are recorded here.
Format follows Keep a Changelog. Versions are the `VERSION` in
`parts/p1_head.py`.

## [2.0.0] - 2026-09-26

v2.0 is specified in `docs/V3-SPEC.md` as R2 plus Tiers A, B and C, built
through four harness prompts and then integrated into one tree. **All four
have landed**: R2 (robustness), Tier A (anomaly engine), Tier B (empty-taxonomy
surface hunting) and Tier C (research pipeline). The work arrived in separate
worktrees and was merged here, so this release also carries the integration
fixes that merge required.

### Added (shipped in this build)

- **Tier C research pipeline** (`parts/p9c_tierc.py`, new build slice between
  p9 and p10):
  - `tierc_dossier(bot, candidate)` writes `research/CANDIDATE-<id>.md` with
    seven parts: header carrying the rails verdict, hypothesis, evidence table
    with every secret passed through `mask_token()`, minimal repro template
    with the run canary replaced by the literal `CANARY`, impact-statement
    scaffold with three fill-in prompts, rails verdict, and a next-steps
    checklist.
  - The rails verdict is mechanical. A candidate that needs DELETE, PUT or
    PATCH, a body the scanner does not own, a cloud metadata address
    (`169.254.169.254`), a flood or concurrency hint, or more than 8 requests
    is stamped `OUT OF SCOPE`, the violated rail is named, and the repro
    template is omitted from the file entirely.
  - Next steps point at `cwe.mitre.org` lookups, the CWE submission process,
    CERT/CC reporting (`kb.cert.org/vuls/report/` and the CERT Guide to CVD
    coordination tutorial), the rule to name the mechanism rather than invent
    a class, and the fact that Category CWEs are `Usage: PROHIBITED` for
    mapping.
- **Scenario `tierc`** (`SCENARIOS`, `RUNNERS`): sends no attack traffic at
  all. Discovery is skipped and the transport is frozen before any candidate
  is read, so `bot.t.used` is 0 by construction rather than by convention.
  It does not require `--i-own-this`, because it owns nothing and touches
  nothing.
- **`--tierc-candidates FILE`**: a JSON list of hand-written candidates
  (`{id, title, hypothesis, repro: [{method, url, headers, body}]}`) rendered
  into dossiers. Parsed and documented, never executed.
- **`--tierc-dir DIR`**: dossier output directory, default `research`.
- **`bot.anomalies` and `bot.tierc`**: empty lists on the bot, ready for the
  anomaly engine to fill. Anomalies are rendered as dossiers with ids
  `ANOM-1`, `ANOM-2`, and each dossier names its Tier A or Tier B source.
- **Reporting**: `report.json` gains a `tierc` array
  (`{id, title, path, rails, out_of_scope}`) and an `anomalies` array;
  `report.html` gains a dossier table with a per-candidate rails verdict and
  no inline code execution; the terminal prints a one-line `TIER C` summary.
- **QA**: `qa/unit_tierc.py` (6 checks, network never touched), invoked from
  `qa/qa_b.py` the way `unit_sources.py` is, surfaced as 7 named gates.
  Suite is now 23/23 (16 original gates unchanged).
- **CHANGELOG.md** (this file).

### Not yet implemented

These are specified in `docs/V3-SPEC.md` and have their own harness prompts
in `docs/PROMPT-1-r2.md`, `docs/PROMPT-2-tier-a.md` and
`docs/PROMPT-3-tier-b.md`. None of them is in this build. Do not expect the
flags, groups, checks or report sections they describe.

- **R2** (prompt 1): soft-404 autocalibration, negative matchers, the global
  secret sweep, passive replay, scan-quality warnings, coverage accounting,
  the exit-code contract, the auth verify predicate.
- **Tier A** (prompt 2): the anomaly engine itself (group and scenario
  `anomaly`, differential probes, distance ranking, the noise filter).
  `bot.anomalies` exists as an empty list so Tier C has something to render;
  nothing populates it yet.
- **Tier B** (prompt 3): group and scenario `tierb`, the desync cell prober,
  unicode normalization oracles, delimiter confusion, the API state machine
  walk.

Because the anomaly engine is absent, a `tierc` run with no candidate file
currently writes zero dossiers and exits 0. That is the correct behaviour
for an empty anomaly set, not a bug.

### Changed

- `VERSION` is `2.0.0`.
- `Transport` gained a `frozen` flag. `request()` and `request_external()`
  raise instead of sending when it is set.
- `Bot` gained the `anomalies` and `tierc` lists.
- `SCENARIOS` gained `tierc`; `GROUPS` is unchanged at 12 entries; `CHECKS`
  is unchanged at 63. Tier C adds no checks by design, it turns evidence
  into documents.
- `run()` no longer forces the scenario to `recon` when `--i-own-this` is
  absent if the scenario is `tierc`.

## [1.1.0] - 2026-09-26

First pinned release. 63 checks, 12 groups, 7 scenarios, 16/16 QA gates,
zero dependencies, target renamed to the `placeholder_website` placeholder
throughout. See the git history for the check-by-check detail.
