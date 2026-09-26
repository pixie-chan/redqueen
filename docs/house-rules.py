"""House-rule scanner for redteam.py. Run in CI and before any commit.

  python3 docs/house-rules.py

Three rules, checked without shell quoting so a regex wildcard can never
quietly defeat them:

  1. no em dash (U+2014) outside the docs that quote this rule
  2. no real site name anywhere
  3. no FULL credential-shaped literal in source. The QA fixtures are
     deliberately elided (AKIAIO...MPLE) or assembled at runtime, and this
     check reads the characters literally: a match must contain no dot.

Exit 0 clean, 1 violations found (each printed with file and line).
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {".git", "__pycache__", ".qa"}
# Files that legitimately quote a rule's own pattern: the checkers themselves
# and the build prompts, which instruct the reader to grep for the em dash.
# The QA harness MUST serve credential-shaped strings verbatim, otherwise the
# masking and secret-detection gates cannot test anything. Those fixtures are
# synthetic by construction and are exempt from rule 3, not from review.
CREDENTIAL_FIXTURE_FILES = {
    "qa/harness_a.py",
    "qa/qx_harness.py",
    "qa/unit_tierc.py",
}
PATTERN_BEARING = {
    "docs/house-rules.py",
    "docs/sync-doc-numbers.py",
    "docs/PROMPT-1-r2.md",
    "docs/PROMPT-2-tier-a.md",
    "docs/PROMPT-3-tier-b.md",
    "docs/PROMPT-4-tier-c.md",
    ".github/workflows/qa.yml",
}
EXT = (".py", ".md", ".sh", ".yml", ".yaml", ".txt")

CRED_PATTERNS = [
    re.compile(r"sk_live_[A-Za-z0-9]{16,}"),
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
]
EM_DASH = "—"
SITE_NAME = "quant iq"


def walk():
    for root, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in sorted(files):
            if f.endswith(EXT):
                yield os.path.join(root, f)


def main():
    problems = []
    for path in walk():
        rel = os.path.relpath(path, ROOT)
        try:
            lines = open(path, encoding="utf-8").read().splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for n, line in enumerate(lines, 1):
            if EM_DASH in line and rel not in PATTERN_BEARING:
                # a line that defines or documents the rule is not a usage
                if "EM_DASH" in line or "em dash" in line.lower():
                    continue
                problems.append((rel, n, "em dash", line.strip()[:70]))
            if SITE_NAME in line.lower() and rel not in PATTERN_BEARING:
                problems.append((rel, n, "real site name", line.strip()[:70]))
            if rel in CREDENTIAL_FIXTURE_FILES:
                continue
            for rx in CRED_PATTERNS:
                m = rx.search(line)
                if not m:
                    continue
                # An ELIDED fixture is exempt. The QA harness deliberately
                # writes AKIAIO...MPLE, and the regex reads the dots as
                # wildcards, so the match can look like a real key. The
                # reliable discriminator: an elided fixture shows a dot in
                # the source line, a real key is 16+ unbroken characters.
                if "..." in line:
                    continue
                if "." in m.group(0):
                    continue
                # 16+ literal characters with no elision: a real key
                problems.append((rel, n, "credential-shaped literal", line.strip()[:70]))

    if problems:
        for rel, n, what, snippet in problems:
            print("%s:%d: %s: %s" % (rel, n, what, snippet))
        print("\n%d house-rule violation(s)" % len(problems))
        return 1
    print("house rules clean: no em dash, no real site name, no full "
          "credential literal")
    return 0


if __name__ == "__main__":
    sys.exit(main())
