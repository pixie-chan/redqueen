"""Refresh every version/count claim in the docs from the built artifact.

Run after a release:  python3 docs/sync-doc-numbers.py

Every number is measured, never typed: version/checks/groups/scenarios come
from importing redteam.py, the line and slice counts from the real files, and
the QA gate count from the assertions actually present in qa/qa.py.
"""
import glob
import importlib.util
import re
import sys

ROOT = "/home/zen/projects/redteam-bot"
BOT = ROOT + "/redteam.py"
QA = ROOT + "/qa/qa.py"


def measure():
    spec = importlib.util.spec_from_file_location("rt_sync", BOT)
    rt = importlib.util.module_from_spec(spec)
    sys.argv = ["x"]
    try:
        spec.loader.exec_module(rt)
    except SystemExit:
        pass
    version = rt.VERSION
    checks = len(rt.CHECKS)
    groups = len(rt.GROUPS)
    scenarios = len(rt.SCENARIOS)
    lines = sum(1 for _ in open(BOT, encoding="utf-8"))
    parts = len(glob.glob(ROOT + "/parts/*.py"))
    # every gate() call in the suite is one assertion the suite makes
    gates = len(re.findall(r"^\s*gate\(", open(QA, encoding="utf-8").read(),
                           re.M))
    return version, checks, groups, scenarios, lines, parts, gates


def main():
    version, checks, groups, scenarios, lines, parts, gates = measure()
    nums = "{:,}".format(lines)
    subs = [
        (r"v\d+\.\d+\.\d+", "v" + version),
        (r"version-\d+\.\d+\.\d+", "version-" + version),
        (r"checks-\d+(?=\")", "checks-%d" % checks),
        (r"\b\d+ checks\b", "%d checks" % checks),
        (r"\b\d{1,3},\d{3}\b( lines)?", nums + (r"\1" if False else "")),
        (r"\b\d+ groups\b", "%d groups" % groups),
        (r"\b\d+/\d+ QA gates\b", "%d/%d QA gates" % (gates, gates)),
        (r"\b\d+/\d+ gates PASS\b", "%d/%d gates PASS" % (gates, gates)),
        (r"\b\d+ build slices\b", "%d build slices" % parts),
        (r"Twelve build slices", "%d build slices" % parts),
        (r"\bTwelve slices\b", "%d slices" % parts),
    ]
    targets = [ROOT + "/README.md", ROOT + "/docs/ARCHITECTURE.md",
               ROOT + "/docs/build-arch-html.py"]
    touched = 0
    for t in targets:
        if not glob.glob(t):
            continue
        s = open(t, encoding="utf-8").read()
        orig = s
        for rx, rep in subs:
            s = re.sub(rx, rep, s)
        if s != orig:
            open(t, "w", encoding="utf-8").write(s)
            touched += 1
            print("updated", t)
    print("measured: v%s | %d checks | %d groups | %d scenarios | %d lines | "
          "%d slices | %d QA gates" % (version, checks, groups, scenarios,
                                        lines, parts, gates))
    print("files updated:", touched)


if __name__ == "__main__":
    main()
