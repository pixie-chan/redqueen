#!/bin/sh
# Build redteam.py from parts/ in dependency order.
# NOTE: never use `cat parts/*.py` here: shell glob sorts p10/p11 before
# p1_head, which assembles the file with functions before imports.
set -e
cd "$(dirname "$0")"
cat parts/p1_head.py \
     parts/p2_checks_a.py \
     parts/p2_checks_b.py \
     parts/p3_transport.py \
     parts/p4_bot.py \
     parts/p5_checks_headers.py \
     parts/p6_tls_exposure.py \
     parts/p7_injection.py \
     parts/p8_auth.py \
     parts/p8b_tierb.py \
     parts/p9b_anomaly.py \
     parts/p9_report_text.py \
     parts/p9c_tierc.py \
     parts/p10_report_html.py \
     parts/p11_main.py \
     > redteam.py
# self-check: every parts/*.py must appear in the cat list above exactly once
missing=""
for f in parts/*.py; do
  if ! grep -q "$(basename "$f")" build.sh; then
    missing="$missing $f"
  fi
done
if [ -n "$missing" ]; then
  echo "build.sh: parts present but NOT in the cat list:$missing" >&2
  exit 1
fi
python3 -m py_compile redteam.py
echo "built redteam.py ($(wc -l < redteam.py) lines), compile OK"
