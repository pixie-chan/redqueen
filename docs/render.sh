#!/bin/sh
# Render docs/diagrams/*.mmd to PNG with the CACHED mermaid-cli (offline) and
# the local Playwright Chromium. Nothing is downloaded.
set -e
cd "$(dirname "$0")/diagrams"
CFG=/tmp/kiki-mmdc-puppeteer-rt.json
cat > "$CFG" <<'CFGJSON'
{ "executablePath": "/home/zen/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome",
  "args": ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"] }
CFGJSON
export PUPPETEER_CONFIG="$CFG"
export npm_config_offline=true
for f in *.mmd; do
  echo "--- $f"
  npx -y @mermaid-js/mermaid-cli -i "$f" -o "${f%.mmd}.png" -b white -w 1600 -p "$CFG" 2>&1 | tail -2
done
echo "=== rendered:"
ls -la *.png
