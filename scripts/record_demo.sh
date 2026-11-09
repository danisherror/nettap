#!/usr/bin/env bash
# Re-record the README demo from a live `nettap inspect` run:
#   docs/demo-inspect.cast  the asciinema recording (`asciinema play` it)
#   docs/demo-inspect.svg   the same, animated, for the README
#   docs/demo-report.png    the HTML report (needs Google Chrome or Chromium)
#
# Needs Docker, `nettap` on PATH, asciinema 2.x (`pip install "asciinema<3"`)
# and the nettap image: the published one, or NETTAP_IMAGE=<local build>.
# Containers it creates are removed by `nettap inspect` itself.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMMAND="nettap inspect python:3.12-alpine --name pip-install --duration 60s -- pip install -q requests"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

docker pull -q python:3.12-alpine >/dev/null

# types the command, then runs it from $WORK so the report lands in $WORK/data
cat > "$WORK/run.sh" <<EOF
#!/usr/bin/env bash
cd "$WORK"
cmd='$COMMAND'
printf '\033[1;32m\$\033[0m '
for ((i = 0; i < \${#cmd}; i++)); do printf '%s' "\${cmd:\$i:1}"; sleep 0.03; done
echo; sleep 0.5
\$cmd
sleep 3
EOF
chmod +x "$WORK/run.sh"

TERM=xterm-256color asciinema rec --overwrite -q --idle-time-limit 1.5 \
  --cols 110 --rows 52 -c "$WORK/run.sh" "$ROOT/docs/demo-inspect.cast" </dev/null >/dev/null
python3 "$ROOT/scripts/cast2svg.py" "$ROOT/docs/demo-inspect.cast" "$ROOT/docs/demo-inspect.svg"
echo "wrote docs/demo-inspect.cast and docs/demo-inspect.svg"

report="$WORK/data/pip-install_report.html"
for chrome in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
              google-chrome chromium chromium-browser; do
  if command -v "$chrome" >/dev/null 2>&1 || [ -x "$chrome" ]; then
    "$chrome" --headless=new --hide-scrollbars --force-device-scale-factor=2 \
      --window-size=860,1180 --screenshot="$ROOT/docs/demo-report.png" \
      "file://$report" >/dev/null 2>&1
    echo "wrote docs/demo-report.png"
    exit 0
  fi
done
echo "no Chrome/Chromium found: skipped docs/demo-report.png" >&2
