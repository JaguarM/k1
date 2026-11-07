#!/usr/bin/env bash
# Browser compatibility check (slower than measure.sh; run after protocol/cert changes).
#  1. Chrome, no flags: cert errors (from its net-log) must all be bypassable ("Proceed" link)
#  2. Chrome, warning bypassed: must render the page
#  3. Firefox (via Marionette) with a cert exception in a throwaway profile: must render the page
set -euo pipefail
cd "$(dirname "$0")"
PORT=${PORT:-8444}
IMG=${1:-build/os.bin}
[[ $# -gt 0 ]] || make -s all >/dev/null
EXPECT=$(head -c 20 www/index.html)
TMP=$(mktemp -d)

qemu-system-x86_64 -nodefaults -display none -no-reboot -m 16 -kernel "$IMG" \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:${PORT}-:443 -device ne2k_isa,netdev=n0 >/dev/null 2>&1 &
QEMU_PID=$!
trap 'kill $QEMU_PID 2>/dev/null || true; rm -rf "$TMP"' EXIT
for _ in $(seq 1 40); do curl -ks --max-time 2 -o /dev/null "https://127.0.0.1:${PORT}/" && break; sleep 0.25; done

chrome() { timeout 30 google-chrome --headless=new --no-sandbox --user-data-dir="$TMP/c$1" "${@:2}" \
  --dump-dom "https://127.0.0.1:${PORT}/" 2>/dev/null; }

chrome 1 --log-net-log="$TMP/netlog.json" >/dev/null || true
if FLAGS=$(python3 -I tools/certerr.py "$TMP/netlog.json"); then echo "chrome cert errors: $FLAGS (bypassable) OK"
else echo "chrome cert errors: $FLAGS -> FAIL (not bypassable)"; exit 1; fi

if chrome 2 --ignore-certificate-errors | grep -qF "$EXPECT"; then echo "chrome page: OK"
else echo "chrome page: FAIL"; exit 1; fi

python3 -I tools/ffcheck.py "https://127.0.0.1:${PORT}/" build/cert.der "$EXPECT"
