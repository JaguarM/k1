#!/usr/bin/env bash
# Build, boot in QEMU, fetch https://127.0.0.1:$PORT/ with curl, report image size.
# Usage: ./measure.sh [image]   (default: build the asm image -> build/os.bin)
set -euo pipefail
cd "$(dirname "$0")"

PORT=${PORT:-8443}
IMG=${1:-}
if [[ -z "$IMG" ]]; then
  make -s all >/dev/null
  IMG=build/os.bin
fi
EXPECT=$(cat www/index.html)
LOG=$(mktemp)

qemu-system-x86_64 -nodefaults -display none -no-reboot -m 16 \
  -kernel "$IMG" \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:${PORT}-:443 \
  -device ne2k_isa,netdev=n0 >"$LOG" 2>&1 &
QEMU_PID=$!
trap 'kill $QEMU_PID 2>/dev/null || true; rm -f "$LOG"' EXIT

BODY=""
for _ in $(seq 1 40); do
  if BODY=$(curl -ks --max-time 5 "https://127.0.0.1:${PORT}/"); then break; fi
  sleep 0.25
done
if [[ "$BODY" != "$EXPECT" ]]; then
  echo "FAIL: got '${BODY}'"
  cat "$LOG"
  exit 1
fi
# second and third request on fresh connections, plus keep-alive reuse
for _ in 1 2; do
  B2=$(curl -ks --max-time 5 "https://127.0.0.1:${PORT}/" "https://127.0.0.1:${PORT}/x") || { echo "FAIL: repeat"; exit 1; }
  [[ "$B2" == "$EXPECT"$'\n'"$EXPECT" ]] || { echo "FAIL: keep-alive got '$B2'"; exit 1; }
done

SIZE=$(stat -c %s "$IMG")
echo "PASS  image=$IMG  size=${SIZE} bytes"
LST=${IMG%.bin}.lst
if [[ -f "$LST" ]]; then
  python3 tools/tbcheck.py "$LST" || true   # warns if TCG would run the handshake ~4x slower
  echo "--- largest routines/data (bytes) ---"
  python3 tools/sizes.py "$LST" 14
fi
