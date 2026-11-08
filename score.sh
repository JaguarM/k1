#!/usr/bin/env bash
# Score = connections / KiB of image. Builds, boots in QEMU (same machine as measure.sh),
# then `tools/load.py hold` opens TLS connections and keeps them all open, fetching the page
# over every one at 64, 128, 256, ... open; "connections" is the most that worked at once.
# Usage: ./score.sh [image] [max connections]   (default: build/os.bin, until out of ports)
#
# By default the client uses every unprivileged source port: explicit binds to 1024-32767 and
# 61000-65535, then the kernel's own ephemeral range, ~64.5K connections in ~45 minutes. While
# it runs, most of 127.0.0.1's ports are taken (don't start servers then). PORTS=auto keeps to
# the ephemeral range: 28,232 connections in ~8 minutes.
set -euo pipefail
cd "$(dirname "$0")"
export PORTS=${PORTS:-1024-32767,61000-65535,auto}

PORT=${PORT:-8445}
IMG=${1:-}
if [[ -z "$IMG" ]]; then
  make -s all >/dev/null
  IMG=build/os.bin
fi
LOG=$(mktemp)

qemu-system-x86_64 -nodefaults -display none -no-reboot -m 16 \
  -kernel "$IMG" \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:${PORT}-:443 \
  -device ne2k_isa,netdev=n0 >"$LOG" 2>&1 &
QEMU_PID=$!
trap 'kill $QEMU_PID 2>/dev/null || true; rm -f "$LOG"' EXIT
for _ in $(seq 1 40); do
  curl -ks --max-time 5 -o /dev/null "https://127.0.0.1:${PORT}/" && break
  sleep 0.25
done

OUT=$(PORT=$PORT python3 tools/load.py hold ${2:-} | tee /dev/stderr)
CONN=$(sed -n 's/^connections: \([0-9]*\).*/\1/p' <<<"$OUT")
SIZE=$(stat -c %s "$IMG")
python3 -c "print(f'SCORE {$CONN / ($SIZE / 1024):.1f}  = $CONN connections / $SIZE bytes')"
