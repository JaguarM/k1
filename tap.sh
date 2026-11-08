#!/usr/bin/env bash
# Boot k1 on a tap interface and run a command against it (needs root and /dev/net/tun).
# Usage: [IMG=build/os.bin] [MEM=160] ./tap.sh COMMAND [ARGS...]
# The host is 10.0.2.2 plus 10.0.2.32-47 (one source IP per slot table); the guest is 10.0.2.15.
# A permanent neighbour entry stands in for ARP replies, which k1 doesn't send.
set -euo pipefail
cd "$(dirname "$0")"
IMG=${IMG:-build/os.bin}
MEM=${MEM:-160}
TAP=k1t
MAC=02:00:00:00:00:01

ip link del "$TAP" 2>/dev/null || true
ip tuntap add dev "$TAP" mode tap
sysctl -q "net.ipv6.conf.$TAP.disable_ipv6=1" 2>/dev/null || true
ip addr add 10.0.2.2/24 dev "$TAP"
for i in $(seq 32 47); do ip addr add "10.0.2.$i/24" dev "$TAP"; done
ip link set "$TAP" up
ip neigh replace 10.0.2.15 lladdr "$MAC" dev "$TAP" nud permanent

LOG=$(mktemp)
qemu-system-x86_64 -nodefaults -display none -no-reboot -m "$MEM" -kernel "$IMG" \
  -netdev "tap,id=n0,ifname=$TAP,script=no,downscript=no" -device ne2k_isa,netdev=n0 >"$LOG" 2>&1 &
QEMU_PID=$!
trap 'kill $QEMU_PID 2>/dev/null || true; wait $QEMU_PID 2>/dev/null || true; ip link del '"$TAP"' 2>/dev/null || true; rm -f "$LOG"' EXIT

up=
for _ in $(seq 1 40); do
  if curl -ks --max-time 3 -o /dev/null --interface 10.0.2.32 https://10.0.2.15/; then up=1; break; fi
  sleep 0.25
done
[[ -n "$up" ]] || { echo "FAIL: guest not answering over tap"; cat "$LOG"; exit 1; }
"$@"
