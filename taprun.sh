#!/usr/bin/env bash
# Run on the host, inside ./tap.sh: W worker processes, each with IPS_PER source IPs x PER ports.
# Usage: ./tap.sh ./taprun.sh W IPS_PER PER   (W*IPS_PER must be <= 16)
cd "$(dirname "$0")"
W=$1 IPS=$2 PER=$3
B=$(mktemp -d)
nstat -n 2>/dev/null
( while sleep 20; do
    echo "  [mem available $(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo) MiB, established $(ss -tn state established 2>/dev/null | grep -c 10.0.2.15)]"
    if [ "$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)" -lt 350 ]; then echo "  [memory guard: stopping workers]"; pkill -f tools/tapload.py; break; fi
  done ) &
MON=$!
for ((w=0; w<W; w++)); do
  IPOFF=$((w*IPS)) BARRIER=$B WID=$w NW=$W python3 -I tools/tapload.py "$IPS" "$PER" &
done
wait $(jobs -p | grep -v "^$MON$")
kill $MON 2>/dev/null
nstat 2>/dev/null | grep -E "TcpRetransSegs|TcpExtTCPTimeouts|TcpActiveOpens"
ip -s link show k1t | sed -n 3,6p
rm -rf "$B"
