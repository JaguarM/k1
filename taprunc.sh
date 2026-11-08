#!/usr/bin/env bash
# Run tools/tapc on the host, inside ./tap.sh: W workers (one source IP each) x PER connections.
# Usage: ./tap.sh ./taprunc.sh W PER [BASE_PORT]   (W <= 16; PER < the fd limit)
cd "$(dirname "$0")"
W=$1 PER=$2 BASE=${3:-3000}
B=$(mktemp -d)
nstat -n 2>/dev/null
mem() { awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo; }
M0=$(mem)
( while sleep 15; do
    A=$(mem)
    echo "  [mem available $A MiB, established $(ss -s | awk '/^TCP:/{gsub(/[(),]/,""); print $4}')]"
    if [ "$A" -lt 1800 ]; then echo "  [memory guard: stopping workers]"; pkill -x tapc; break; fi
  done ) &
MON=$!
PIDS=()
for ((w=0; w<W; w++)); do
  build/tapc "10.0.2.$((32+w))" "$BASE" "$PER" www/index.html "$B" "$w" "$W" &
  PIDS+=($!)
done
PEAK=$M0
( while kill -0 "${PIDS[0]}" 2>/dev/null; do mem; sleep 1; done | sort -n | head -1 > "$B/lowest" ) &
LOW=$!
wait "${PIDS[@]}"
wait $LOW 2>/dev/null
kill $MON 2>/dev/null
L=$(cat "$B/lowest")
echo "memory: $M0 MiB available before, lowest $L MiB, used $((M0-L)) MiB"
nstat 2>/dev/null | grep -E "TcpRetransSegs|TcpExtTCPTimeouts|TcpActiveOpens"
ip -s link show k1t | sed -n 3,6p
rm -rf "$B"
