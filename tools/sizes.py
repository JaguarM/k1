#!/usr/bin/env python3
"""Per-routine byte counts from a NASM listing (nasm -l): span of each top-level label.
Usage: sizes.py build/os.lst [top-N]"""
import re
import sys

spans = []  # [label, first_offset, end_offset]
for line in open(sys.argv[1], errors="replace"):
    m = re.match(r"\s*\d+\s+([0-9A-F]{8})\s+(\S+?)(?:<rep ([0-9A-F]+)h>)?-?\s+(?:<\d+>\s*)?(.*)", line)
    bare = re.match(r"\s*\d+\s+(?:<\d+>\s*)?([A-Za-z_]\w*):", line)  # label on a line of its own
    src = m.group(4) if m else ""
    lab = re.match(r"([A-Za-z_]\w*):", src) or bare
    if lab:
        spans.append([lab.group(1), None, None])
    if m and spans:
        addr, hexbytes, rep, _ = m.groups()
        n = len(re.sub(r"[^0-9A-F]", "", hexbytes)) // 2 * (int(rep, 16) if rep else 1)
        start = int(addr, 16)
        if spans[-1][1] is None:
            spans[-1][1] = start
        spans[-1][2] = max(spans[-1][2] or 0, start + n)
# continuation lines of long db's only carry bytes, so use the next label's start as the end
for i in range(len(spans) - 1):
    if spans[i + 1][1] is not None:
        spans[i][2] = spans[i + 1][1]
rows = sorted(((e - s, n) for n, s, e in spans if s is not None), reverse=True)
for size, name in rows[: int(sys.argv[2]) if len(sys.argv) > 2 else 40]:
    print(f"{size:6d}  {name}")
