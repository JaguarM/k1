#!/usr/bin/env python3
"""Warn when the SHA-256 round loop's return addresses collide in QEMU's TCG jump cache.

TCG finds the target of every `ret` in a per-CPU jump cache indexed, within one 4 KiB page,
by only 6 bits: (pc ^ pc >> 6) & 63. The whole image is one page, so if two `ret` targets
of the round loop (after its calls to wnext/sigma) share a slot, they evict each other on
every round and handshakes get ~4x slower under TCG (measured: 10.3M vs 2.4M cycles).
Moving routines around (zero bytes) fixes it. Usage: tbcheck.py build/os.lst
"""
import re
import sys

HOT = ("sha256", "wnext")  # routines whose calls run several times per SHA-256 round


def main(path):
    fn, rets = None, []
    for line in open(path):
        m = re.match(r"\s*\d+\s+([0-9A-F]{8})\s+([0-9A-F]+)\s+(.*)", line)
        lab = re.match(r"\s*\d+\s+(?:[0-9A-F]{8}\s+[0-9A-F]+\s+)?([A-Za-z_]\w*):", line)
        if lab:
            fn = lab.group(1)
        if m and fn in HOT and re.match(r"(\.\w+:\s*)?call\b", m.group(3)):
            rets.append((int(m.group(1), 16) + len(m.group(2)) // 2, fn, m.group(3).split(";")[0].strip()))
    slots = {}
    for addr, fn, src in rets:
        off = addr & 0xFFF
        slots.setdefault((off ^ off >> 6) & 63, []).append(f"{fn}+{addr:#x} ({src})")
    bad = [v for v in slots.values() if len(v) > 1]
    for v in bad:
        print("tbcheck: TCG jump-cache collision (handshakes ~4x slower under QEMU):", " vs ".join(v))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "build/os.lst"))
