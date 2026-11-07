#!/usr/bin/env python3
"""Print the cert_status flags Chrome recorded for 127.0.0.1 in a net-log; exit 1 if any is fatal."""
import json
import sys

FATAL = {"REVOKED", "INVALID", "CONTAINS_ERRORS", "PINNED_KEY_MISSING"}  # no "Proceed" link for these
raw = open(sys.argv[1]).read()
try:
    d = json.loads(raw)
except ValueError:
    d = json.loads(raw.rstrip().rstrip(",") + "]}")
names = {v: k for k, v in d["constants"].get("certStatusFlag", {}).items()}
local = {e["source"]["id"] for e in d["events"] if "127.0.0.1" in json.dumps(e.get("params", {}))}
flags = set()
for e in d["events"]:
    st = e.get("params", {}).get("cert_status")
    if e["source"]["id"] in local and st:
        flags |= {n for f, n in names.items() if st & f}
print(" ".join(sorted(flags)) or "none")
sys.exit(1 if not flags or flags & FATAL else 0)
