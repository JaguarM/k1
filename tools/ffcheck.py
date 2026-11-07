#!/usr/bin/env python3
"""Load a URL in headless Firefox via Marionette and report what rendered, then quit cleanly.

Usage: ffcheck.py URL CERT_DER [expected-text]
Uses a throwaway profile with a cert_override.txt entry for CERT_DER (what "Accept the Risk"
creates), so an overridable error loads the page and a non-overridable one shows the error
page, whose code we print. Exit 0 only if expected-text shows up. Unlike --screenshot, this
never leaves Firefox hanging on an error page.
"""
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse

url, der_path = sys.argv[1], sys.argv[2]
expect = sys.argv[3] if len(sys.argv) > 3 else None
hostport = urllib.parse.urlsplit(url).netloc
mport = 2900 + os.getpid() % 500

# under build/: snap Firefox can't read the host's /tmp
prof = tempfile.mkdtemp(prefix="ffcheck.", dir=os.path.join(os.path.dirname(__file__), "..", "build"))
fp = hashlib.sha256(open(der_path, "rb").read()).hexdigest().upper()
fp = ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))
with open(os.path.join(prof, "cert_override.txt"), "w") as f:
    f.write(f"# PRIVATE FILE\n{hostport}:\tOID.2.16.840.1.101.3.4.2.1\t{fp}\t\n")
with open(os.path.join(prof, "user.js"), "w") as f:
    f.write(f'user_pref("marionette.port", {mport});\n'
            'user_pref("browser.shell.checkDefaultBrowser", false);\n'
            'user_pref("datareporting.policy.dataSubmissionEnabled", false);\n')

ff = subprocess.Popen(["firefox", "--headless", "--marionette", "-no-remote", "-profile", prof],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def connect():
    for _ in range(100):
        try:
            return socket.create_connection(("127.0.0.1", mport), timeout=30)
        except OSError:
            time.sleep(0.2)
    raise SystemExit("ffcheck: marionette did not come up")


sock = connect()
buf = b""


def recv():
    global buf
    while b":" not in buf:
        buf += sock.recv(65536)
    n, rest = buf.split(b":", 1)
    n = int(n)
    while len(rest) < n:
        rest += sock.recv(65536)
    buf = rest[n:]
    return json.loads(rest[:n])


msgid = 0


def cmd(name, params=None):
    global msgid
    msgid += 1
    data = json.dumps([0, msgid, name, params or {}]).encode()
    sock.sendall(str(len(data)).encode() + b":" + data)
    while True:
        m = recv()
        if m[0] == 1 and m[1] == msgid:
            return m[2], m[3]  # error, result


try:
    recv()  # server hello
    cmd("WebDriver:NewSession", {"capabilities": {"alwaysMatch": {"acceptInsecureCerts": False}}})
    err, _ = cmd("WebDriver:Navigate", {"url": url})
    _, res = cmd("WebDriver:ExecuteScript", {"script": "return [document.documentURI, document.body ? document.body.innerText : '']", "args": []})
    uri, text = res["value"]
    if uri.startswith("about:"):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query)
        _, res = cmd("WebDriver:ExecuteScript", {"script": "return document.getElementById('errorCode') ? document.getElementById('errorCode').textContent : (document.querySelector('[data-l10n-id]')||{}).textContent", "args": []})
        print(f"firefox: ERROR PAGE {uri.split('?')[0]} e={q.get('e')} code={res.get('value')!r}"
              + (f" navigate={err.get('error')}" if err else ""))
        ok = False
    else:
        print(f"firefox: page text {text[:60]!r}")
        ok = expect is None or expect in text
    try:
        cmd("Marionette:Quit", {"flags": ["eForceQuit"]})
    except OSError:
        pass
finally:
    try:
        ff.wait(timeout=15)
    except subprocess.TimeoutExpired:
        ff.kill()
    shutil.rmtree(prof, ignore_errors=True)
sys.exit(0 if ok else 1)
