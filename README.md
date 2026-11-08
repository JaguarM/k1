# k1

k1 is a 2,347-byte bootable x86 "operating system" that serves a static web page over HTTPS
(TLS 1.3) and holds 64,497 TLS connections at once. It boots in QEMU, drives an NE2000
network card, speaks just enough TCP, and does the whole TLS 1.3 handshake itself: ECDSA
P-256, ChaCha20-Poly1305, SHA-256 / HKDF, all hand-written in assembly. curl, Chrome and
Firefox load the page (after the usual certificate warning).

The name comes from the ECDSA nonce k = 1 that the whole signing trick rests on.

**It is deliberately, hilariously insecure.** The keys are constants, the ECDSA nonce is
fixed, the key exchange gives the session keys to anyone who sees the ClientHello, the
certificate isn't even signed, nothing from the client is verified, and nothing is
constant-time. It is a size-coding exercise, not something to put on a network.

The goal is connections per KiB: `./score.sh` opens TLS connections until the client runs
out of ports, keeps them all open, and checks that every one still serves the page.

| | image | connections at once | score (connections / KiB) |
|---|---|---|---|
| size-only version | 2,714 bytes | 56 | 21 |
| now | 2,347 bytes | 64,497 | 28,140 |

## Try it

Needs `nasm`, `python3` with `cryptography`, `qemu-system-x86_64` and `curl`.

```bash
make                 # -> build/os.bin
./measure.sh         # boot it, fetch the page with curl, print the size
./score.sh           # ~45 minutes: hold as many connections as the client has ports
```

Or by hand:

```bash
qemu-system-x86_64 -nodefaults -display none -m 16 -kernel build/os.bin \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:8443-:443 -device ne2k_isa,netdev=n0
curl -k https://127.0.0.1:8443/
```

Change `www/index.html` to serve something else.

## How it gets this small

- ECDSA with nonce k = 1 and private key d = 1/r: a signature is just `SHA-256(msg) + 1`.
  The server random is nudged until the signature encodes to a fixed length.
- No elliptic-curve math at all: our X25519 key share is 9, the curve's base point, so the
  shared secret X25519(client key, 9) is simply the client's own key share.
- The certificate has no signature. Its issuer name differs from its (empty) subject, so
  clients look for the issuer, don't find it, report "unknown issuer" (which you can click
  through) and never check the signature, whose "algorithm" is therefore just a 2-byte OID.
  Its key is the d = 1/r above.
- Poly1305 multiplies with 8-bit limbs, as 17 column sums over a precomputed table.
- The SHA-256 constants are computed at boot from their definition (cube roots of primes,
  by Newton's method on the x87 FPU) instead of being stored.
- No ARP replies, one TCP segment per reply, and the client's data is never decrypted.

## How it holds 64,497 connections

- One 128-byte slot per client port, all 65,536 of them, found with a single unaligned load
  from the received frame: slirp (QEMU's user-mode network) shows every client as 10.0.2.2,
  so the port alone identifies a connection.
- A slot holds only a record counter, the next sequence number expected, how much of the
  current record is still to come, and the application key and IV. After the handshake,
  records are skipped by their headers, never stored. ClientHellos (up to 2 KB) are
  reassembled in 1,024 shared buckets, indexed by slirp's initial sequence number.
- Anything that isn't the next expected byte is just acknowledged again, so slirp's resends
  recover from the NE2000's receive ring, which overflows whenever handshakes queue up.
- The ceiling is the client: 64,510 is every unprivileged port on 127.0.0.1 (minus two in
  use); 13 of those page fetches timed out. Beyond ~10K connections, slirp's main loop, which
  walks all its sockets on every iteration (~0.5 s at 64K), is the bottleneck, not the guest.

`CLAUDE.md` lists every shortcut and the machine contract. `src/os.c` is an earlier C
version (~4.5 KB) of the size-only design that is easier to read.

## Tests

- `make test` checks the asm crypto against pyca/cryptography (needs 32-bit gcc support).
- `./browsers.sh` loads the page in headless Chrome and Firefox.
- `tools/load.py` has `burst K` (K clients connecting at the same moment), `seq N` and `ka N`.
