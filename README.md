# k1

k1 is a 2,714-byte bootable x86 "operating system" that serves a static web page over HTTPS
(TLS 1.3). It boots in QEMU, drives an NE2000 network card, speaks just enough TCP, and
does the whole TLS 1.3 handshake itself: X25519, ECDSA P-256, ChaCha20-Poly1305,
SHA-256 / HKDF, all hand-written in assembly. curl, Chrome and Firefox load the page
(after the usual self-signed certificate warning).

The name comes from the ECDSA nonce k = 1 that the whole signing trick rests on.

**It is deliberately, hilariously insecure.** The private keys are constants, the ECDSA
nonce is fixed, nothing from the client is verified, and nothing is constant-time. It is
a size-coding exercise, not something to put on a network.

## Try it

Needs `nasm`, `python3` with `cryptography`, `qemu-system-x86_64` and `curl`.

```bash
make                 # -> build/os.bin
./measure.sh         # boot it, fetch the page with curl, print the size
```

Or by hand:

```bash
qemu-system-x86_64 -nodefaults -display none -m 16 -kernel build/os.bin \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:8443-:443 -device ne2k_isa,netdev=n0
curl -k https://127.0.0.1:8443/
```

Change `www/index.html` to serve something else.

## How it gets this small

- ECDSA with nonce k = 1 and private key d = 1/r: a signature is just `SHA-256(msg) + 1`,
  with no elliptic-curve code at all. The server random is nudged until the signature
  encodes to a fixed length.
- The X25519 private key is all zeros, which clamps to 2^254: the shared secret takes
  254 point doublings, with no ladder. The field operations run as 2-byte "instructions"
  through a tiny interpreter.
- One modular-multiply routine serves both X25519 (mod 2^255 - 19) and Poly1305
  (mod 2^130 - 5).
- The SHA-256 constants are computed at boot from their definition (cube roots of primes,
  by Newton's method on the x87 FPU) instead of being stored.
- Stateless TCP, no ARP replies, the client's data is never decrypted, and the
  certificate is trimmed to the bone (v1, no names, compressed key).

`CLAUDE.md` lists every shortcut and the machine contract. `src/os.c` is an earlier C
version (~4.5 KB) that is easier to read.

## Tests

- `make test` checks the asm crypto against pyca/cryptography (needs 32-bit gcc support).
- `./browsers.sh` loads the page in headless Chrome and Firefox.
