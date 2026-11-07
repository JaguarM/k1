# Goal: smallest bootable x86 image that serves a static file over HTTPS

Minimize the byte size of `build/os.bin` while `./measure.sh` keeps passing.
Security does not matter. Correctness for real clients (curl, Chrome, Firefox) does.

## Commands
- `make` assembles `src/os.asm` into `build/os.bin` (flat multiboot image for `qemu -kernel`)
  and a listing `build/os.lst`; `python3 tools/sizes.py build/os.lst` = bytes per routine
- `./measure.sh` builds, boots it in QEMU (TCG, no KVM here), fetches it with curl
  (fresh connections + keep-alive), prints PASS + size + largest routines
- `./browsers.sh` checks Chrome (cert errors must be bypassable, page renders) and
  Firefox (`tools/ffcheck.py`, Marionette, cert exception in a throwaway profile).
  Run after any TLS/cert/TCP/HTTP change.
- `make test` checks the asm crypto (`src/os.asm` built with `-DHOST`, driven by
  `test/test_asm.c` in a 32-bit process) and the old C crypto against pyca/cryptography
- `make c` builds the reference C version (`src/os.c`, `src/crypto.h`) as `build/os_c.bin`;
  `make debug` builds it with serial logging of segments/records (`-serial stdio`)

## Machine contract (what measure.sh boots)
`qemu-system-x86_64 -nodefaults -m 16 -kernel build/os.bin -netdev user,hostfwd=tcp::8443-:443 -device ne2k_isa,netdev=n0`
Default CPU (qemu64: has SSE3, which `fisttp` needs). NIC: ISA NE2000 at port 0x300, polled
(no PCI, no IRQs, no DMA). Guest IP is 10.0.2.15 (slirp's hostfwd default), MAC
00:00:00:00:00:00, NIC in promiscuous mode.

## Layout
- `src/os.asm`: everything (boot, NE2000, TCP, TLS 1.3, crypto). Buffers live at fixed
  addresses from 2 MiB (RAM is zero at boot); connections at 4 MiB, 16 KiB each, slot =
  low byte of the client port.
- `tools/gen.py`: build-time cert, CertificateVerify template, HTTP response -> `build/gen.inc`
  (and `build/gen.h` for the C version)
- `www/index.html`: the served file (keep it fixed when comparing sizes)
- `src/os.c`, `src/crypto.h`, `src/start.S`: the C version (~4.5 KB), a readable reference
- `tools/ffcheck.py`: Firefox via Marionette; `tools/certerr.py`: Chrome net-log cert flags;
  `tools/sizes.py`: bytes per routine from the NASM listing

## Shortcuts already taken (do not "fix" these)
- TLS 1.3 only, one suite: TLS_CHACHA20_POLY1305_SHA256, X25519, ecdsa_secp256r1_sha256.
- ECDSA nonce k=1 and private key d=1/r, so a signature is `s = SHA256(msg) + 1`, no EC math.
  The server random (client random echoed) is incremented until s is a plain 32-byte DER
  INTEGER with no carry, so the CertificateVerify is a fixed template (~2 tries/handshake).
- X25519 private key is all-zero bytes, which clamps to 2^254: only doublings, no ladder.
  Field ops run from a 2-bytes-per-op program (`run`); subtraction = multiply by -1.
- One field routine (`fop`) does both mod 2^255-19 and mod 2^130-5 (Poly1305), parameterised.
- SHA-256 constants are computed at boot (primes by trial division, cube roots by Newton
  on the x87, `fisttp` for the fraction bits).
- Client data is never decrypted; client Finished is not verified. We count records:
  1st = ClientHello, then each application_data record after the client's Finished
  gets one HTTP response (keep-alive works).
- TCP is stateless: our seq = their ack, our ack = their seq + len. No retransmits
  (slirp doesn't drop). Pure ACKs are needed to stop slirp retransmitting into our stream.
- No ARP replies: one unsolicited ARP reply at boot puts 10.0.2.15 -> MAC 0 in slirp's table.
- Replies are built in place from the received frame; Ethernet addresses are not swapped
  (slirp ignores them); the window field is whatever slirp sent us. TCP segments are at
  most 127 bytes (imm8 compares).
- The frame buffer lives at address 0 (old real-mode IVT) so `xor reg, reg` loads it; the
  boot ARP announcement therefore carries IVT junk as MAC (fine: promiscuous NIC).
- NE2000 packet header read with one 32-bit `in` (QEMU allows it); 4 bytes past the frame
  are read too.
- No stack setup: QEMU's multiboot loader leaves esp = 0x6f10.
- Multiboot bss_end covers the 31 zero bytes after the base point 9 (PUB must stay last).
- Cert: X.509 v1, empty names, no extensions, compressed EC point. Its own signature uses a
  fixed nonce (K_CERT in gen.py) whose r has 2 leading zero bytes, and notBefore's time of
  day is chosen so s does too (deterministic build). Chrome: AUTHORITY_INVALID +
  COMMON_NAME_INVALID, both bypassable.
- HTTP response: `HTTP/1.1 200\nContent-Length:N\n\n` (bare LFs, no reason phrase).
- No final reduction in X25519/Poly1305 (wrong only with ~2^-128 probability).
- SHA-256 pads in place: every buffer passed to sha256 needs 72 spare bytes after the data.

## Tried and rejected
- Dummy cert signature (-62 bytes): Firefox says nssBadCert, which an exception can't override.
- Sharing one multiply routine in the C version, table-driven ChaCha indices: no gain.
- Field registers at address 0 (saves 12 in `run`/`x25519`): the M/K constants then need
  explicit zeroing, which eats the gain; the frame buffer is the better tenant for 0.

## Workflow
Measure after every change; any protocol/cert/HTTP change also needs `./browsers.sh`.
Firefox `--screenshot` hangs forever on error pages, and snap Firefox can't be killed from
here: always use `tools/ffcheck.py`, which quits Firefox through Marionette.
Image compression has not been tried: ask the user before going there.
