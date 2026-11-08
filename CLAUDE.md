# Goal: most simultaneous HTTPS connections per KiB of bootable x86 image

Maximize the score from `./score.sh`: connections / (size of `build/os.bin` / 1024), where
connections = the most TLS connections that were open at the same time and all served the page.
`./measure.sh` must keep passing. (Until 2026-11-08 the goal was size alone: 2,714 bytes.)
Security does not matter. Correctness for real clients (curl, Chrome, Firefox) does.

## Commands
- `make` assembles `src/os.asm` into `build/os.bin` (flat multiboot image for `qemu -kernel`)
  and a listing `build/os.lst`; `python3 tools/sizes.py build/os.lst` = bytes per routine
- `./measure.sh` builds, boots it in QEMU (TCG, no KVM here), fetches it with curl
  (fresh connections + keep-alive), prints PASS + size + largest routines
- `./score.sh [image] [max]` boots the image and runs `tools/load.py hold`: opens TLS
  connections from every unprivileged client port (explicit binds to 1024-32767 and
  61000-65535, then Linux's ephemeral range; ~64.5K), keeps them all open, fetches the page
  over every one at 64, 128, 256, ... open and at the end; stops at the first failing
  checkpoint, at `max`, out of ports, or when more than 10 + 0.1% of handshakes fail.
  4 handshakes in flight (more overflow the NIC ring: with 16, handshakes past 32K open
  started timing out, since slirp walks all its sockets on every main-loop iteration, ~0.5 s
  at 60K, and resends back off); starts 4 ms apart (slirp's listen backlog is 1). ~45 minutes,
  ~5 GB of client RAM, and most of 127.0.0.1's ports are taken meanwhile. `PORTS=auto` keeps
  to the ephemeral range (28,232, ~8 minutes). The guest has one slot per client port and
  slirp shows every client as 10.0.2.2, so 65,536 is the ceiling. `tools/load.py` also has
  `burst K` (K clients at the same moment), `seq N` (handshake rate) and `ka N` (keep-alive).
- `tools/tbcheck.py build/os.lst` (run by measure.sh) warns when two `ret` targets of the
  SHA-256 round loop share a slot of QEMU's TCG jump cache: within one 4 KiB page it has only
  64 slots ((pc ^ pc >> 6) & 63), and a collision makes handshakes ~4x slower. Fix by moving
  routines around (zero bytes).
- `./browsers.sh` checks Chrome (cert errors must be bypassable, page renders) and
  Firefox (`tools/ffcheck.py`, Marionette, cert exception in a throwaway profile).
  Run after any TLS/cert/TCP/HTTP change.
- `make test` checks the asm crypto (`src/os.asm` built with `-DHOST`, driven by
  `test/test_asm.c` in a 32-bit process) and the old C crypto against pyca/cryptography
  (the asm has no X25519 any more; its x9/xm vectors are only checked for the C version)
- `make c` builds the reference C version (`src/os.c`, `src/crypto.h`) as `build/os_c.bin`;
  `make debug` builds it with serial logging of segments/records (`-serial stdio`)

## Machine contract (what measure.sh boots)
`qemu-system-x86_64 -nodefaults -m 160 -kernel build/os.bin -netdev user,hostfwd=tcp::8443-:443 -device ne2k_isa,netdev=n0`
Default CPU (qemu64: has SSE3, which `fisttp` needs). NIC: ISA NE2000 at port 0x300, polled
(no PCI, no IRQs, no DMA). Guest IP is 10.0.2.15 (slirp's hostfwd default), MAC
00:00:00:00:00:00, NIC in promiscuous mode.

Needs -m 160: the client IP's low nibble picks one of 16 x 8 MiB slot tables, from 8 MiB up
(slirp's 10.0.2.2 uses the table at 24 MiB). `./tap.sh ./taprunc.sh W PER` runs k1 on a tap
interface and loads it with `build/tapc` (`gcc -O2 -o build/tapc tools/tapc.c -lssl -lcrypto`;
needs root): 240,000 connections held from 16 source IPs.

## Layout
- `src/os.asm`: everything (boot, NE2000, TCP, TLS 1.3, crypto). Buffers live at fixed
  addresses from 2 MiB (RAM is zero there at boot). Connections: one 128-byte slot per client
  port at 8 MiB (all 65536 ports fit, so no collisions: slirp shows every client as 10.0.2.2).
  ClientHellos are reassembled in 1024 x 4 KiB buckets at 4 MiB, indexed by slirp's ISN.
  The top ~400 KiB below 16 MiB hold SeaBIOS tables at boot: never assume zeros up there.
- `tools/gen.py`: build-time cert, CertificateVerify template, HTTP response -> `build/gen.inc`
  (and `build/gen.h` for the C version)
- `www/index.html`: the served file (keep it fixed when comparing sizes)
- `src/os.c`, `src/crypto.h`, `src/start.S`: the C version (~4.5 KB), a readable reference for
  the size-only design (X25519 doublings, 256 connection slots); not updated since
- `tools/ffcheck.py`: Firefox via Marionette; `tools/certerr.py`: Chrome net-log cert flags;
  `tools/sizes.py`: bytes per routine from the NASM listing

## Shortcuts already taken (do not "fix" these)
- TLS 1.3 only, one suite: TLS_CHACHA20_POLY1305_SHA256, X25519, ecdsa_secp256r1_sha256.
- ECDSA nonce k=1 and private key d=1/r, so a signature is `s = SHA256(msg) + 1`, no EC math.
  The server random (client random echoed) is incremented until s is a plain 32-byte DER
  INTEGER with no carry, so the CertificateVerify is a fixed template (~2 tries/handshake).
- No elliptic-curve math at all: our X25519 key share is 9, the base point itself, so the
  shared secret X25519(their key, 9) is their own key share; the handshake feeds the client's
  x25519 key share straight into HKDF-Extract. curl, Chrome and Firefox accept it. (Idea from
  Gemini; it replaced 254 doublings with 8-bit limbs, ~200 bytes, and tripled the handshake rate.)
- Poly1305: 8-bit limbs in dwords; h * r is 17 column sums over a table R (R[16 + j] = r[j],
  R[j - 1] = 320 r[j], since 2^136 = 320 mod 2^130 - 5), then 3 carry passes.
- SHA-256 constants are computed at boot (primes by trial division, cube roots by Newton
  on the x87, `fisttp` for the fraction bits).
- Client data is never decrypted; client Finished is not verified. We count records:
  1st = ClientHello, then each application_data record after the client's Finished
  gets one HTTP response (keep-alive works).
- TCP: our seq = their ack (nothing we send is lost, so no retransmits, no send state).
  Per connection we keep the next sequence number we expect: a segment that isn't exactly
  that (a resend, or one after a segment the NIC dropped) is ignored and re-acked, so slirp
  resends from there. The NE2000 drops frames when its 31 KB ring is full (QEMU has no
  can_receive for it), which happens whenever handshakes queue up; slirp's resends recover.
  A client FIN gets FIN+ACK. Pure ACKs are needed to stop slirp retransmitting into our
  stream. Pipelined requests in separate segments would get overlapping seqs (no client does).
- slirp's ISN is 1 + 64000 n (n counts connections and 500 ms ticks), so ClientHello bucket
  125 n mod 1024 differs for 1024 connections in a row. slirp sends the ClientHello's 2nd
  segment only after we ack the 1st (slow start), so partial ClientHellos are the norm.
- After the handshake, records are only skipped (header read, length counted down), never
  stored: a record header split across two segments would desync (needs >1 MSS of requests).
- `keys` writes 20 junk bytes after the IV (HKDF-Expand always stores 32): slots are 128 bytes.
- No ARP replies: one unsolicited ARP reply at boot puts 10.0.2.15 -> MAC 0 in slirp's table.
- Replies are built in place from the received frame; Ethernet addresses are not swapped
  (slirp ignores them); the window field is whatever slirp sent us. One segment per reply
  (the largest, our handshake flight, is ~420 bytes), so there is no send-side state at all.
  The TCP pseudo-header reuses the received IP header's protocol byte.
- The frame buffer lives at address 0 (old real-mode IVT) so `xor reg, reg` loads it; the
  boot ARP announcement therefore carries IVT junk as MAC (fine: promiscuous NIC).
- NE2000 packet header read with one 32-bit `in` (QEMU allows it); 4 bytes past the frame
  are read too.
- No stack setup: QEMU's multiboot loader leaves esp = 0x6f10.
- Multiboot bss_end covers the 31 zero bytes after the base point 9 (PUB must stay last).
- Cert (125 bytes): X.509 v1, no extensions, compressed EC point, and no signature (an empty
  BIT STRING, under the "algorithm" OID 2.5: 1 byte is fine there, 0 bytes breaks curl and
  Firefox; an empty RDN set as the issuer breaks Chrome and Firefox). The issuer name (one attribute: OID 2.5.4 = "";
  Firefox calls a 1-byte OID such as 2.5 bad DER, not overridable) differs from the empty subject,
  so it is not self-signed: clients look for the issuer, don't find it, and never check the
  signature. Chrome: AUTHORITY_INVALID + COMMON_NAME_INVALID, both bypassable; Firefox:
  unknown issuer, overridable. The key is still d = 1/r for the CertificateVerify trick.
- HTTP response: `HTTP/1.1 200\nContent-Length:N\n\n` (bare LFs, no reason phrase).
- No final reduction in Poly1305 (wrong only with ~2^-128 probability).
- SHA-256 pads in place: every buffer passed to sha256 needs 72 spare bytes after the data.

## Tried and rejected
- Dummy cert signature with issuer == subject (both empty): Firefox verifies the
  self-signature and says nssBadCert, which an exception can't override. (A distinct issuer
  name avoids the check: that is what the cert does now.)
- Sharing one multiply routine in the C version, table-driven ChaCha indices: no gain.
- Field registers at address 0 (saved 12 in the old `run`/`x25519`): the M/K constants then
  needed explicit zeroing, which ate the gain; the frame buffer is the better tenant for 0.
- Cert validity as UTCTime without seconds (-4 bytes): curl and Chrome reject it.
- More handshakes in flight in the score test (16 past 32K open): resends back off past the
  60 s timeout while slirp crawls; 4 in flight reaches 64.5K without handshake failures.
- Draining the NE2000 into RAM during handshakes (for bursts): slirp delivers a burst of
  ClientHello segments within one main-loop iteration while holding QEMU's global lock, and
  the guest's port I/O needs that lock, so the ring overflows before the guest can drain it.

## Workflow
Measure after every change; any protocol/cert/HTTP change also needs `./browsers.sh`.
Firefox `--screenshot` hangs forever on error pages, and snap Firefox can't be killed from
here: always use `tools/ffcheck.py`, which quits Firefox through Marionette.
Image compression has not been tried: ask the user before going there.
