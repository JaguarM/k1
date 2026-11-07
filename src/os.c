/* Tiny bare-metal HTTPS server.
 * NE2000 (ISA, port 0x300, polled) -> ARP / stateless TCP -> TLS 1.3
 * (TLS_CHACHA20_POLY1305_SHA256, X25519, ecdsa_secp256r1_sha256) -> one static file. */
#include "crypto.h"
#include "../build/gen.h"

#define IO 0x300
#define PSTART 0x46
#define PSTOP 0xC0
#define NC 16
#define RXSZ 16384

static inline void outb(u16 p, u8 v) { __asm__ volatile("outb %0,%1" ::"a"(v), "Nd"(p)); }
static inline u8 inb(u16 p) { u8 v; __asm__ volatile("inb %1,%0" : "=a"(v) : "Nd"(p)); return v; }
static inline void insb(void *d, u32 n) { __asm__ volatile("rep insb" : "+D"(d), "+c"(n) : "d"(IO + 16) : "memory"); }
static inline void outsb(const void *s, u32 n) { __asm__ volatile("rep outsb" : "+S"(s), "+c"(n) : "d"(IO + 16)); }

void *memcpy(void *d, const void *s, u32 n) { return mcpy(d, s, n); }
void *memset(void *d, int c, u32 n) { u8 *p = d; while (n--) *p++ = c; return d; }

#ifdef DEBUG
static void dc(char ch) { while (!(inb(0x3fd) & 0x20)); outb(0x3f8, ch); }
static void ds(const char *s) { while (*s) dc(*s++); }
static void dx(u32 v, int n) { while (n--) dc("0123456789abcdef"[(v >> (n * 4)) & 15]); }
#define D(x) x
#else
#define D(x)
#endif

struct conn {
    u32 st, len;
    u8 kiv[68];
    u8 rx[RXSZ];
};
static struct conn cs[NC];
static u8 fr[2048];             /* rx frame, reused as tx frame */
static u8 tr[8192];             /* handshake transcript */
static u8 ob[20480];            /* tls output */
static u32 on, sseq, sack;
static u8 nxt = PSTART;

/* ServerHello tail: cipher suite, compression, extensions, X25519 share (filled at boot) */
static u8 shtail[51] = {0x13, 0x03, 0x00, 0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
                        0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
                        9}; /* base point; replaced by our public key at boot */

/* sized without the NUL terminator */
static const char L_der[9] = "\x20\x07" "derived", L_shts[14] = "\x20\x0c" "s hs traffic",
                  L_sats[14] = "\x20\x0c" "s ap traffic", L_fin[10] = "\x20\x08" "finished";

static u32 be16(const u8 *p) { return p[0] << 8 | p[1]; }

static void nic_send(u32 len)
{
    outb(IO + 8, 0); outb(IO + 9, 0x40); outb(IO + 11, 6);
    outsb(fr, len);
    outb(IO + 5, len); outb(IO + 6, len >> 8); outb(IO, 4);
}

/* Internet checksum, summed little-endian (result is stored as-is); p[n] must be 0 if n is odd */
static u16 csum(const u8 *p, u32 n)
{
    u32 s = 0, i;
    for (i = 0; i < n; i += 2) s += *(u16u *)(p + i);
    s = (s & 0xffff) + (s >> 16);
    return ~(s + (s >> 16));
}

static __attribute__((noinline)) void tcp_out(u8 fl, const u8 *d, u32 n)
{
    u32 tl = 20 + n;
    mcpy(fr + 54, d, n);
    fr[54 + n] = 0;
    W32(fr + 22, 0x600 | BS(tl)); /* TCP pseudo header built in place over TTL..checksum */
    W32(fr + 38, BS(sseq));
    W32(fr + 42, BS(sack));
    W32(fr + 46, 0x400050 | fl << 8); /* data offset 5, flags, window 0x4000 */
    W32(fr + 50, 0);
    *(u16u *)(fr + 50) = csum(fr + 22, 12 + tl);
    W32(fr + 14, 0x45 | BS(tl + 20)); /* version/IHL, TOS, total length */
    W32(fr + 22, 0x0640); /* TTL 64, proto TCP, checksum 0 */
    *(u16u *)(fr + 24) = csum(fr + 14, 20);
    nic_send(34 + tl);
    sseq += n;
}

static u8 z[32], eh[32], d[32], th[32];

static void thash(u8 *end) { sha256(th, tr, end - tr); } /* transcript hash so far */

/* next key-schedule stage: out = HKDF-Extract(Derive-Secret(prev, "derived", ""), ikm) */
static void stage(u8 *out, const u8 *prev, const u8 *ikm)
{
    expand(d, prev, L_der, eh);
    hmac(out, d, ikm, 32);
}

static void handshake(struct conn *c, const u8 *ch, u32 n)
{
    static u8 es[32], hs[32], ts[32], k[68], sec[32], s[33];
    static u8 cv[192]; /* 130 bytes + room for sha256 padding */
    u8 *p, *enc, *q;
    const u8 *ks = ch;
    u32 sl = ch[38], ql, i;

    while (R32(ks) != 0x20001d00) ks++; /* X25519 key share entry: 00 1d 00 20 */
    x25519(sec, ks + 4);

    mcpy(tr, ch, n);
    p = tr + n; /* ServerHello: reuse CH prefix (random + session id echo) */
    mcpy(p, ch, 39 + sl);
    W32(p, 2 | (86 + sl) << 24);
    mcpy(p + 39 + sl, shtail, 51);
    W32(ob, 0x030316);
    ob[4] = 90 + sl;
    mcpy(ob + 5, p, 90 + sl);
    on = 95 + sl;
    p += 90 + sl;

    sha256(eh, cv, 0);
    hmac(es, z, z, 32);
    stage(hs, es, sec);
    thash(p);
    expand(ts, hs, L_shts, th);
    keys(k, ts);

    enc = p;
    mcpy(p, eecert, sizeof eecert);
    p += sizeof eecert;

    /* CertificateVerify: ECDSA with k=1, d=1/r  =>  s = SHA256(msg) + 1 */
    thash(p);
    memset(cv, 0x20, 64);
    mcpy(cv + 64, "TLS 1.3, server CertificateVerify", 34);
    mcpy(cv + 98, th, 32);
    sha256(s + 1, cv, 130); /* s[0] stays 0: room for a DER sign byte */
    for (i = 32; !++s[i]; i--);
    for (q = s, ql = 33; !q[0] && !(q[1] & 0x80); q++, ql--);
    mcpy(p, cvt, 46); /* 0f 00 00 L | 04 03 | 00 L | 30 L 02 20 <r> 02 L */
    p[3] = 42 + ql; p[7] = 38 + ql; p[9] = 36 + ql; p[45] = ql;
    mcpy(p + 46, q, ql);
    p += 46 + ql;

    /* Finished */
    expand(d, ts, L_fin, 0);
    thash(p);
    W32(p, 0x20000014);
    hmac(p + 4, d, th, 32);
    p += 36;
    *p = 0x16;
    on += seal(ob + on, enc, p + 1 - enc, k, 0);

    /* application traffic keys (server side only; we never decrypt) */
    thash(p);
    stage(es, hs, z);
    expand(ts, es, L_sats, th);
    keys(c->kiv, ts);
}

static void tcp(void)
{
    u8 *t = fr + 34;
    u32 doff = t[12] >> 2; /* low nibble (reserved bits) is 0 */
    u32 plen = be16(fr + 16) - 20 - doff;
    u8 fl = t[13];
    struct conn *c = &cs[t[1] & (NC - 1)];
    u32 i, rl;

    D(ds("\nseg port=");dx(be16(t),4);ds(" fl=");dx(fl,2);ds(" len=");dx(plen,4);)
    sseq = BS(R32(t + 8));
    sack = BS(R32(t + 4)) + plen + ((fl >> 1) & 1);
    if (fl & 2) c->st = c->len = 0;
    mcpy(c->rx + c->len, t + doff, plen);
    c->len += plen;

    /* Reply in place: swap IPs and ports. The Ethernet addresses are left as received
     * (dst = us, src = slirp): slirp never looks at them. */
    i = R32(fr + 26);
    W32(fr + 26, R32(fr + 30));
    W32(fr + 30, i);
    W32(t, R32(t) >> 16 | R32(t) << 16);

    on = 0;
    /* consume every complete TLS record at the front of the buffer */
    while (c->len >= 5 && c->len >= (rl = be16(c->rx + 3) + 5)) {
        D(ds(" rec ");dx(c->rx[0],2);ds("/");dx(rl,4);ds(" st=");dx(c->st,2);)
        if (!c->st) {
            handshake(c, c->rx + 5, rl - 5);
            c->st = 1;
        } else if (c->rx[0] == 23 && ++c->st > 2) {
            on = seal(ob, resp, sizeof resp, c->kiv, c->st - 3);
        }
        mcpy(c->rx, c->rx + rl, c->len -= rl);
    }

    /* answer SYNs and data (pure ACKs get no reply): SYN|ACK|PSH, or ACK|PSH with
     * whatever TLS output we have, in <= 1400-byte segments (an empty one is a plain ACK) */
    if (plen || (fl & 2))
        for (i = 0; tcp_out(0x18 | (fl & 2), ob + i, on - i < 1400 ? on - i : 1400), (i += 1400) < on;);
}


/* NE2000 init as (register, value): ring PSTART/PSTOP, TX page, promiscuous,
 * page 1: CURR = PSTART, back to page 0 */
static const u8 nicinit[] = {1, PSTART, 2, PSTOP, 4, 0x40, 12, 0x10, 0, 0x40, 7, PSTART, 0, 0};

void kmain(void)
{
    u8 h[4];
    u32 i;
    x25519(shtail + 19, shtail + 19); /* our public key = X25519(priv, 9) */

    for (i = 0; i < sizeof nicinit; i += 2) outb(IO + nicinit[i], nicinit[i + 1]);

    /* Announce once: unsolicited ARP reply "10.0.2.15 is at 00:00:00:00:00:00".
     * slirp files it in its ARP table, so we never have to answer ARP requests. */
    *(u16u *)(fr + 12) = 0x0608;
    fr[21] = 2;
    W32(fr + 28, 0x0f02000a);
    nic_send(42);

    for (;;) {
        u8 cur;
        outb(IO, 0x40); cur = inb(IO + 7); outb(IO, 0);
        if (cur == nxt) continue;
        outb(IO + 8, 0); outb(IO + 9, nxt);
        insb(h, 4); /* NE2000 header: status, next page, length (incl. header) */
        insb(fr, (h[2] | h[3] << 8) - 4);
        nxt = h[1];
        outb(IO + 3, nxt);

        if (!fr[13]) tcp(); /* IPv4 (slirp also sends IPv6 RAs and ARP requests) */
    }
}
