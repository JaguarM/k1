/* Minimal crypto for a TLS 1.3 server: SHA-256, HMAC, HKDF-Expand-Label,
 * X25519 (fixed scalar 2^254), ChaCha20-Poly1305 seal.
 * Nothing here is constant-time or hardened. */
#ifndef CRYPTO_H
#define CRYPTO_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef u32 __attribute__((may_alias, aligned(1))) u32u; /* unaligned word access */
typedef u16 __attribute__((may_alias, aligned(1))) u16u;
#define R32(p) (*(u32u *)(p))
#define W32(p, v) (*(u32u *)(p) = (v))
#define BS(x) __builtin_bswap32(x)

static void *mcpy(void *d, const void *s, u32 n)
{
    u8 *a = d;
    const u8 *b = s;
    while (n--) *a++ = *b++;
    return d;
}

/* ---------------- SHA-256 (one-shot) ---------------- */
static const u32 K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static const u32 H256[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

static u32 ror(u32 x, int n) { return (x >> n) | (x << (32 - n)); }

/* Hashes m[0..n). The padding is written in place, so m[n .. n+72) gets clobbered.
 * out may alias m (it is written last). */
static void sha256(u8 *out, u8 *m, u32 n)
{
    u32 h[8], w[64], v[8], i, j;
    u8 *e = m + ((n + 72) & ~63u);
    for (i = 0; i < 8; i++) h[i] = H256[i];
    for (i = n; m + i < e; i++) m[i] = 0;
    m[n] = 0x80;
    W32(e - 4, BS(n << 3));
    for (; m < e; m += 64) {
        for (i = 0; i < 16; i++) w[i] = BS(R32(m + 4 * i));
        for (i = 16; i < 64; i++) {
            u32 s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
            u32 s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        for (i = 0; i < 8; i++) v[i] = h[i];
        for (i = 0; i < 64; i++) {
            u32 t1 = v[7] + (ror(v[4], 6) ^ ror(v[4], 11) ^ ror(v[4], 25)) +
                     ((v[4] & v[5]) ^ (~v[4] & v[6])) + K256[i] + w[i];
            u32 t2 = (ror(v[0], 2) ^ ror(v[0], 13) ^ ror(v[0], 22)) +
                     ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
            for (j = 7; j; j--) v[j] = v[j - 1];
            v[4] += t1;
            v[0] = t1 + t2;
        }
        for (i = 0; i < 8; i++) h[i] += v[i];
    }
    for (i = 0; i < 8; i++) W32(out + 4 * i, BS(h[i]));
}

/* HMAC-SHA256 with a 32-byte key, message up to 96 bytes */
static void hmac(u8 *out, const u8 *k, const u8 *m, u32 n) /* b also holds sha256 padding */
{
    u8 b[64 + 96];
    u32 i;
    for (i = 0; i < 64; i++) b[i] = (i < 32 ? k[i] : 0) ^ 0x36;
    mcpy(b + 64, m, n);
    sha256(b + 64, b, 64 + n);
    for (i = 0; i < 64; i++) b[i] ^= 0x36 ^ 0x5c;
    sha256(out, b, 96);
}

/* HKDF-Expand-Label. lab = { output length, label length, label }; "tls13 " is prepended.
 * ctx is a 32-byte hash or 0 for empty context. Always writes 32 bytes. */
static const char tls13[6] = "tls13 ", sigma[16] = "expand 32-byte k", L_key[5] = "\x20\x03key",
                  L_iv[4] = "\x0c\x02iv";
static void expand(u8 *out, const u8 *sec, const char *lab, const u8 *ctx)
{
    u8 info[64], *p = info;
    *p++ = 0;
    *p++ = lab[0];
    *p++ = lab[1] + 6;
    mcpy(p, tls13, 6);
    mcpy(p + 6, lab + 2, lab[1]);
    p += lab[1] + 6;
    *p++ = ctx ? 32 : 0;
    if (ctx) {
        mcpy(p, ctx, 32);
        p += 32;
    }
    *p++ = 1;
    hmac(out, sec, info, p - info);
}

/* kiv = key (32) | 4 spare bytes (ChaCha block counter slot) | iv (12): the ChaCha
 * state words 4..15. Needs 68 bytes (expand always writes 32). */
static void keys(u8 *kiv, const u8 *sec)
{
    expand(kiv, sec, L_key, 0);
    expand(kiv + 36, sec, L_iv, 0);
}

/* ---------------- X25519, scalar fixed to 2^254 ---------------- */
/* field elements: 32 limbs of 8 bits stored in u32 (djb's "ref" style) */
static void fcarry(u32 *a)
{
    u32 j, u = 0;
    for (j = 0; j < 31; j++) { u += a[j]; a[j] = u & 255; u >>= 8; }
    u += a[31]; a[31] = u & 127; u = 19 * (u >> 7);
    for (j = 0; j < 31; j++) { u += a[j]; a[j] = u & 255; u >>= 8; }
    a[31] += u;
}
static void fadd(u32 *o, const u32 *a, const u32 *b)
{
    u32 j;
    for (j = 0; j < 32; j++) o[j] = a[j] + b[j];
    fcarry(o);
}
static void fsub(u32 *o, const u32 *a, const u32 *b) /* a + 2p - b */
{
    u32 j;
    for (j = 0; j < 32; j++) o[j] = a[j] + 0x1fe - b[j];
    o[0] -= 0x24;
    o[31] -= 0x100;
    fcarry(o);
}
static void fmul(u32 *o, const u32 *a, const u32 *b)
{
    u32 t[32], i, j;
    for (i = 0; i < 32; i++) {
        u32 u = 0;
        for (j = 0; j < 32; j++) {
            u32 p = a[j] * b[(i - j) & 31];
            u += j > i ? 38 * p : p;
        }
        t[i] = u;
    }
    for (i = 0; i < 32; i++) o[i] = t[i];
    fcarry(o);
}

/* out = X25519(k, in) where k clamps to 2^254 (i.e. private key bytes all zero):
 * that is just 254 doublings, no ladder needed. */
static void x25519(u8 *out, const u8 *in)
{
    static u32 x[32], z[32], a[32], b[32], e[32];
    int i, j;
    for (i = 0; i < 32; i++) x[i] = in[i], z[i] = !i;
    for (i = 0; i < 254; i++) {
        fadd(a, x, z);
        fsub(b, x, z);
        fmul(a, a, a);
        fmul(b, b, b);
        fsub(e, a, b);
        fmul(x, a, b);
        for (j = 0; j < 32; j++) z[j] = e[j] * 121665;
        fcarry(z);
        fadd(z, z, a);
        fmul(z, z, e);
    }
    for (i = 0; i < 32; i++) a[i] = z[i];
    for (i = 253; i >= 0; i--) {
        fmul(a, a, a);
        if (i != 2 && i != 4) fmul(a, a, z);
    }
    fmul(x, x, a);
    for (i = 0; i < 32; i++) out[i] = x[i];
}

/* ---------------- ChaCha20 ---------------- */
static u32 rol(u32 x, int n) { return (x << n) | (x >> (32 - n)); }
static void chacha(u32 *o, const u32 *in)
{
    u32 x[16], i;
    for (i = 0; i < 16; i++) x[i] = in[i];
    for (i = 0; i < 80; i++) {
        u32 s = (i >> 2) & 1, a = i & 3;
        u32 b = 4 + ((a + s) & 3), c = 8 + ((a + 2 * s) & 3), d = 12 + ((a + 3 * s) & 3);
        x[a] += x[b]; x[d] = rol(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = rol(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = rol(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = rol(x[b] ^ x[c], 7);
    }
    for (i = 0; i < 16; i++) o[i] = x[i] + in[i];
}

/* ---------------- Poly1305 over whole 16-byte blocks ---------------- */
static void poly1305(u8 *tag, const u8 *m, u32 nb, const u8 *k)
{
    u32 r[17], h[17], x[17], i, j, u;
    for (j = 0; j < 17; j++) /* r = clamped k[0..16) */
        h[j] = 0, r[j] = j > 15 ? 0 : k[j] & ((j & 3) == 3 ? 15 : (j & 3) || !j ? 255 : 252);
    while (nb--) {
        for (j = 0; j < 16; j++) h[j] += m[j];
        h[16] += 1;
        m += 16;
        for (i = 0; i < 17; i++) {
            x[i] = 0;
            for (j = 0; j < 17; j++)
                x[i] += h[j] * (j <= i ? r[i - j] : 320 * r[i + 17 - j]);
        }
        u = 0;
        for (j = 0; j < 16; j++) { u += x[j]; h[j] = u & 255; u >>= 8; }
        u += x[16]; h[16] = u & 3; u = 5 * (u >> 2);
        for (j = 0; j < 16; j++) { u += h[j]; h[j] = u & 255; u >>= 8; }
        h[16] += u;
    }
    u = 0;
    for (j = 0; j < 16; j++) { u += h[j] + k[16 + j]; tag[j] = u; u >>= 8; }
}

/* TLS 1.3 record seal. m[n-1] must already hold the inner content type; kiv as from keys().
 * Writes header|ciphertext|tag to o, returns record length. */
static u8 sb[20480]; /* poly1305 input scratch: header block | ciphertext | lengths */
static u32 seal(u8 *o, const u8 *m, u32 n, const u8 *kiv, u32 seq)
{
    u32 st[16], ks[16], pk[16], i, L = n + 16, pn = (n + 15) & ~15u;
    mcpy(st, sigma, 16);
    mcpy(st + 4, kiv, 48);
    st[12] = 0;
    st[15] ^= BS(seq);
    W32(o, 0x030317 | (L >> 8) << 24);
    o[4] = L;
    chacha(pk, st);
    for (i = 0; i < pn + 32; i++) sb[i] = i < 5 ? o[i] : 0;
    for (i = 0; i < n; i++) {
        if (!(i & 63)) { st[12]++; chacha(ks, st); }
        sb[16 + i] = m[i] ^ ((u8 *)ks)[i & 63];
    }
    sb[16 + pn] = 5;
    W32(sb + 24 + pn, n);
    poly1305(o + 5 + n, sb, pn / 16 + 2, (u8 *)pk);
    mcpy(o + 5, sb + 16, n);
    return n + 21;
}

#endif
