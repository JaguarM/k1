/* Host harness for the asm crypto (src/os.asm built with -DHOST): prints the same lines as
 * test_crypto.c so test/test_crypto.py can check them. Build: gcc -m32 -no-pie. */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

typedef unsigned char u8;
typedef unsigned int u32;

#define ASMCALL(fn, ...) __asm__ volatile("call " #fn : __VA_ARGS__ : : "memory", "cc")

static void sha(u8 *out, u8 *m, u32 n) { ASMCALL(sha256, "+D"(out), "+S"(m), "+c"(n)); }
static void hm(u8 *out, const u8 *k, const u8 *m, u32 n) { ASMCALL(hmac, "+D"(out), "+b"(k), "+S"(m), "+c"(n)); }
static void ex(u8 *out, const u8 *sec, const char *lab, const u8 *ctx) { ASMCALL(expand, "+D"(out), "+b"(sec), "+S"(lab), "+d"(ctx)); }
static u32 sl(u8 *o, const u8 *m, u32 n, const u8 *kiv, u32 seq)
{
    u8 *e = o;
    ASMCALL(seal, "+D"(e), "+S"(m), "+c"(n), "+b"(kiv), "+d"(seq));
    return e - o;
}

static void hex(const char *tag, const u8 *p, u32 n)
{
    printf("%s ", tag);
    while (n--) printf("%02x", *p++);
    printf("\n");
}

int main(void)
{
    static u8 m[2000], out[4096], tmp[2100];
    u8 h[32], kiv[68] = {0};
    u32 i, lens[] = {0, 3, 55, 56, 63, 64, 119, 1000, 1999};
    if (mmap((void *)0x200000, 0x100000, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0) != (void *)0x200000) {
        perror("mmap");
        return 1;
    }
    __asm__ volatile("call shaconst" ::: "memory", "cc");
    for (i = 0; i < sizeof m; i++) m[i] = i * 7 + 3;
    for (i = 0; i < sizeof lens / sizeof *lens; i++) {
        char t[32];
        memcpy(tmp, m, lens[i]);
        sha(h, tmp, lens[i]);
        sprintf(t, "sha%u", lens[i]);
        hex(t, h, 32);
    }
    hm(h, m, m + 32, 50);
    hex("hmac", h, 32);
    ex(h, m, "\x20\x07" "derived", m + 100);
    hex("expand", h, 32);
    for (i = 0; i < 32; i++) kiv[i] = m[300 + i], kiv[36 + i] = m[400 + i];
    for (i = 0; i < 3; i++) {
        u32 n = (u32[]){1, 100, 1500}[i], L = sl(out, m, n, kiv, i * 77);
        char t[32];
        sprintf(t, "seal%u_%u", n, i * 77);
        hex(t, out, L);
    }
    return 0;
}
