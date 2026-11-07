/* Host-side harness: prints crypto outputs for test/test_crypto.py to check. */
#include <stdio.h>
#include <string.h>
#include "../src/crypto.h"

static void hex(const char *tag, const u8 *p, u32 n)
{
    printf("%s ", tag);
    while (n--) printf("%02x", *p++);
    printf("\n");
}

int main(void)
{
    static u8 m[2000], out[4096];
    u8 h[32], kiv[68], nine[32] = {9};
    u32 i, lens[] = {0, 3, 55, 56, 63, 64, 119, 1000, 1999};
    for (i = 0; i < sizeof m; i++) m[i] = i * 7 + 3;
    for (i = 0; i < sizeof lens / sizeof *lens; i++) {
        char t[32];
        static u8 tmp[2100];
        memcpy(tmp, m, lens[i]);
        sha256(h, tmp, lens[i]);
        sprintf(t, "sha%u", lens[i]);
        hex(t, h, 32);
    }
    hmac(h, m, m + 32, 50);
    hex("hmac", h, 32);
    expand(h, m, "\x20\x07" "derived", m + 100);
    hex("expand", h, 32);
    x25519(h, nine);
    hex("x9", h, 32);
    m[231] &= 127; /* real clients send canonical u-coordinates */
    x25519(h, m + 200);
    hex("xm", h, 32);
    for (i = 0; i < 32; i++) kiv[i] = m[300 + i], kiv[36 + i] = m[400 + i];
    for (i = 0; i < 3; i++) {
        u32 n = (u32[]){1, 100, 1500}[i], L = seal(out, m, n, kiv, i * 77);
        char t[32];
        sprintf(t, "seal%u_%u", n, i * 77);
        hex(t, out, L);
    }
    return 0;
}
