/* Standalone integration peer: fixed test keys and deterministic test RNG. */
#include <bee2/defs.h>
#include <bee2/core/err.h>
#include <bee2/crypto/bake.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/brng.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static err_t read_frame(size_t *read_count, void *buf, size_t count, void *file) {
    (void)file;
    unsigned char h[4];
    *read_count = 0;
    if (fread(h, 1, 4, stdin) != 4) return ERR_BAD_FILE;
    size_t n = ((size_t)h[0] << 24) | ((size_t)h[1] << 16) | ((size_t)h[2] << 8) | h[3];
    if (n > count || (count != 512 && n != count)) return ERR_BAD_LENGTH;
    if (fread(buf, 1, n, stdin) != n) return ERR_BAD_FILE;
    *read_count = n;
    /* BSTS uses ERR_MAX to mark the end of a variable-length message. */
    return count == 512 && n < count ? ERR_MAX : ERR_OK;
}
static err_t write_frame(size_t *written, const void *buf, size_t count, void *file) {
    (void)file;
    if (count > 65536) return ERR_BAD_LENGTH;
    unsigned char h[4] = {(unsigned char)(count >> 24), (unsigned char)(count >> 16), (unsigned char)(count >> 8), (unsigned char)count};
    *written = 0;
    if (fwrite(h, 1, 4, stdout) != 4 || fwrite(buf, 1, count, stdout) != count || fflush(stdout)) return ERR_BAD_FILE;
    *written = count;
    return ERR_OK;
}
static err_t validate(octet *pub, const bign_params *p, const octet *data, size_t len) {
    if (len != 64) return ERR_BAD_CERT;
    err_t e = bignPubkeyVal(p, data);
    if (e) return e;
    if (pub) memcpy(pub, data, 64);
    return ERR_OK;
}
static void random_bytes(void *buf, size_t count, void *state) {
    memset(buf, 0, count);
    brngCTRStepR(buf, count, state);
}
int main(int argc, char **argv) {
    if (argc != 4 || (strcmp(argv[2], "A") && strcmp(argv[2], "B"))) return 2;
    int role_a = !strcmp(argv[2], "A"), flags = atoi(argv[3]);
    if (flags < 0 || flags > 3) return 2;
    bign_params p;
    err_t e = bignParamsStd(&p, "1.2.112.0.2.0.34.101.45.3.1");
    if (e) goto fail;
    octet a[32] = {1}, b[32] = {2}, pub_a[64], pub_b[64], key[32];
    e = bignPubkeyCalc(pub_a, &p, a); if (e) goto fail;
    e = bignPubkeyCalc(pub_b, &p, b); if (e) goto fail;
    bake_cert ca = {pub_a, sizeof(pub_a), validate}, cb = {pub_b, sizeof(pub_b), validate};
    octet rng_key[32] = {0}, iv[32] = {0}; rng_key[0] = role_a ? 1 : 2;
    void *rng = calloc(1, brngCTR_keep()); if (!rng) return 2;
    brngCTRStart(rng, rng_key, iv);
    bake_settings s = {0}; s.kca = !!(flags & 1); s.kcb = !!(flags & 2); s.rng = random_bytes; s.rng_state = rng;
    if (!strcmp(argv[1], "bmqv")) {
        if (role_a) e = bakeBMQVRunA(key, &p, &s, a, &ca, &cb, read_frame, write_frame, NULL);
        else e = bakeBMQVRunB(key, &p, &s, b, &cb, &ca, read_frame, write_frame, NULL);
    } else if (!strcmp(argv[1], "bsts")) {
        if (role_a) e = bakeBSTSRunA(key, &p, &s, a, &ca, validate, read_frame, write_frame, NULL);
        else e = bakeBSTSRunB(key, &p, &s, b, &cb, validate, read_frame, write_frame, NULL);
    } else if (!strcmp(argv[1], "bpace")) {
        if (role_a) e = bakeBPACERunA(key, &p, &s, (const octet*)"password", 8, read_frame, write_frame, NULL);
        else e = bakeBPACERunB(key, &p, &s, (const octet*)"password", 8, read_frame, write_frame, NULL);
    } else { free(rng); return 2; }
    free(rng);
    if (e) goto fail;
    size_t written; e = write_frame(&written, key, sizeof(key), NULL);
    if (!e) return 0;
fail:
    fprintf(stderr, "bee2 error %u\n", (unsigned)e);
    return 1;
}
