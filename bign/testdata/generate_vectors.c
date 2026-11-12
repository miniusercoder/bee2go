/* Standalone fixture generator. From repository root:
 * cc -Ibee2/include bign/testdata/generate_vectors.c -Lbuild/bee2/src -lbee2_static -o /tmp/bign-vectors
 * /tmp/bign-vectors > bign/testdata/vectors.txt
 * Output is test-only: public entropy readers supply the 64 seed bytes, not
 * this callback's raw output. Reinitialize the CTR for each random operation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/brng.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/bign96.h>
#include <bee2/crypto/bign128.h>
#include <bee2/crypto/bign192.h>
#include <bee2/crypto/bign256.h>

static void random_bytes(void *out, size_t count, void *state) {
    memset(out, 0, count);
    brngCTRStepR(out, count, state);
}
static void reset(void *state) {
    octet seed[64];
    for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = (octet)i;
    brngCTRStart(state, seed, seed + 32);
}
static void emit(int level, const char *name, const octet *buf, size_t n) {
    printf("%d.%s=", level, name);
    for (size_t i = 0; i < n; ++i) printf("%02x", buf[i]);
    putchar('\n');
}
#define CHECK(expr) do { err_t rc_ = (expr); if (rc_ != ERR_OK) { fprintf(stderr, "%s: %u\n", #expr, (unsigned)rc_); exit(1); } } while (0)
#define PROFILE(op, ...) do { switch (level) { \
 case 96: CHECK(bign96##op(__VA_ARGS__)); break; \
 case 128: CHECK(bign128##op(__VA_ARGS__)); break; \
 case 192: CHECK(bign192##op(__VA_ARGS__)); break; \
 case 256: CHECK(bign256##op(__VA_ARGS__)); break; \
 default: exit(1); } } while(0)
#define FULL(op, ...) do { switch (level) { \
 case 128: CHECK(bign128##op(__VA_ARGS__)); break; \
 case 192: CHECK(bign192##op(__VA_ARGS__)); break; \
 case 256: CHECK(bign256##op(__VA_ARGS__)); break; \
 default: exit(1); } } while(0)
int main(void) {
    void *rng = malloc(brngCTR_keep());
    if (!rng) return 1;
    for (int level = 96; level <= 256; level += (level == 96 ? 32 : 64)) {
        size_t n = (size_t)level / 4, siglen = level == 96 ? 34 : 3*n/2;
        octet priv[64], pub[128], sig[96], sig2[96], token[128], recovered[128];
        const octet *hash = beltH(), *key = beltH(), *header = beltH()+32;
        reset(rng); PROFILE(KeypairGen, priv, pub, random_bytes, rng);
        emit(level,"profile_priv",priv,n); emit(level,"profile_pub",pub,2*n);
        reset(rng); PROFILE(Sign,sig,hash,priv,random_bytes,rng);
        PROFILE(Sign2,sig2,hash,priv,NULL,0);
        PROFILE(Verify,hash,sig,pub); PROFILE(Verify,hash,sig2,pub);
        emit(level,"profile_sign",sig,siglen); emit(level,"profile_sign2",sig2,siglen);
        if(level == 96) continue;
        FULL(DH,recovered,priv,pub,2*n); emit(level,"profile_dh",recovered,2*n);
        reset(rng); FULL(KeyWrap,token,key,18,header,pub,random_bytes,rng);
        FULL(KeyUnwrap,recovered,token,18+n+16,header,priv);
        if(memcmp(recovered,key,18)) return 1;
        emit(level,"profile_wrap",token,18+n+16);
        bign_params params;
        const char *curve=level==128?"1.2.112.0.2.0.34.101.45.3.1":level==192?"1.2.112.0.2.0.34.101.45.3.2":"1.2.112.0.2.0.34.101.45.3.3";
        const char *oid=level==128?"1.2.112.0.2.0.34.101.31.81":level==192?"1.2.112.0.2.0.34.101.77.12":"1.2.112.0.2.0.34.101.77.13";
        octet oidder[32], idpriv[64], idpub[128], cert[96], idsig[96], idsig2[96]; size_t oidlen=sizeof(oidder);
        CHECK(bignParamsStd(&params,curve)); CHECK(bignOidToDER(oidder,&oidlen,oid));
        reset(rng); CHECK(bignKeypairGen(priv,pub,&params,random_bytes,rng));
        emit(level,"generic_priv",priv,n); emit(level,"generic_pub",pub,2*n);
        CHECK(bignDH(recovered,&params,priv,pub,2*n)); emit(level,"generic_dh",recovered,2*n);
        reset(rng); CHECK(bignSign(sig,&params,oidder,oidlen,hash,priv,random_bytes,rng));
        CHECK(bignSign2(sig2,&params,oidder,oidlen,hash,priv,NULL,0));
        CHECK(bignVerify(&params,oidder,oidlen,hash,sig,pub)); CHECK(bignVerify(&params,oidder,oidlen,hash,sig2,pub));
        emit(level,"generic_sign",sig,siglen); emit(level,"generic_sign2",sig2,siglen);
        reset(rng); CHECK(bignKeyWrap(token,&params,key,18,header,pub,random_bytes,rng));
        CHECK(bignKeyUnwrap(recovered,&params,token,18+n+16,header,priv));
        if(memcmp(recovered,key,18))return 1;
        emit(level,"generic_wrap",token,18+n+16);
        const octet *id = beltH()+64;
        CHECK(bignSign2(cert,&params,oidder,oidlen,id,priv,NULL,0));
        CHECK(bignIdExtract(idpriv,idpub,&params,oidder,oidlen,id,cert,pub));
        emit(level,"id_cert",cert,siglen);emit(level,"id_priv",idpriv,n);emit(level,"id_pub",idpub,2*n);
        reset(rng);CHECK(bignIdSign(idsig,&params,oidder,oidlen,id,hash,idpriv,random_bytes,rng));
        CHECK(bignIdSign2(idsig2,&params,oidder,oidlen,id,hash,idpriv,NULL,0));
        CHECK(bignIdVerify(&params,oidder,oidlen,id,hash,idsig,idpub,pub));
        CHECK(bignIdVerify(&params,oidder,oidlen,id,hash,idsig2,idpub,pub));
        emit(level,"id_sign",idsig,siglen);emit(level,"id_sign2",idsig2,siglen);
    }
    free(rng); return 0;
}
