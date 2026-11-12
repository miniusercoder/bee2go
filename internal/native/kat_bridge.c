#include "kat_bridge.h"
#include <bee2/core/err.h>
#include <bee2/core/mem.h>
#include <bee2/core/prng.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/bake.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/brng.h>
#include <stdlib.h>
#include <string.h>

struct kat_ctr { size_t offset; unsigned char state[]; };
static void kat_ctr_step(void *buf, size_t count, void *state) {
 struct kat_ctr *s = state; octet *dst = buf;
 for (size_t i = 0; i < count; ++i) dst[i] = beltH()[(s->offset++) % 256];
 brngCTRStepR(buf, count, s->state);
}
err_t bee2go_kat_bign(octet priv[32], octet pub[64]) {
 bign_params p; err_t e = bignParamsStd(&p, "1.2.112.0.2.0.34.101.45.3.1");
 if (e) return e;
 size_t n = sizeof(struct kat_ctr) + brngCTR_keep();
 struct kat_ctr *s = calloc(1, n); if (!s) return ERR_OUTOFMEMORY;
 brngCTRStart(s->state, beltH() + 128, beltH() + 192);
 e = bignKeypairGen(priv, pub, &p, kat_ctr_step, s);
 memWipe(s,n); free(s); memWipe(&p,sizeof(p)); return e;
}
err_t bee2go_kat_bake_dh(octet out[64], const octet priv[32]) {
 bign_params p; octet generator[64] = {0};
 err_t e = bignParamsStd(&p, "1.2.112.0.2.0.34.101.45.3.1"); if (e) return e;
 memcpy(generator+32,p.yG,32); e = bakeDH(out,&p,priv,generator,64);
 memWipe(&p,sizeof(p)); return e;
}
err_t bee2go_kat_bpace(octet m1[16], octet m2[80], octet m3[72], octet m4[8], octet ka[32], octet kb[32], const octet seed_a[48], const octet seed_b[48]) {
 bign_params p; bake_settings a={0},b={0}; octet sa[48],sb[48];
 memcpy(sa,seed_a,48); memcpy(sb,seed_b,48);
 size_t rn=prngEcho_keep(), sn=bakeBPACE_keep(128);
 void *ra=calloc(1,rn), *rb=calloc(1,rn), *pa=calloc(1,sn), *pb=calloc(1,sn);
 err_t e=ERR_OUTOFMEMORY;
 if (!ra||!rb||!pa||!pb) goto done;
 e=bignParamsStd(&p,"1.2.112.0.2.0.34.101.45.3.1"); if (e) goto done;
 prngEchoStart(ra,sa,48);prngEchoStart(rb,sb,48);
 a.kca=a.kcb=b.kca=b.kcb=TRUE; a.rng=b.rng=prngEchoStepR; a.rng_state=ra;b.rng_state=rb;
 e=bakeBPACEStart(pa,&p,&a,(const octet*)"8086",4); if(e) goto done;
 e=bakeBPACEStart(pb,&p,&b,(const octet*)"8086",4); if(e) goto done;
 e=bakeBPACEStep2(m1,pb); if(e) goto done;
 e=bakeBPACEStep3(m2,m1,pa); if(e) goto done;
 e=bakeBPACEStep4(m3,m2,pb); if(e) goto done;
 e=bakeBPACEStep5(m4,m3,pa); if(e) goto done;
 e=bakeBPACEStep6(m4,pb); if(e) goto done;
 e=bakeBPACEStepG(ka,pa); if(e) goto done;
 e=bakeBPACEStepG(kb,pb);
done:
 if(ra){memWipe(ra,rn);free(ra);} if(rb){memWipe(rb,rn);free(rb);}
 if(pa){memWipe(pa,sn);free(pa);} if(pb){memWipe(pb,sn);free(pb);}
 memWipe(sa,sizeof(sa));memWipe(sb,sizeof(sb));memWipe(&p,sizeof(p));return e;
}
