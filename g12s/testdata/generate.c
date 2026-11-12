/* Reproduce: cc -Ibee2/include g12s/testdata/generate.c build/bee2/src/libbee2_static.a -lpthread -o /tmp/g12s-fixture && /tmp/g12s-fixture > g12s/testdata/fixtures.txt */
#include <bee2/defs.h>
#include <bee2/crypto/g12s.h>
#include <bee2/crypto/brng.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void dump(const octet *p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",p[i]);putchar(' ');}
static void rnd(void *p,size_t n,void *s){memset(p,0,n);brngCTRStepR(p,n,s);}
static void reset(void *s){octet seed[64];for(int i=0;i<64;i++)seed[i]=i;brngCTRStart(s,seed,seed+32);}
static void last(const octet*p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",p[i]);putchar('\n');}
int main(void){const char *names[]={"1.2.643.2.2.35.0","1.2.643.2.2.35.1","1.2.643.2.2.35.2","1.2.643.2.2.35.3","1.2.643.2.9.1.8.1","1.2.643.7.1.2.1.2.0","1.2.643.7.1.2.1.2.1","1.2.643.7.1.2.1.2.2"};void *rng=calloc(1,brngCTR_keep());if(!rng)return 2;for(int i=0;i<8;i++){g12s_params p;if(g12sParamsStd(&p,names[i])||g12sParamsVal(&p))return 3;printf("%s %u %u ",names[i],p.l,p.n);dump(p.p,68);dump(p.a,68);dump(p.b,68);dump(p.q,64);dump(p.xP,68);dump(p.yP,68);size_t n=p.l*68/512;while(n&&p.p[n-1]==0)n--;size_t k=p.l/8;octet priv[64],pub[136],sig[128],digest[64];for(size_t j=0;j<k;j++)digest[j]=j;reset(rng);if(g12sKeypairGen(priv,pub,&p,rnd,rng))return 4;reset(rng);if(g12sSign(sig,&p,digest,priv,rnd,rng))return 5;if(g12sVerify(&p,digest,sig,pub))return 6;dump(priv,k);dump(pub,2*n);last(sig,2*k);}free(rng);return 0;}
