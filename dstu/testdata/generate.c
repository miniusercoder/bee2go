/* Reproduce: cc -Ibee2/include dstu/testdata/generate.c build/bee2/src/libbee2_static.a -lpthread -o /tmp/dstu-fixture && /tmp/dstu-fixture > dstu/testdata/fixtures.txt */
#include <bee2/defs.h>
#include <bee2/crypto/dstu.h>
#include <bee2/crypto/brng.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void dump(const octet *p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",p[i]);putchar(' ');}
static void rnd(void *p,size_t n,void *s){memset(p,0,n);brngCTRStepR(p,n,s);}
static void reset(void *s){octet seed[64];for(int i=0;i<64;i++)seed[i]=i;brngCTRStart(s,seed,seed+32);}
static void last(const octet*p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",p[i]);putchar('\n');}
int main(void){void *rng=calloc(1,brngCTR_keep());if(!rng)return 2;for(int i=0;i<10;i++) {char oid[80];sprintf(oid,"1.2.804.2.1.1.1.1.3.1.1.1.2.%d",i);dstu_params p;err_t e=dstuParamsStd(&p,oid);if(e)return 3;printf("%s %u %u %u %u %u %u ",oid,p.p[0],p.p[1],p.p[2],p.p[3],p.A,p.c);dump(p.B,64);dump(p.n,64);dump(p.P,128);
 size_t n=(p.p[0]+7)/8,k=n;while(k&&p.n[k-1]==0)k--;octet point[128],compressed[64],recover[128],priv[64],pub[128],sig[128],digest[32];for(int j=0;j<32;j++)digest[j]=j;reset(rng);if(dstuPointGen(point,&p,rnd,rng))return 4;memcpy(p.P,point,2*n);if(dstuParamsVal(&p)||dstuPointVal(&p,point)||dstuPointCompress(compressed,&p,point)||dstuPointRecover(recover,&p,compressed))return 5;reset(rng);if(dstuKeypairGen(priv,pub,&p,rnd,rng))return 6;reset(rng);if(dstuSign(sig,&p,1024,digest,32,priv,rnd,rng))return 7;if(dstuVerify(&p,1024,digest,32,sig,pub))return 8;dump(point,2*n);dump(compressed,n);dump(recover,2*n);dump(priv,k);dump(pub,2*n);last(sig,128);}free(rng);return 0;}
