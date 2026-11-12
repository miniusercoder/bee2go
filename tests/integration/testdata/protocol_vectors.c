/* Reproducer for protocol_vectors.txt. Fixed keys/seeds are TEST DATA ONLY.
 * Compile against pinned+patched bee2; no Go wrapper participates. */
#include <bee2/crypto/bake.h>
#include <bee2/crypto/btok.h>
#include <bee2/crypto/brng.h>
#include <bee2/core/mem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void rng(void*b,size_t n,void*s){memset(b,0,n);brngCTRStepR(b,n,s);}
static err_t val(octet*pub,const bign_params*p,const octet*d,size_t n){if(n!=p->l/2)return 514;err_t e=bignPubkeyVal(p,d);if(!e)memcpy(pub,d,n);return e;}
static void hex(const octet*b,size_t n){if(!n){putchar('-');return;}for(size_t i=0;i<n;i++)printf("%02x",b[i]);}
#define OK(f) do{err_t rc=(f);if(rc){fprintf(stderr,"%s:%d code%u\n",__FILE__,__LINE__,(unsigned)rc);return 1;}}while(0)
int main(void){for(int lev=128;lev<=256;lev+=64){bign_params p;char oid[64];snprintf(oid,sizeof(oid),"1.2.112.0.2.0.34.101.45.3.%d",lev/64-1);OK(bignParamsStd(&p,oid));size_t no=lev/4;
 for(int kind=1;kind<=4;kind++){if(lev!=128&&kind!=4)continue;for(int flags=0;flags<4;flags++){if(kind==2&&flags!=3)continue;if(kind==4&&!(flags&1))continue;
 octet a[64]={1},b[64]={2},A[128],B[128],keyA[32],keyB[32];OK(bignPubkeyCalc(A,&p,a));OK(bignPubkeyCalc(B,&p,b));bake_cert ca={A,2*no,val},cb={B,2*no,val};
 void*ra=calloc(1,brngCTR_keep()),*rb=calloc(1,brngCTR_keep());octet ka[32]={1},kb[32]={2},iv[32]={0};brngCTRStart(ra,ka,iv);brngCTRStart(rb,kb,iv);bake_settings sa={0},sb={0};sa.kca=sb.kca=!!(flags&1);sa.kcb=sb.kcb=!!(flags&2);sa.rng=sb.rng=rng;sa.rng_state=ra;sb.rng_state=rb;
 size_t keep=kind==1?bakeBMQV_keep(lev):kind==2?bakeBSTS_keep(lev):kind==3?bakeBPACE_keep(lev):btokBAuthCT_keep(lev);size_t keepa=kind==4?btokBAuthT_keep(lev):keep;void*x=calloc(1,keepa),*y=calloc(1,keep);octet m1[512]={0},m2[512]={0},m3[512]={0},m4[8]={0};size_t n1=0,n2=0,n3=0,n4=0;
 if(kind==1){OK(bakeBMQVStart(x,&p,&sa,a,&ca));OK(bakeBMQVStart(y,&p,&sb,b,&cb));n1=2*no;n2=2*no+((flags&1)?8:0);n3=(flags&2)?8:0;OK(bakeBMQVStep2(m1,y));OK(bakeBMQVStep3(m2,m1,&cb,x));OK(bakeBMQVStep4(m3,m2,&ca,y));if(n3)OK(bakeBMQVStep5(m3,x));OK(bakeBMQVStepG(keyA,x));OK(bakeBMQVStepG(keyB,y));}
 if(kind==2){OK(bakeBSTSStart(x,&p,&sa,a,&ca));OK(bakeBSTSStart(y,&p,&sb,b,&cb));n1=2*no;n2=3*no+ca.len+8;n3=no+cb.len+8;OK(bakeBSTSStep2(m1,y));OK(bakeBSTSStep3(m2,m1,x));OK(bakeBSTSStep4(m3,m2,n2,val,y));OK(bakeBSTSStep5(m3,n3,val,x));OK(bakeBSTSStepG(keyA,x));OK(bakeBSTSStepG(keyB,y));}
 if(kind==3){OK(bakeBPACEStart(x,&p,&sa,(octet*)"password",8));OK(bakeBPACEStart(y,&p,&sb,(octet*)"password",8));n1=no/2;n2=5*no/2;n3=2*no+((flags&2)?8:0);n4=(flags&1)?8:0;OK(bakeBPACEStep2(m1,y));OK(bakeBPACEStep3(m2,m1,x));OK(bakeBPACEStep4(m3,m2,y));OK(bakeBPACEStep5(m4,m3,x));if(n4)OK(bakeBPACEStep6(m4,y));OK(bakeBPACEStepG(keyA,x));OK(bakeBPACEStepG(keyB,y));}
 if(kind==4){OK(btokBAuthTStart(x,&p,&sa,a,&ca));OK(btokBAuthCTStart(y,&p,&sb,b,&cb));n1=5*no/2+16;n2=8+((flags&2)?16:0);n3=(flags&2)?no+cb.len+8:0;OK(btokBAuthCTStep2(m1,&ca,y));OK(btokBAuthTStep3(m2,m1,x));OK(btokBAuthCTStep4(m3,m2,y));if(n3)OK(btokBAuthTStep5(m3,n3,val,x));OK(btokBAuthTStepG(keyA,x));OK(btokBAuthCTStepG(keyB,y));}
 if(memcmp(keyA,keyB,32))return 2;printf("%d %d %d ",kind,lev,flags);hex(m1,n1);putchar(' ');hex(m2,n2);putchar(' ');hex(m3,n3);putchar(' ');hex(m4,n4);putchar(' ');hex(keyA,32);putchar('\n');free(x);free(y);free(ra);free(rb);
 }}}return 0;}
