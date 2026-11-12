#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bee2/crypto/bels.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/brng.h>
static void gen(void *buf,size_t len,void *state){memset(buf,0,len);brngCTRStepR(buf,len,state);}
static void dump(const unsigned char*p,size_t n){for(size_t i=0;i<n;i++)printf("%02X",p[i]);puts("");}
int main(void){unsigned char m[32],keys[5*32],out[5*33];void*s=calloc(1,brngCTR_keep());for(size_t n=16;n<=32;n+=8){belsStdM(m,n,0);for(size_t i=0;i<5;i++)belsStdM(keys+i*n,n,i+1);brngCTRStart(s,beltH()+128,beltH()+160);if(belsShare(out,5,3,n,beltH(),m,keys,gen,s))return 1;dump(out,5*n);brngCTRStart(s,beltH()+128,beltH()+160);if(belsShare2(out,5,3,n,beltH(),gen,s))return 1;dump(out,5*(n+1));}free(s);}
