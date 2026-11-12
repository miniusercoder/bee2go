#include <stdio.h>
#include <bee2/crypto/bpki.h>
#include <bee2/crypto/belt.h>
static void dump(const unsigned char*p,size_t n){for(size_t i=0;i<n;i++)printf("%02X",p[i]);puts("");}
int main(void){unsigned char der[1024],share[33];size_t n;const unsigned char pwd[]={'z','e','d'};size_t keys[]={24,32,48,64}, salts[]={24,32,40,48};for(int j=0;j<4;j++){if(bpkiPrivkeyWrap(der,&n,beltH(),keys[j],pwd,3,beltH()+salts[j],10000+j))return 1;dump(der,n);}for(int j=0;j<3;j++){size_t k=16+8*j;share[0]=j==2?16:j+1;for(size_t i=0;i<k;i++)share[i+1]=beltH()[i];if(bpkiShareWrap(der,&n,share,k+1,pwd,3,beltH()+64,10003+j))return 1;dump(der,n);}}
