#include <stdio.h>
#include <stdint.h>
#include <bee2/crypto/botp.h>
int main(void){char otp[16];const unsigned char key[]="key",q[]="12345678";tm_time_t ts[]={-2,INT64_MIN};printf("%zu %d\n",sizeof(tm_time_t),(tm_time_t)-1<0);for(int i=0;i<2;i++){if(botpTOTPRand(otp,8,key,3,ts[i]))return 1;puts(otp);if(botpOCRARand(otp,"OCRA-1:HOTP-HBELT-6:QN08-T1M",key,3,q,8,0,0,0,ts[i]))return 2;puts(otp);}if(botpOCRARand(otp,"OCRA-1:HOTP-HBELT-6:QN08",key,3,q,8,0,0,0,0))return 3;puts(otp);}
