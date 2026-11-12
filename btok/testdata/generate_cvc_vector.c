#include <stdio.h>
#include <string.h>
#include <bee2/crypto/btok.h>
int main(void){unsigned char key[32]={1},der[512];size_t n=0;btok_cvc_t c={0};strcpy(c.authority,"BYCA0000");strcpy(c.holder,"BYCA0000");unsigned char from[6]={2,2,0,7,0,7},until[6]={9,9,0,7,0,7};memcpy(c.from,from,6);memcpy(c.until,until,6);if(btokCVCWrap(der,&n,&c,key,32))return 1;for(size_t i=0;i<n;i++)printf("%02X",der[i]);puts("");for(size_t i=0;i<c.pubkey_len;i++)printf("%02X",c.pubkey[i]);puts("");}
