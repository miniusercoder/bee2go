#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bee2/crypto/belt.h>
int main(void){unsigned char b[48];void* s=malloc(beltWBL_keep());if(!s)return 1;memcpy(b,beltH(),48);beltWBLStart(s,beltH()+128,32);beltWBLStepR(b,48,s);beltWBLStepR(b,48,s);for(int i=0;i<48;i++)printf("%02x",b[i]);puts("");free(s);return 0;}
