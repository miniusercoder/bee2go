/* cc -Ibee2/include pfok/testdata/generate.c build/bee2/src/libbee2_static.a -lpthread -o /tmp/pfok-fixture; /tmp/pfok-fixture > pfok/testdata/fixtures.txt */
#include <bee2/defs.h>
#include <bee2/crypto/pfok.h>
#include <stdio.h>
#include <string.h>
static void dump(const octet*p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",p[i]);putchar(' ');}
static void last(const octet*p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",p[i]);putchar('\n');}
int main(int argc,char**argv){const size_t levels[]={638,702,766,862,958,1022,1118,1214,1310,1438,1534,1662,1790,1918,2046,2174,2334,2462,2622,2782,2942};const char *names[]={"test","1.2.112.0.2.0.1176.2.3.3.2","1.2.112.0.2.0.1176.2.3.6.2","1.2.112.0.2.0.1176.2.3.10.2"};if(argc>1){pfok_seed s={0};pfok_params p;s.l=766;if(pfokSeedAdj(&s)||pfokParamsGen(&p,&s,0)||pfokParamsVal(&p))return 5;printf("%zu %zu %zu ",p.l,p.r,p.n);dump(p.p,368);last(p.g,368);return 0;}(void)argv;
 for(size_t i=0;i<sizeof(levels)/sizeof(levels[0]);i++){pfok_seed s={0};s.l=levels[i];if(pfokSeedAdj(&s)||pfokSeedVal(&s))return 1;printf("S %zu ",s.l);for(int j=0;j<31;j++)printf("%u ",s.zi[j]);for(int j=0;j<20;j++)printf("%zu%s",s.li[j],j==19?"":" ");putchar('\n');}for(size_t i=0;i<4;i++){pfok_params p;pfok_seed s;if(pfokParamsStd(&p,&s,names[i])||pfokParamsVal(&p)||pfokSeedVal(&s))return 2;printf("P %s %zu %zu %zu ",names[i],p.l,p.r,p.n);dump(p.p,368);last(p.g,368);}return 0;}
