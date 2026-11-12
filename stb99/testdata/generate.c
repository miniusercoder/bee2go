/* cc -Ibee2/include stb99/testdata/generate.c build/bee2/src/libbee2_static.a -lpthread -o /tmp/stb99-fixture; /tmp/stb99-fixture > stb99/testdata/fixtures.txt */
#include <bee2/defs.h>
#include <bee2/crypto/stb99.h>
#include <stdio.h>
#include <string.h>
static void dump(const octet*p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",p[i]);putchar(' ');}
static void last(const octet*p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",p[i]);putchar('\n');}
int main(int argc,char**argv){const size_t levels[]={638,766,1022,1118,1310,1534,1790,2046,2334,2462};const char*names[]={"test","1.2.112.0.2.0.1176.2.3.3.1","1.2.112.0.2.0.1176.2.3.6.1","1.2.112.0.2.0.1176.2.3.10.1"};if(argc>1){stb99_seed s={0};stb99_params p;s.l=766;if(stb99SeedAdj(&s)||stb99ParamsGen(&p,&s)||stb99ParamsVal(&p))return 5;printf("%zu %zu ",p.l,p.r);dump(p.p,308);dump(p.q,33);dump(p.a,308);last(p.d,308);return 0;}(void)argv;
 for(size_t i=0;i<sizeof(levels)/sizeof(levels[0]);i++){stb99_seed s={0};s.l=levels[i];if(stb99SeedAdj(&s)||stb99SeedVal(&s))return 1;printf("S %zu ",s.l);for(int j=0;j<31;j++)printf("%u ",s.zi[j]);for(int j=0;j<18;j++)printf("%zu ",s.di[j]);for(int j=0;j<10;j++)printf("%zu%s",s.ri[j],j==9?"":" ");putchar('\n');}for(size_t i=0;i<4;i++){stb99_params p;stb99_seed s;if(stb99ParamsStd(&p,&s,names[i])||stb99ParamsVal(&p)||stb99SeedVal(&s))return 2;printf("P %s %zu %zu ",names[i],p.l,p.r);dump(p.p,308);dump(p.q,33);dump(p.a,308);last(p.d,308);}return 0;}
