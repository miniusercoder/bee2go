#include "bign_generate.h"
extern err_t bee2go_bign_order(bign_params*,uintptr_t);
extern err_t bee2go_bign_seed(bign_params*,uintptr_t);
static err_t bee2go_bign_calc_adapter(bign_params*p,void*s){return bee2go_bign_order(p,(uintptr_t)s);}
static err_t bee2go_bign_seed_adapter(const bign_params*p,void*s){return bee2go_bign_seed((bign_params*)p,(uintptr_t)s);}
err_t bee2go_bign_generate(bign_params*p,uintptr_t h){return bignParamsGen(p,bee2go_bign_calc_adapter,bee2go_bign_seed_adapter,(void*)h);}
