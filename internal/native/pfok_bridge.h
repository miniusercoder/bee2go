#ifndef BEE2GO_PFOK_BRIDGE_H
#define BEE2GO_PFOK_BRIDGE_H
#include <stdint.h>
#include <bee2/crypto/pfok.h>
err_t bee2go_pfok_generate(pfok_params *params, const pfok_seed *seed, uintptr_t handle);
#endif
