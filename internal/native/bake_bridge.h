#ifndef BEE2GO_BAKE_BRIDGE_H
#define BEE2GO_BAKE_BRIDGE_H
#include "bridge.h"
#include <bee2/crypto/bake.h>
#include <bee2/crypto/btok.h>
uintptr_t bee2go_cert_scope(uintptr_t handle);
err_t bee2go_certval(octet* pub,const bign_params* p,const octet* data,size_t n);
err_t bee2go_bake_start(int kind,void* state,const bign_params* p,const bake_settings* settings,const octet* secret,size_t secret_len,const bake_cert* cert,uintptr_t handle);
err_t bee2go_bake_step(int kind,int step,octet* out,const octet* in,size_t in_len,const bake_cert* peer,void* state,uintptr_t handle);
#endif
