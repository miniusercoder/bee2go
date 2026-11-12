#ifndef BEE2GO_BIGN_PROFILES_H
#define BEE2GO_BIGN_PROFILES_H
#include "bridge.h"
#include <bee2/crypto/bign96.h>
#include <bee2/crypto/bign128.h>
#include <bee2/crypto/bign192.h>
#include <bee2/crypto/bign256.h>
err_t bee2go_bign_profile_key(int l,octet* a,octet* b,void* rng);
err_t bee2go_bign_profile_pair(int l,const octet* a,const octet* b);
err_t bee2go_bign_profile_val(int l,const octet* b);
err_t bee2go_bign_profile_pub(int l,octet* b,const octet* a);
err_t bee2go_bign_profile_sign(int l,octet* sig,const octet* hash,const octet* priv,void* rng);
err_t bee2go_bign_profile_sign2(int l,octet* sig,const octet* hash,const octet* priv,const void* t,size_t n);
err_t bee2go_bign_profile_verify(int l,const octet* hash,const octet* sig,const octet* pub);
err_t bee2go_bign_profile_dh(int l,octet* out,const octet* priv,const octet* pub,size_t n);
err_t bee2go_bign_profile_wrap(int l,octet* out,const octet* key,size_t n,const octet* header,const octet* pub,void* rng);
err_t bee2go_bign_profile_unwrap(int l,octet* out,const octet* token,size_t n,const octet* header,const octet* priv);
#endif
