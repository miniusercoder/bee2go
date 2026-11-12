#include "bign_profiles.h"
#define PROFILES(fn, ...) switch(l){case 96:return bign96##fn(__VA_ARGS__);case 128:return bign128##fn(__VA_ARGS__);case 192:return bign192##fn(__VA_ARGS__);case 256:return bign256##fn(__VA_ARGS__);default:return ERR_BAD_PARAMS;}
#define FULL_PROFILES(fn, ...) switch(l){case 128:return bign128##fn(__VA_ARGS__);case 192:return bign192##fn(__VA_ARGS__);case 256:return bign256##fn(__VA_ARGS__);default:return ERR_BAD_PARAMS;}
err_t bee2go_bign_profile_key(int l,octet*a,octet*b,void*rng){PROFILES(KeypairGen,a,b,bee2go_random,rng)}
err_t bee2go_bign_profile_pair(int l,const octet*a,const octet*b){PROFILES(KeypairVal,a,b)}
err_t bee2go_bign_profile_val(int l,const octet*b){PROFILES(PubkeyVal,b)}
err_t bee2go_bign_profile_pub(int l,octet*b,const octet*a){PROFILES(PubkeyCalc,b,a)}
err_t bee2go_bign_profile_sign(int l,octet*sig,const octet*hash,const octet*priv,void*rng){PROFILES(Sign,sig,hash,priv,bee2go_random,rng)}
err_t bee2go_bign_profile_sign2(int l,octet*sig,const octet*hash,const octet*priv,const void*t,size_t n){PROFILES(Sign2,sig,hash,priv,t,n)}
err_t bee2go_bign_profile_verify(int l,const octet*hash,const octet*sig,const octet*pub){PROFILES(Verify,hash,sig,pub)}
err_t bee2go_bign_profile_dh(int l,octet*out,const octet*priv,const octet*pub,size_t n){FULL_PROFILES(DH,out,priv,pub,n)}
err_t bee2go_bign_profile_wrap(int l,octet*out,const octet*key,size_t n,const octet*header,const octet*pub,void*rng){FULL_PROFILES(KeyWrap,out,key,n,header,pub,bee2go_random,rng)}
err_t bee2go_bign_profile_unwrap(int l,octet*out,const octet*token,size_t n,const octet*header,const octet*priv){FULL_PROFILES(KeyUnwrap,out,token,n,header,priv)}
