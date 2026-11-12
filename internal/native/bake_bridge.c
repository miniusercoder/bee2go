#include "bake_bridge.h"
extern err_t bee2go_validate_certificate(octet*,bign_params*,octet*,size_t,uintptr_t);
static _Thread_local uintptr_t bee2go_cert_handle;
uintptr_t bee2go_cert_scope(uintptr_t h){uintptr_t old=bee2go_cert_handle;bee2go_cert_handle=h;return old;}
err_t bee2go_certval(octet*pub,const bign_params*p,const octet*data,size_t n){if(!bee2go_cert_handle)return ERR_BAD_CERT;return bee2go_validate_certificate(pub,(bign_params*)p,(octet*)data,n,bee2go_cert_handle);}
err_t bee2go_bake_start(int kind,void*s,const bign_params*p,const bake_settings*st,const octet*secret,size_t n,const bake_cert*c,uintptr_t h){
 uintptr_t old=bee2go_cert_scope(h);err_t rc;
 switch(kind){case 1:rc=bakeBMQVStart(s,p,st,secret,c);break;case 2:rc=bakeBSTSStart(s,p,st,secret,c);break;case 3:rc=bakeBPACEStart(s,p,st,secret,n);break;case 4:rc=btokBAuthCTStart(s,p,st,secret,c);break;case 5:rc=btokBAuthTStart(s,p,st,secret,c);break;default:rc=ERR_BAD_INPUT;}
 bee2go_cert_scope(old);return rc;
}
err_t bee2go_bake_step(int kind,int step,octet*out,const octet*in,size_t n,const bake_cert*peer,void*s,uintptr_t h){
 uintptr_t old=bee2go_cert_scope(h);err_t rc=ERR_BAD_INPUT;
 if(kind==1){switch(step){case 2:rc=bakeBMQVStep2(out,s);break;case 3:rc=bakeBMQVStep3(out,in,peer,s);break;case 4:rc=bakeBMQVStep4(out,in,peer,s);break;case 5:rc=bakeBMQVStep5(in,s);break;case 7:rc=bakeBMQVStepG(out,s);break;}}
 if(kind==2){switch(step){case 2:rc=bakeBSTSStep2(out,s);break;case 3:rc=bakeBSTSStep3(out,in,s);break;case 4:rc=bakeBSTSStep4(out,in,n,bee2go_certval,s);break;case 5:rc=bakeBSTSStep5(in,n,bee2go_certval,s);break;case 7:rc=bakeBSTSStepG(out,s);break;}}
 if(kind==3){switch(step){case 2:rc=bakeBPACEStep2(out,s);break;case 3:rc=bakeBPACEStep3(out,in,s);break;case 4:rc=bakeBPACEStep4(out,in,s);break;case 5:rc=bakeBPACEStep5(out,in,s);break;case 6:rc=bakeBPACEStep6(in,s);break;case 7:rc=bakeBPACEStepG(out,s);break;}}
 if(kind==4){switch(step){case 2:rc=btokBAuthCTStep2(out,peer,s);break;case 4:rc=btokBAuthCTStep4(out,in,s);break;case 7:rc=btokBAuthCTStepG(out,s);break;}}
 if(kind==5){switch(step){case 3:rc=btokBAuthTStep3(out,in,s);break;case 5:rc=btokBAuthTStep5(in,n,bee2go_certval,s);break;case 7:rc=btokBAuthTStepG(out,s);break;}}
 bee2go_cert_scope(old);return rc;
}
