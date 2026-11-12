#ifndef BEE2GO_KAT_BRIDGE_H
#define BEE2GO_KAT_BRIDGE_H
#include <bee2/defs.h>
err_t bee2go_kat_bign(octet priv[32], octet pub[64]);
err_t bee2go_kat_bake_dh(octet out[64], const octet priv[32]);
err_t bee2go_kat_bpace(octet m1[16], octet m2[80], octet m3[72], octet m4[8], octet ka[32], octet kb[32], const octet seeda[48], const octet seedb[48]);
#endif
