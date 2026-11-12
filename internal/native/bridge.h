#ifndef BEE2GO_BRIDGE_H
#define BEE2GO_BRIDGE_H
#include <bee2/defs.h>
#include <bee2/core/err.h>
#include <bee2/core/mem.h>
#include <bee2/crypto/brng.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
void bee2go_random(void* buf, size_t count, void* state);
#endif
