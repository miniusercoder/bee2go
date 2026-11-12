#include "bridge.h"
void bee2go_random(void* buf, size_t count, void* state) {
    memset(buf, 0, count);
    brngCTRStepR(buf, count, state);
}
