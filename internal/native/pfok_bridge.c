#include "pfok_bridge.h"
extern void bee2go_pfok_progress(uintptr_t handle, const word *q, size_t n, size_t num);
struct pfok_frame { uintptr_t handle; struct pfok_frame *prev; };
static _Thread_local struct pfok_frame *current;
static void progress(const word *q, size_t n, size_t num) {
    bee2go_pfok_progress(current->handle, q, n, num);
}
err_t bee2go_pfok_generate(pfok_params *params, const pfok_seed *seed, uintptr_t handle) {
    struct pfok_frame frame = {handle, current};
    current = &frame;
    err_t result = pfokParamsGen(params, seed, progress);
    current = frame.prev;
    return result;
}
