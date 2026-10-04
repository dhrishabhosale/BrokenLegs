// Build with: gcc -DTARGET_SRC='"<file.c>"' ... then strip. The target symbol becomes hidden + noinline.
#include <stdint.h>
#define lineage_f hidden_target
#include TARGET_SRC
#undef lineage_f
#include "decoys.c"
__attribute__((visibility("default"))) uint32_t entry(uint32_t x){
    return hidden_target(x, x+1) ^ decoy_crcish(x, 3) ^ decoy_mix(x, 5) ^ decoy_scale(x, 7) ^ decoy_pick(x, 11);
}
