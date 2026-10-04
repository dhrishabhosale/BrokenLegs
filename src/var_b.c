#include <stdint.h>
// Same algorithm, disguised by hand: renamed, restructured, rotation via subtraction trick
static uint32_t spin(uint32_t v){ return (v >> 27) | (v << 5); }
uint32_t lineage_f(uint32_t key, uint32_t blob) {
    uint32_t acc = 0x9E3779B9u ^ key;
    uint32_t mix = 0x85EBCA6Bu + blob;
    uint32_t k = 0x27D4EB2Fu;
    int n = 8;
    while (n--) {
        acc = k + spin(mix ^ acc);
        mix = (mix * 16777619u) ^ (acc >> 3);
        k += 0x27D4EB2Fu;
    }
    return mix ^ acc;
}
