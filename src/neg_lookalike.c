#include <stdint.h>
static inline uint32_t rotl(uint32_t x, int r){ return (x << r) | (x >> (32 - r)); }
uint32_t lineage_f(uint32_t a, uint32_t b) {
    uint32_t s = a ^ 0x9E3779B9u;
    uint32_t t = b + 0x85EBCA6Bu;
    for (int i = 0; i < 8; i++) {
        s = rotl(s ^ t, 5) + (0x27D4EB2Fu * (uint32_t)(i + 1));
        t = (t * 0x01000193u) ^ (s >> 4);      // <-- 3 became 4
    }
    return s ^ t;
}
