#include <stdint.h>
// Same function, plus a semantically-dead loop whose bound depends on the INPUT.
// Symbolic execution forks every iteration -> path explosion -> fallback to differential testing.
static inline uint32_t rotl(uint32_t x, int r){ return (x << r) | (x >> (32 - r)); }
uint32_t lineage_f(uint32_t a, uint32_t b) {
    uint32_t s = a ^ 0x9E3779B9u, t = b + 0x85EBCA6Bu, junk = 0;
    for (int i = 0; i < 8; i++) {
        s = rotl(s ^ t, 5) + (0x27D4EB2Fu * (uint32_t)(i + 1));
        t = (t * 0x01000193u) ^ (s >> 3);
    }
    for (uint32_t j = 0; j < (a & 0xFFFu); j++) junk ^= j * 31u;   // dead work, input-dependent trip count
    (void)junk;
    return s ^ t;
}
