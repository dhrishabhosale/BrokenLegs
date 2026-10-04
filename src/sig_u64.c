#include <stdint.h>
// 64-bit mixer (splitmix-style).  sig: u64,u64->u64
#ifndef K2
#define K2 0x94D049BB133111EBull
#endif
uint64_t lineage_f(uint64_t a, uint64_t b) {
    uint64_t z = a + 0x9E3779B97F4A7C15ull, k = b;
#ifdef REFACTOR
    int n = 4;
    while (n--) { z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull; z = (z ^ (z >> 27)) * K2; z ^= z >> 31; z += k; k = k * 3 + 1; }
#else
    for (int i = 0; i < 4; i++) { z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull; z = (z ^ (z >> 27)) * K2; z ^= z >> 31; z += k; k = k * 3 + 1; }
#endif
    return z;
}
