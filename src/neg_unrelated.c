#include <stdint.h>
uint32_t lineage_f(uint32_t a, uint32_t b) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < 4; i++) { h ^= (a >> (8*i)) & 0xFF; h *= 16777619u; }
    for (int i = 0; i < 4; i++) { h ^= (b >> (8*i)) & 0xFF; h *= 16777619u; }
    return h;
}
