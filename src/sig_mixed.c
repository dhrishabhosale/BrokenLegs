#include <stdint.h>
// Mixed widths, 16-bit result.  sig: u8,u16,u32->u16
#ifndef SH
#define SH 7
#endif
uint16_t lineage_f(uint8_t a, uint16_t b, uint32_t c) {
#ifdef REFACTOR
    uint32_t x = ((uint32_t)a << 8) + a + b;      // a*257 + b
    x = x ^ (c >> SH);
    x = (x >> 29) | (x << 3);
    x = x + 0x9E37u * c;
    return (uint16_t)((x >> 16) ^ x);
#else
    uint32_t x = (uint32_t)a * 257u + b;
    x ^= c >> SH; x = (x << 3) | (x >> 29); x += c * 0x9E37u;
    return (uint16_t)(x ^ (x >> 16));
#endif
}
