#include <stdint.h>
// Unrelated helper functions with the same (u32,u32)->u32 signature, so discovery has real decoys to reject.
#define HID __attribute__((visibility("hidden"), noinline))
HID uint32_t decoy_crcish(uint32_t a, uint32_t b){ uint32_t c = a; for (int i=0;i<8;i++) c = (c>>1) ^ (0xEDB88320u & -(c&1u)); return c ^ b; }
HID uint32_t decoy_mix(uint32_t a, uint32_t b){ a ^= b << 13; b ^= a >> 7; a ^= b << 17; return a + b; }
HID uint32_t decoy_scale(uint32_t a, uint32_t b){ return a * 2654435761u + b * 40503u; }
HID uint32_t decoy_pick(uint32_t a, uint32_t b){ return (a > b) ? a - b : b - a; }
