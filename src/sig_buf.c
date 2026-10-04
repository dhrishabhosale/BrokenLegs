#include <stdint.h>
#include <stddef.h>
// Byte-buffer hash.  sig: buf16,len16->u32   (pointer to 16 bytes, length 16)
#ifndef OFFSET
#define OFFSET 0x811C9DC5u
#endif
#ifndef SKIP
#define SKIP 0            // number of trailing bytes ignored (bug / tampering)
#endif
uint32_t lineage_f(const uint8_t *p, size_t n) {
    uint32_t h = OFFSET;
#ifdef REFACTOR
    const uint8_t *e = p + n - SKIP;
    while (p != e) { h ^= *p++; h *= 0x01000193u; h = (h << 5) | (h >> 27); }
#else
    for (size_t i = 0; i < n - SKIP; i++) { h ^= p[i]; h *= 0x01000193u; h = (h << 5) | (h >> 27); }
#endif
    return h ^ (h >> 15);
}
