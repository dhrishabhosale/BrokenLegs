#include <stdint.h>
// Hand-obfuscated (NOT a real tool): switch-dispatcher flattening + opaque predicates.
// Opaque predicate: x*(x+1) is always even (here x is an INPUT, so the solver must actually reason about it)  -> "true" branch always taken, but not obvious statically.
#define OPAQUE_TRUE(x)  ((((x) * ((x) + 1u)) & 1u) == 0u)
uint32_t lineage_f(uint32_t p, uint32_t q) {
    uint32_t s = 0, t = 0, i = 0, state = 0;
    for (;;) {
        switch (state) {
        case 0:  s = p ^ 0x9E3779B9u; t = q + 0x85EBCA6Bu; i = 0;
                 state = OPAQUE_TRUE(p) ? 1 : 6; break;
        case 1:  state = (i < 8) ? 2 : 5; break;
        case 2:  { uint32_t m = s ^ t; s = ((m << 5) | (m >> 27)) + 0x27D4EB2Fu * (i + 1);
                   state = OPAQUE_TRUE(q ^ i) ? 3 : 7; } break;
        case 3:  t = (t * 0x01000193u) ^ (s >> 3);
                 state = 4; break;
        case 4:  i++; state = 1; break;
        case 5:  return s ^ t;
        case 6:  s ^= 0xDEADBEEFu; state = 5; break;   // dead junk (never reached)
        case 7:  t += 0x1337u;     state = 3; break;   // dead junk (never reached)
        }
    }
}
