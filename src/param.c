#include <stdint.h>
// Parametric version of the reference. Compile with -DROUNDS=<n> -DLEVEL=<0..4>
//  LEVEL 0: plain loop
//  LEVEL 1: control-flow flattening (switch dispatcher)
//  LEVEL 2: + opaque predicates tied to the inputs
//  LEVEL 3: + mixed boolean-arithmetic (MBA) rewriting of + and ^, one layer
//  LEVEL 4: + MBA rewriting applied twice (nested identities)
#ifndef ROUNDS
#define ROUNDS 8
#endif
#ifndef LEVEL
#define LEVEL 0
#endif
typedef uint32_t u32;
static inline u32 rotl(u32 x, int r){ return (x << r) | (x >> (32 - r)); }

// MBA identities:  a^b = (a|b)-(a&b)      a+b = (a^b) + 2*(a&b)
//   layer 2 uses:  a^b = 2*(a|b) - (a+b), with (a+b) itself rewritten by layer 1
static inline u32 x1(u32 a, u32 b){ return (a | b) - (a & b); }
static inline u32 a1(u32 a, u32 b){ return x1(a, b) + 2u * (a & b); }
static inline u32 x2(u32 a, u32 b){ return 2u * (a | b) - a1(a, b); }
static inline u32 a2(u32 a, u32 b){ return x2(a, b) + 2u * (a & b); }
#if LEVEL == 3
#define XOR(a,b) x1(a,b)
#define ADD(a,b) a1(a,b)
#elif LEVEL >= 4
#define XOR(a,b) x2(a,b)
#define ADD(a,b) a2(a,b)
#else
#define XOR(a,b) ((a) ^ (b))
#define ADD(a,b) ((a) + (b))
#endif

#define OPAQUE_TRUE(x) ((((x) * ((x) + 1u)) & 1u) == 0u)   // x*(x+1) is always even

static inline u32 round_s(u32 s, u32 t, u32 i){ return ADD(rotl(XOR(s, t), 5), 0x27D4EB2Fu * (i + 1)); }
static inline u32 round_t(u32 s, u32 t){ return XOR(t * 0x01000193u, s >> 3); }

u32 lineage_f(u32 a, u32 b) {
#if LEVEL == 0
    u32 s = a ^ 0x9E3779B9u, t = b + 0x85EBCA6Bu;
    for (u32 i = 0; i < ROUNDS; i++) { s = round_s(s, t, i); t = round_t(s, t); }
    return s ^ t;
#else
    u32 s = 0, t = 0, i = 0, st = 0;
    for (;;) {
        switch (st) {
        case 0: s = a ^ 0x9E3779B9u; t = b + 0x85EBCA6Bu; i = 0;
#if LEVEL >= 2
                st = OPAQUE_TRUE(a) ? 1 : 6;
#else
                st = 1;
#endif
                break;
        case 1: st = (i < ROUNDS) ? 2 : 5; break;
        case 2: s = round_s(s, t, i);
#if LEVEL >= 2
                st = OPAQUE_TRUE(b ^ i) ? 3 : 7;
#else
                st = 3;
#endif
                break;
        case 3: t = round_t(s, t); st = 4; break;
        case 4: i++; st = 1; break;
        case 5: return s ^ t;
        case 6: s ^= 0xDEADBEEFu; st = 5; break;   // dead junk
        case 7: t += 0x1337u;     st = 3; break;   // dead junk
        }
    }
#endif
}
