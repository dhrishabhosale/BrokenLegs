#include <stdint.h>
// Mutation template of the reference. Every knob defaults to the ORIGINAL value.
#ifndef C_S0
#define C_S0 0x9E3779B9u
#endif
#ifndef C_T0
#define C_T0 0x85EBCA6Bu
#endif
#ifndef C_K
#define C_K  0x27D4EB2Fu
#endif
#ifndef C_M
#define C_M  0x01000193u
#endif
#ifndef ROT
#define ROT 5
#endif
#ifndef SHR
#define SHR 3
#endif
#ifndef NROUNDS
#define NROUNDS 8
#endif
#ifndef COMBINE1            // combines s and t before the rotation: default XOR
#define COMBINE1(s,t) ((s) ^ (t))
#endif
#ifndef COMBINE2            // combines t*M with s>>SHR: default XOR
#define COMBINE2(x,y) ((x) ^ (y))
#endif
#ifndef ROTL_EXPR           // alternative (equivalent) rotation spelling is injected by -DROTL_EXPR
#define ROTL_EXPR(x) (((x) << ROT) | ((x) >> (32 - ROT)))
#endif
uint32_t lineage_f(uint32_t a, uint32_t b) {
    uint32_t s = a ^ C_S0, t = b + C_T0;
    for (int i = 0; i < NROUNDS; i++) {
        s = ROTL_EXPR(COMBINE1(s, t)) + (C_K * (uint32_t)(i + 1));
        t = COMBINE2(t * C_M, s >> SHR);
    }
    uint32_t r = s ^ t;
#ifdef TRIG_MASK            // rare-trigger "backdoor": differs only when (a & MASK) == VAL
    if ((a & TRIG_MASK) == TRIG_VAL) r ^= 1u;
#endif
    return r;
}
