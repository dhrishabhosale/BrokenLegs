// usage: fuzz ref.so cand.so N seed   -> prints "OK N" or "DIFF idx a b"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <dlfcn.h>
typedef uint32_t (*fn)(uint32_t, uint32_t);
static uint64_t s[2];
static inline uint64_t rotl64(uint64_t x, int k){ return (x << k) | (x >> (64 - k)); }
static inline uint64_t next(void){ uint64_t s0=s[0], s1=s[1], r=s0+s1; s1^=s0; s[0]=rotl64(s0,55)^s1^(s1<<14); s[1]=rotl64(s1,36); return r; }
int main(int argc, char **argv){
    if (argc < 5) return 2;
    void *h1 = dlopen(argv[1], RTLD_NOW), *h2 = dlopen(argv[2], RTLD_NOW);
    if (!h1 || !h2) { fprintf(stderr, "dlopen failed\n"); return 2; }
    fn f1 = (fn)dlsym(h1, "lineage_f"), f2 = (fn)dlsym(h2, "lineage_f");
    if (!f1 || !f2) { fprintf(stderr, "dlsym failed\n"); return 2; }
    uint64_t n = strtoull(argv[3], 0, 10), seed = strtoull(argv[4], 0, 10);
    s[0] = seed * 0x9E3779B97F4A7C15ull + 1; s[1] = seed ^ 0xD1B54A32D192ED03ull;
    for (int i = 0; i < 20; i++) next();
    for (uint64_t i = 0; i < n; i++) {
        uint64_t r = next(); uint32_t a = (uint32_t)r, b = (uint32_t)(r >> 32);
        if (f1(a, b) != f2(a, b)) { printf("DIFF %llu %u %u\n", (unsigned long long)i, a, b); return 1; }
    }
    printf("OK %llu\n", (unsigned long long)n); return 0;
}
