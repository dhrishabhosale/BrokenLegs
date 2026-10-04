#!/usr/bin/env bash
# Builds reference, disguised variants, stripped libraries, negative controls and the C fuzzer.
set -euo pipefail
mkdir -p build
CF="-shared -fPIC -fno-stack-protector -fcf-protection=none"
HF="$CF -fvisibility=hidden -Isrc"          # hidden-visibility flags for stripped builds

gcc $CF -O0 src/ref.c            -o build/ref_O0.so             # reference ("the proprietary code")
gcc $CF -O3 src/ref.c            -o build/var_a_O3.so           # (a) recompiled, different flags
gcc $CF -O0 src/var_b.c          -o build/var_b_refactor.so     # (b) hand-refactored / renamed
gcc $CF -O0 src/var_c.c          -o build/var_c_flatten.so      # (c) flattened + opaque predicates
gcc $CF -O0 src/var_d_symloop.c  -o build/var_d_symloop.so      # (d) + input-dependent loop (forces fallback)
gcc $CF -O0 -DROUNDS=8 -DLEVEL=3 src/param.c -o build/var_e_mba.so   # (e) flattening + opaque + 1-layer MBA (Z3 wall)
gcc $CF -O0 src/neg_lookalike.c  -o build/neg_lookalike.so      # N1 one constant changed
gcc $CF -O0 src/neg_unrelated.c  -o build/neg_unrelated.so      # N2 unrelated hash

# stripped libraries: target hidden (not in .dynsym), only `entry` exported, then strip --strip-all
gcc $HF -O3 -DTARGET_SRC='"ref.c"' src/strip_wrap.c -o build/stripped_a_O3.so
gcc $HF -O0 -DTARGET_SRC='"param.c"' -DROUNDS=8 -DLEVEL=2 src/strip_wrap.c -o build/stripped_c_flatten.so
gcc $HF -O0 -DTARGET_SRC='"neg_lookalike.c"' src/strip_wrap.c -o build/stripped_lookalike.so
strip --strip-all build/stripped_*.so

# signature-scope test libraries (wider function signatures)
mkdir -p build/sig
gcc $CF -O0 src/sig_u64.c -o build/sig/u64_ref.so;     gcc $CF -O3 src/sig_u64.c -o build/sig/u64_O3.so
gcc $CF -O0 -DK2=0x94D049BB133111ECull src/sig_u64.c -o build/sig/u64_lookalike.so
gcc $CF -O0 src/sig_mixed.c -o build/sig/mixed_ref.so; gcc $CF -O3 src/sig_mixed.c -o build/sig/mixed_O3.so
gcc $CF -O0 -DSH=6 src/sig_mixed.c -o build/sig/mixed_lookalike.so
gcc $CF -O0 src/sig_buf.c -o build/sig/buf_ref.so;     gcc $CF -O3 src/sig_buf.c -o build/sig/buf_O3.so
gcc $CF -O0 -DREFACTOR -DSKIP=1 src/sig_buf.c -o build/sig/buf_skip.so

gcc -O2 src/fuzz.c -o build/fuzz -ldl                            # fast C differential fuzzer
echo "built:"; ls build/*.so build/fuzz
