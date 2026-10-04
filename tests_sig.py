#!/usr/bin/env python3
"""Function-scope tests: wider signatures (64-bit args, mixed widths, byte buffers). Run: python3 tests_sig.py"""
import os, subprocess, time
import lineage as L
L.Z3_TIMEOUT_MS = 20_000
os.makedirs("build/sig", exist_ok=True)
CF = ["gcc", "-shared", "-fPIC", "-fcf-protection=none", "-fno-stack-protector"]
# (name, source, signature, ref flags, candidate flags, expected)
CASES = [
    ("u64: recompiled -O3",          "sig_u64",   "u64,u64->u64",    ["-O0"], ["-O3"],                    "PROVED"),
    ("u64: refactored",              "sig_u64",   "u64,u64->u64",    ["-O0"], ["-O0", "-DREFACTOR"],      "PROVED"),
    ("u64: lookalike (1 const)",     "sig_u64",   "u64,u64->u64",    ["-O0"], ["-O0", "-DK2=0x94D049BB133111ECull"], "NOT_EQUIVALENT"),
    ("mixed u8,u16,u32->u16: -O3",   "sig_mixed", "u8,u16,u32->u16", ["-O0"], ["-O3"],                    "PROVED"),
    ("mixed: refactored",            "sig_mixed", "u8,u16,u32->u16", ["-O0"], ["-O0", "-DREFACTOR"],      "PROVED"),
    ("mixed: lookalike (shift 7->6)","sig_mixed", "u8,u16,u32->u16", ["-O0"], ["-O0", "-DSH=6"],          "NOT_EQUIVALENT"),
    ("buf16: recompiled -O3",        "sig_buf",   "buf16,len16->u32", ["-O0"], ["-O3"],                   "PROVED"),
    ("buf16: refactored (pointer loop)", "sig_buf", "buf16,len16->u32", ["-O0"], ["-O0", "-DREFACTOR"],   "PROVED"),
    ("buf16: lookalike (offset basis)", "sig_buf", "buf16,len16->u32", ["-O0"], ["-O0", "-DOFFSET=0x811C9DC6u"], "NOT_EQUIVALENT"),
    ("buf16: ignores last byte",     "sig_buf",   "buf16,len16->u32", ["-O0"], ["-O0", "-DREFACTOR", "-DSKIP=1"], "NOT_EQUIVALENT"),
]


def build(i, src, flags, tag):
    out = f"build/sig/t{i}_{tag}.so"
    subprocess.run(CF + flags + [f"src/{src}.c", "-o", out], check=True)
    return out


if __name__ == "__main__":
    print(f"{'case':36} {'signature':20} {'verdict':15} {'expected':15} {'time':>6}  detail")
    bad = 0
    for i, (name, src, sigtxt, rf, cf, exp) in enumerate(CASES):
        sig = L.Sig(sigtxt)
        ref, cand = L.exported_func(build(i, src, rf, "ref")), L.exported_func(build(i, src, cf, "cand"))
        r = L.prove(ref, cand, fuzz_n=50_000, sig=sig)
        ok = r["verdict"] == exp
        bad += not ok
        print(f"{name:36} {sigtxt:20} {r['verdict']:15} {exp:15} {r['time']:5.1f}s  {'OK ' if ok else 'MISMATCH '}{r['detail'][:70]}", flush=True)
    print("\nall as expected" if not bad else f"\n{bad} case(s) differ from expectation")
