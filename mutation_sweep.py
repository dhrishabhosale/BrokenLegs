#!/usr/bin/env python3
"""
Mutation sweep: how often does each method notice that a candidate is NOT the reference?

Families
  const-bitflip   flip one bit of one of the 4 round constants
  rot/shift       change the rotate or shift amount by one
  rounds          7 or 9 rounds instead of 8
  operator-swap   XOR replaced by ADD / OR somewhere in the round
  rare-trigger    identical EXCEPT when (a & (2^k-1)) == v  -> differs on a 2^-k fraction of inputs ("backdoor")
  equivalent      semantics-preserving rewrites (controls: must NOT be called NOT_EQUIVALENT)

Methods
  Lineage  : symbolic extraction + Z3 (verdict NOT_EQUIVALENT with a native-confirmed counterexample)
  fuzz-300k: 300,000 random inputs      fuzz-50M: 50,000,000 random inputs   (C harness, build/fuzz)
Outputs: results/sweep.csv, results/sweep_detection.png
"""
import os, sys, csv, random, subprocess, time
import lineage as L

L.Z3_TIMEOUT_MS = 10_000
random.seed(20261003)
os.makedirs("build/mut", exist_ok=True)
os.makedirs("results", exist_ok=True)
REF = "build/ref_O0.so"
N_SMALL, N_LARGE = 300_000, 50_000_000
PER_K = 6
KS = [8, 12, 16, 20, 24, 28, 32]

mutants = []   # (family, label, [gcc -D flags], truly_different)
for cname, orig in [("C_S0", 0x9E3779B9), ("C_T0", 0x85EBCA6B), ("C_K", 0x27D4EB2F), ("C_M", 0x01000193)]:
    for bit in random.sample(range(32), 3):
        mutants.append(("const-bitflip", f"{cname} bit {bit}", [f"-D{cname}=0x{orig ^ (1 << bit):X}u"], True))
for lab, fl in [("ROT=4", "-DROT=4"), ("ROT=6", "-DROT=6"), ("SHR=2", "-DSHR=2"), ("SHR=4", "-DSHR=4")]:
    mutants.append(("rot/shift", lab, [fl], True))
for n in (7, 9):
    mutants.append(("rounds", f"{n} rounds", [f"-DNROUNDS={n}"], True))
mutants += [
    ("operator-swap", "s^t -> s+t",    ["-DCOMBINE1(s,t)=((s)+(t))"], True),
    ("operator-swap", "s^t -> s|t",    ["-DCOMBINE1(s,t)=((s)|(t))"], True),
    ("operator-swap", "t*M^x -> +",    ["-DCOMBINE2(x,y)=((x)+(y))"], True),
]
for k in KS:
    for _ in range(PER_K):
        mask = (1 << k) - 1
        val = random.getrandbits(k)
        mutants.append(("rare-trigger", f"2^-{k} (a&0x{mask:X})==0x{val:X}",
                        [f"-DTRIG_MASK=0x{mask:X}u", f"-DTRIG_VAL=0x{val:X}u"], True))
mutants += [
    ("equivalent", "rotl respelled",       ["-DROTL_EXPR(x)=(((x)>>(32-ROT))|((x)<<ROT))"], False),
    ("equivalent", "C_K as sum",           ["-DC_K=(0x27D40000u+0xEB2Fu)"], False),
    ("equivalent", "C_M as sum",           ["-DC_M=(16777216u+403u)"], False),
    ("equivalent", "s^t as (s|t)-(s&t)",   ["-DCOMBINE1(s,t)=(((s)|(t))-((s)&(t)))"], False),
]


def build(i, flags):
    out = f"build/mut/m{i:03d}.so"
    subprocess.run(["gcc", "-shared", "-fPIC", "-fcf-protection=none", "-fno-stack-protector", "-O0", *flags,
                    "src/mut.c", "-o", out], check=True)
    return out


def fuzz(cand, n):
    r = subprocess.run(["./build/fuzz", REF, cand, str(n), "1"], capture_output=True, text=True).stdout.split()
    return r[0] == "DIFF"       # True = difference noticed


ref = L.exported_func(REF)
rows = []
t_start = time.time()
for i, (fam, lab, flags, differs) in enumerate(mutants):
    so = build(i, flags)
    t = time.time()
    r = L.prove(ref, L.exported_func(so), fuzz_n=1)
    proof_caught = r["verdict"] == "NOT_EQUIVALENT"
    f_small, f_large = fuzz(so, N_SMALL), fuzz(so, N_LARGE)
    row = dict(family=fam, label=lab, truly_different=differs, lineage_verdict=r["verdict"],
               lineage_caught=proof_caught, lineage_time=round(r["time"], 2),
               fuzz_300k_caught=f_small, fuzz_50M_caught=f_large)
    rows.append(row)
    print(f"[{i+1:2}/{len(mutants)}] {fam:14} {lab[:34]:34} lineage={r['verdict']:14} "
          f"fuzz300k={'caught' if f_small else 'missed':6} fuzz50M={'caught' if f_large else 'missed':6} "
          f"({time.time()-t:.1f}s)", flush=True)

with open("results/sweep.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0]))
    w.writeheader(); w.writerows(rows)

# ------------------------------------------------------------ summary table
print("\n" + "=" * 100)
print(f"{'family':16} {'n':>3} {'Lineage caught':>15} {'fuzz-300k':>10} {'fuzz-50M':>9}   notes")
print("-" * 100)
for fam in dict.fromkeys(r["family"] for r in rows):
    sub = [r for r in rows if r["family"] == fam]
    n = len(sub)
    lc = sum(r["lineage_caught"] for r in sub)
    note = ""
    if fam == "equivalent":
        note = "verdicts: " + ", ".join(sorted({r["lineage_verdict"] for r in sub})) + "  (never NOT_EQUIVALENT = no false alarms)"
    print(f"{fam:16} {n:3} {lc:>9}/{n:<5} {sum(r['fuzz_300k_caught'] for r in sub):>5}/{n:<4} "
          f"{sum(r['fuzz_50M_caught'] for r in sub):>4}/{n:<4}   {note}")
diff = [r for r in rows if r["truly_different"]]
eq = [r for r in rows if not r["truly_different"]]
print("-" * 100)
print(f"All truly-different mutants: Lineage {sum(r['lineage_caught'] for r in diff)}/{len(diff)}, "
      f"fuzz-300k {sum(r['fuzz_300k_caught'] for r in diff)}/{len(diff)}, fuzz-50M {sum(r['fuzz_50M_caught'] for r in diff)}/{len(diff)}")
print(f"False alarms on equivalent mutants: {sum(r['lineage_verdict']=='NOT_EQUIVALENT' for r in eq)}/{len(eq)}")
print(f"total sweep time {time.time()-t_start:.0f}s")

# ------------------------------------------------------------ plot
import math
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

trig = [r for r in rows if r["family"] == "rare-trigger"]
ks, lin, f1, f2 = [], [], [], []
for k in KS:
    sub = [r for r in trig if r["label"].startswith(f"2^-{k} ")]
    ks.append(k)
    lin.append(100 * sum(r["lineage_caught"] for r in sub) / len(sub))
    f1.append(100 * sum(r["fuzz_300k_caught"] for r in sub) / len(sub))
    f2.append(100 * sum(r["fuzz_50M_caught"] for r in sub) / len(sub))
xs = [x / 4 for x in range(4 * 6, 4 * 33)]
th = lambda n: [100 * (1 - math.exp(-n * 2 ** -x)) for x in xs]
fig, ax = plt.subplots(figsize=(8, 4.8))
ax.plot(xs, th(N_SMALL), ":", color="tab:orange", label="fuzz 300k (theory)")
ax.plot(xs, th(N_LARGE), ":", color="tab:green", label="fuzz 50M (theory)")
ax.plot(ks, f1, "o", color="tab:orange", label=f"fuzz 300k (observed, n={PER_K}/pt)")
ax.plot(ks, f2, "s", color="tab:green", label=f"fuzz 50M (observed, n={PER_K}/pt)")
ax.plot(ks, lin, "D-", color="tab:blue", lw=2, label="Lineage (SMT proof)")
ax.set_xlabel("k : mutant differs on a 2^-k fraction of inputs  (higher = rarer backdoor)")
ax.set_ylabel("% of mutants detected")
ax.set_title("Rare-trigger mutants: fuzzing detection collapses, proof does not")
ax.set_ylim(-5, 105); ax.grid(alpha=.3); ax.legend(fontsize=8, loc="center left")
fig.tight_layout(); fig.savefig("results/sweep_detection.png", dpi=150)
print("wrote results/sweep.csv and results/sweep_detection.png")
