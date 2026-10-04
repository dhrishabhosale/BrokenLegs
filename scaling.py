#!/usr/bin/env python3
"""
Scaling experiment: proof success and time vs. (number of rounds) x (obfuscation level).
  level 0 plain loop | 1 flattening | 2 + opaque predicates | 3 + MBA (1 layer) | 4 + MBA (2 layers)
Reference = plain function with the same round count. Outputs results/scaling.csv, results/scaling.png
"""
import os, csv, subprocess, time
import lineage as L

L.Z3_TIMEOUT_MS = 20_000
os.makedirs("build/scale", exist_ok=True); os.makedirs("results", exist_ok=True)
ROUNDS = [1, 2, 4, 8, 16, 32]
LEVELS = [0, 1, 2, 3, 4]
NAMES = {0: "plain", 1: "flatten", 2: "flatten+opaque", 3: "+MBA (1 layer)", 4: "+MBA (2 layers)"}
CF = ["gcc", "-shared", "-fPIC", "-fcf-protection=none", "-fno-stack-protector", "-O0"]

import sys
if os.path.exists("results/scaling.csv") and "--rerun" not in sys.argv:
    rows = list(csv.DictReader(open("results/scaling.csv")))
    for r in rows:
        r["rounds"], r["level"], r["seconds"] = int(r["rounds"]), int(r["level"]), float(r["seconds"])
        r["dag_nodes"], r["tree_nodes"] = int(r["dag_nodes"]), float(r["tree_nodes"])
    print("re-plotting from results/scaling.csv (use --rerun to redo the experiment)")
else:
    rows = []
    for R in ROUNDS:
        refso = f"build/scale/ref_{R}.so"
        subprocess.run(CF + [f"-DNROUNDS={R}", "src/mut.c", "-o", refso], check=True)
        ref = L.exported_func(refso)
        for LV in LEVELS:
            so = f"build/scale/v_{R}_{LV}.so"
            subprocess.run(CF + [f"-DROUNDS={R}", f"-DLEVEL={LV}", "src/param.c", "-o", so], check=True)
            r = L.prove(ref, L.exported_func(so), fuzz_n=100_000)
            row = dict(rounds=R, level=LV, level_name=NAMES[LV], verdict=r["verdict"], seconds=round(r["time"], 2),
                       dag_nodes=r.get("dag_nodes"), tree_nodes=r.get("tree_nodes"), reason=r.get("reason", ""))
            rows.append(row)
            print(f"rounds={R:2} {NAMES[LV]:16} {r['verdict']:8} {r['time']:6.1f}s dag={row['dag_nodes']} "
                  f"tree={row['tree_nodes']:.2e} {row['reason']}", flush=True)

    with open("results/scaling.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
fig, ax = plt.subplots(1, 3, figsize=(16, 4.6))
colors = ["tab:blue", "tab:cyan", "tab:green", "tab:orange", "tab:red"]
for LV in LEVELS:
    sub = [r for r in rows if r["level"] == LV]
    ax[0].plot([r["rounds"] for r in sub], [max(r["seconds"], 0.05) for r in sub], "-", color=colors[LV], label=NAMES[LV])
    for r in sub:
        if r["reason"].startswith("query too large"):
            ax[0].plot(r["rounds"], max(r["seconds"], 0.05), "s", mfc="none", color=colors[LV], ms=9)   # skipped, not timed out
            continue
        ax[0].plot(r["rounds"], max(r["seconds"], 0.05), "o" if r["verdict"] == "PROVED" else "X",
                   color=colors[LV], ms=8 if r["verdict"] != "PROVED" else 5)
ax[0].set_xscale("log", base=2); ax[0].set_yscale("log")
ax[0].set_xlabel("rounds"); ax[0].set_ylabel("seconds to verdict (log)")
ax[0].set_title("Proof time\n(o PROVED, X Z3 timeout, hollow square = skipped, too large)", fontsize=9); ax[0].grid(alpha=.3); ax[0].legend(fontsize=8)
# grid
grid = [[1 if next(r for r in rows if r["rounds"] == R and r["level"] == LV)["verdict"] == "PROVED" else 0
         for R in ROUNDS] for LV in LEVELS]
ax[1].imshow(grid, cmap="RdYlGn", vmin=-0.3, vmax=1.3, aspect="auto")
for i, LV in enumerate(LEVELS):
    for j, R in enumerate(ROUNDS):
        r = next(r for r in rows if r["rounds"] == R and r["level"] == LV)
        skipped = r["reason"].startswith("query too large")
        ax[1].text(j, i, f"{r['verdict'][:6]}\n" + ("skipped:\ntoo large" if skipped else f"{r['seconds']:.1f}s"),
                   ha="center", va="center", fontsize=8)
ax[1].set_xticks(range(len(ROUNDS))); ax[1].set_xticklabels(ROUNDS); ax[1].set_yticks(range(len(LEVELS)))
ax[1].set_yticklabels([NAMES[l] for l in LEVELS]); ax[1].set_xlabel("rounds"); ax[1].set_title("Verdict grid (green = PROVED)")
# DAG vs tree
sub = [r for r in rows if r["level"] == 2]
ax[2].plot([r["rounds"] for r in sub], [r["tree_nodes"] for r in sub], "o-", color="tab:red", label="as a tree (naive SMT-LIB export)")
ax[2].plot([r["rounds"] for r in sub], [r["dag_nodes"] for r in sub], "o-", color="tab:green", label="as a shared DAG (our Z3 translator)")
ax[2].set_xscale("log", base=2); ax[2].set_yscale("log"); ax[2].set_xlabel("rounds"); ax[2].set_ylabel("expression nodes")
ax[2].set_title("Why the translator preserves sharing"); ax[2].grid(alpha=.3); ax[2].legend(fontsize=8)
fig.tight_layout(); fig.savefig("results/scaling.png", dpi=140)
print("wrote results/scaling.csv and results/scaling.png")
