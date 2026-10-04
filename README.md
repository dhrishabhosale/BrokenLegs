# Lineage

> "Obfuscation hides how code looks. It can't hide what code computes. We prove the latter."

Proves (or fails to prove) that two compiled functions compute the same thing, even when they look nothing alike.

## Run
```bash
pip install -U angr z3-solver matplotlib   # use angr >= 10 (see note below); x86-64 Linux with gcc and strip
./build.sh                                 # reference, variants, stripped libs, C fuzzer
python3 lineage.py                         # main demo table            (~1.5 min)
python3 mutation_sweep.py                  # 67 mutants, fuzz vs proof  (~1.5 min) -> results/sweep.*
python3 scaling.py --rerun                 # rounds x obfuscation grid  (~5 min)   -> results/scaling.*
```
(`python3 scaling.py` without `--rerun` just re-plots the saved CSV.) Timings are from a 1-CPU sandbox.

## Pipeline (per pair)
1. angr lifts both functions to VEX and symbolically executes them with the **same** symbolic inputs `(a, b)`.
2. Both return expressions are translated to Z3 *preserving DAG sharing* (a naive SMT-LIB export is a tree and explodes: 10^22 nodes at 32 rounds vs 361 shared nodes).
3. Query: *does any input exist where the outputs differ?* Solved by Z3 (bit-blast + SAT, restart portfolio over random seeds).
   - UNSAT -> **PROVED**   |   SAT -> **NOT_EQUIVALENT** (counterexample re-run natively)
   - path budget / query-size budget / timeout -> 300k-sample differential test -> **TESTED** (evidence, not proof)
4. **Stripped binaries:** recover functions with a CFG scan, reject candidates by concrete emulation on 6 probe inputs (a mismatch is a sound rejection), then run the proof on survivors. Nothing survives -> **NOT_FOUND**.
5. Syntactic baseline (mnemonic-trigram Jaccard + basic-block ratio) stands in for BinDiff/Diaphora. For stripped libs it reports the best match among all recovered functions.

## Results (as measured)
### Main table
| variant | syntactic | Lineage |
|---|---|---|
| a) recompiled -O3 | 11% | PROVED 0.3s |
| b) refactored/renamed | 79% | PROVED 0.2s |
| c) flattened + input-dependent opaque predicates | 24% | PROVED 0.4s |
| e) flattened + 1-layer MBA, 8 rounds | 21% | TESTED (Z3 timeout) |
| f) stripped -O3, 4 decoys | 54% | PROVED, function found among 9 candidates |
| g) stripped flatten+opaque | 50% | PROVED, found among 13 candidates |
| d) + input-dependent loop | 66% | TESTED (path explosion >512) |
| N1) lookalike, one constant changed | **100%** | NOT_EQUIVALENT + counterexample |
| N2) unrelated hash | 44% | NOT_EQUIVALENT + counterexample |
| N3) stripped lookalike | 100% | NOT_FOUND |

### Mutation sweep (`results/sweep_detection.png`)
63 truly-different mutants: **Lineage 63/63**, fuzz-300k 42/63, fuzz-50M 52/63.
42 rare-trigger "backdoor" mutants (differ on 2^-k of inputs): Lineage 42/42, fuzz-300k 21/42, fuzz-50M 31/42; every 2^-32 backdoor missed by both fuzzers.
4 semantics-preserving rewrites (incl. an MBA identity): 0 false alarms, all PROVED.

### Scaling (`results/scaling.png`)
Plain / flattened / flattened+opaque: PROVED at every size from 1 to 32 rounds, <= 1.5s.
MBA is the wall: 1 layer proves only at 1 round; 2 layers never proves (not even at 1 round); at 32 rounds x 2 layers the query exceeds the size budget and is skipped.

## limitations
- **Baseline is a stand-in**, not real BinDiff/Diaphora. **Obfuscation is hand-written**, not Tigress/ollvm (MBA rewrites are my own identities).
- **MBA defeats the solver** once it is composed across rounds; this is the main open problem (idea: per-round cut points / MBA simplification).
- Budgets are tunable and results depend on them: 512 paths, 20-30s Z3 timeout, 1200 shared-DAG nodes (Z3 can abort on memory beyond that).
- TESTED is statistical. The sweep shows rare-trigger differences slip past even 50M samples; only a proof rules them out.
- Target is narrow: fixed rounds, register-only (u32,u32)->u32 inputs, same architecture (x86-64). No buffers/memory, no loop summarization, no VM-based protectors.
- Stripped discovery assumes the reference's signature is known (the owner knows their own function); the emulation probe is a sound *rejection* filter, not evidence of equivalence.
- Not done: cross-architecture (ARM) builds, whole-binary scoring.


## Web control panel
```bash
pip install flask
python3 webapp.py
```
Run Build, Demo table, Mutation sweep and Scaling grid from the browser. Jobs are detached processes that keep running if you close the tab or restart the server; logs are in `jobs/`. One job runs at a time so timings stay meaningful. It binds to localhost and only runs the four fixed commands.

