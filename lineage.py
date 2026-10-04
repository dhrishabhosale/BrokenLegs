#!/usr/bin/env python3
"""
Lineage: decide whether two compiled functions compute the same thing.

Core API (also used by mutation_sweep.py and scaling.py):
    exported_func(path)            -> Func for the exported `lineage_f`
    discover(ref, path)            -> find the matching function inside a STRIPPED library
    prove(ref, cand)               -> verdict dict: PROVED / NOT_EQUIVALENT / TESTED
    compare(ref, path, stripped)   -> prove() + syntactic baseline + discovery, for the demo table

Per pair:
  1. angr lifts both functions to VEX and symbolically executes them with SHARED symbolic inputs (a, b).
  2. "Is there any input where the outputs differ?" is exported as SMT-LIB and solved by Z3.
        UNSAT -> PROVED   SAT -> NOT_EQUIVALENT (cex re-run natively)   timeout/path budget -> TESTED (fuzz)
  3. For stripped binaries, candidate functions are recovered with a CFG scan and filtered by a cheap
     concrete-emulation probe BEFORE the expensive symbolic proof.
"""
import os, sys, time, random, ctypes, logging
import angr, capstone, z3
try:
    # angr >= 10 bundles its own claripy. Prefer it: a stale standalone `claripy` package left over from an
    # older install would otherwise be imported instead, and angr rejects its expressions.
    from angr import claripy
except ImportError:                       # angr < 10: claripy is a separate package
    import claripy

z3.set_param("memory_max_size", 1500)   # MB: Z3 raises instead of letting the OS kill the process

for n in ("angr", "claripy", "angr.claripy", "cle", "pyvex", "archinfo"):
    logging.getLogger(n).setLevel(logging.CRITICAL)

if int(angr.__version__.split(".")[0]) < 10:
    print(f"[warn] angr {angr.__version__} detected. It runs, but older claripy does not normalise expressions as well,\n"
          "       so optimised (-O3) builds may fall back to TESTED instead of PROVED. Recommended: pip install -U angr",
          file=sys.stderr)

SYMBOL = "lineage_f"
MAX_PATHS = 512          # path budget (live + finished); beyond this we give up the symbolic proof
MAX_STEPS = 20000        # simgr step cap
Z3_TIMEOUT_MS = 30_000          # overridable by callers (scaling.py lowers it)
FUZZ_SAMPLES = 300_000
MAX_DAG_NODES = 1200     # query-size budget: beyond this Z3 can abort on memory, so we don't even try
PROBES = [(0, 0), (1, 2), (0xDEADBEEF, 0xCAFEBABE), (0x12345678, 0x9ABCDEF0), (0xFFFFFFFF, 1), (7, 0x80000000)]


# ---- claripy compatibility: angr<10 ships claripy as a separate package (claripy.ast.Base, args layout differs)
BASE = getattr(claripy, "Base", None) or claripy.ast.Base


def _h(n):
    """Structural hash of an AST node."""
    try:
        return n.hash()
    except AttributeError:
        return hash(n)


def _bits(n):
    """Bit width of a BV node (BVS.args differs between claripy versions, so don't read it from args)."""
    v = getattr(n, "length", None)
    if isinstance(v, int):
        return v
    try:
        return n.size()
    except Exception:
        return n.args[1]

A = claripy.BVS("a", 32)
B = claripy.BVS("b", 32)


# ============================================================ function handles
class Func:
    def __init__(self, path, addr, size, name=None):
        self.path, self.addr, self.size, self.name = path, addr, size, name or f"sub_{addr:x}"

    @property
    def proj(self):
        return get_proj(self.path)

    def __repr__(self):
        return f"<Func {self.name} @ {self.addr:#x} in {os.path.basename(self.path)}>"


_PROJ, _CFG, _LIB, _SUMMARY = {}, {}, {}, {}


def get_proj(path):
    if path not in _PROJ:
        _PROJ[path] = angr.Project(path, auto_load_libs=False)
    return _PROJ[path]


def get_cfg(path):
    if path not in _CFG:
        _CFG[path] = get_proj(path).analyses.CFGFast(normalize=True, show_progressbar=False)
    return _CFG[path]


def exported_func(path):
    proj = get_proj(path)
    sym = proj.loader.find_symbol(SYMBOL)
    return Func(path, sym.rebased_addr, sym.size, SYMBOL)


# ============================================================ native execution
def _native_base(path):
    real = os.path.realpath(path)
    for line in open("/proc/self/maps"):
        p = line.split()
        if len(p) >= 6 and p[5] == real and int(p[2], 16) == 0:
            return int(p[0].split("-")[0], 16)
    raise RuntimeError("library not mapped")


def native_fn(func):
    """Callable for ANY function (exported or not) by address arithmetic on the mapped library."""
    if func.path not in _LIB:
        _LIB[func.path] = ctypes.CDLL(os.path.realpath(func.path))
    addr = _native_base(func.path) + (func.addr - func.proj.loader.main_object.mapped_base)
    return ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32)(addr)


def differential_test(fa, fb, n=FUZZ_SAMPLES, seed=0xC0FFEE):
    rng = random.Random(seed)
    edge = [0, 1, 2, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xDEADBEEF, 0x55555555, 0xAAAAAAAA]
    for x in edge:
        for y in edge:
            if fa(x, y) != fb(x, y):
                return False, (x, y), 0
    for i in range(n):
        x, y = rng.getrandbits(32), rng.getrandbits(32)
        if fa(x, y) != fb(x, y):
            return False, (x, y), i
    return True, None, n


# ============================================================ symbolic extraction + SMT
def make_state(proj, addr, a, b):
    """Call state for f(a, b) with args written into the ABI argument registers directly.
    (Passing claripy values through call_state() relies on prototype guessing, which breaks on some angr versions.)"""
    st = proj.factory.call_state(addr, add_options={
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    for reg, v in zip(proj.factory.cc().ARG_REGS, (a, b)):
        bv = claripy.BVV(v, 32) if isinstance(v, int) else v
        setattr(st.regs, reg, claripy.ZeroExt(proj.arch.bits - 32, bv))
    return st


def summarize(func):
    """Symbolically run func(A, B). Returns ([(constraints, ret32)], info) or (None, info) on give-up. Cached."""
    key = (func.path, func.addr)
    if key in _SUMMARY:
        return _SUMMARY[key]
    proj = func.proj
    st = make_state(proj, func.addr, A, B)
    simgr = proj.factory.simgr(st)
    steps = 0
    while simgr.active and steps < MAX_STEPS:
        simgr.step()
        steps += 1
        if len(simgr.active) + len(simgr.deadended) > MAX_PATHS:
            res = (None, {"reason": f">{MAX_PATHS} paths (path explosion)", "steps": steps})
            _SUMMARY[key] = res
            return res
    if simgr.active:
        res = (None, {"reason": f"step cap {MAX_STEPS} hit", "steps": steps})
    else:
        paths = [(list(s.solver.constraints), s.regs.rax[31:0]) for s in simgr.deadended]
        res = (paths, {"steps": steps, "paths": len(paths)})
    _SUMMARY[key] = res
    return res


_Z3_OPS = {
    "__add__": lambda k: _fold(lambda x, y: x + y, k), "__sub__": lambda k: _fold(lambda x, y: x - y, k),
    "__mul__": lambda k: _fold(lambda x, y: x * y, k), "__and__": lambda k: _fold(lambda x, y: x & y, k),
    "__or__":  lambda k: _fold(lambda x, y: x | y, k), "__xor__": lambda k: _fold(lambda x, y: x ^ y, k),
    "__lshift__": lambda k: k[0] << k[1], "__rshift__": lambda k: k[0] >> k[1], "LShR": lambda k: z3.LShR(k[0], k[1]),
    "__eq__": lambda k: k[0] == k[1], "__ne__": lambda k: k[0] != k[1],
    "ULT": lambda k: z3.ULT(k[0], k[1]), "ULE": lambda k: z3.ULE(k[0], k[1]),
    "UGT": lambda k: z3.UGT(k[0], k[1]), "UGE": lambda k: z3.UGE(k[0], k[1]),
    "SLT": lambda k: k[0] < k[1], "SLE": lambda k: k[0] <= k[1], "SGT": lambda k: k[0] > k[1], "SGE": lambda k: k[0] >= k[1],
    "Not": lambda k: z3.Not(k[0]), "And": lambda k: z3.And(*k), "Or": lambda k: z3.Or(*k),
    "If": lambda k: z3.If(k[0], k[1], k[2]), "Concat": lambda k: z3.Concat(*k),
    "__invert__": lambda k: ~k[0], "__neg__": lambda k: -k[0], "RotateLeft": lambda k: z3.RotateLeft(k[0], k[1]),
}


def _fold(op, k):
    r = k[0]
    for x in k[1:]:
        r = op(r, x)
    return r


class UnsupportedOp(Exception):
    pass


def _z3_node(n, k):
    op = n.op
    if op == "BVS":
        return z3.BitVec(n.args[0], _bits(n))
    if op == "BVV":
        return z3.BitVecVal(n.args[0], n.args[1])
    if op == "BoolV":
        return z3.BoolVal(bool(n.args[0]))
    if op == "Extract":
        return z3.Extract(n.args[0], n.args[1], k[0])
    if op == "ZeroExt":
        return z3.ZeroExt(n.args[0], k[0])
    if op == "SignExt":
        return z3.SignExt(n.args[0], k[0])
    if op in _Z3_OPS:
        return _Z3_OPS[op](k)
    raise UnsupportedOp(op)


def to_z3(root, memo):
    """Translate a claripy AST to Z3 iteratively, preserving DAG sharing via memo (keyed by AST hash)."""
    stack = [root]
    while stack:
        n = stack[-1]
        h = _h(n)
        if h in memo:
            stack.pop()
            continue
        kids = [a for a in n.args if isinstance(a, BASE)]
        pend = [c for c in kids if _h(c) not in memo]
        if pend:
            stack.extend(pend)
            continue
        memo[h] = _z3_node(n, [memo[_h(c)] for c in kids])
        stack.pop()
    return memo[_h(root)]


def tree_size(root):
    """Node count if the DAG were printed as a tree (what a naive SMT-LIB export would pay)."""
    memo, stack = {}, [root]
    while stack:
        n = stack[-1]
        h = _h(n)
        if h in memo:
            stack.pop()
            continue
        kids = [a for a in n.args if isinstance(a, BASE)]
        pend = [c for c in kids if _h(c) not in memo]
        if pend:
            stack.extend(pend)
            continue
        memo[h] = 1 + sum(memo[_h(c)] for c in kids)
        stack.pop()
    return memo[_h(root)]


def smt_equivalence(pa, pb, dump=None):
    """Any input and pair of paths feasible together with ret_A != ret_B?
    Returns ('UNSAT'|'SAT'|'UNKNOWN', cex, info)."""
    memo = {}
    try:
        disj = []
        for ca, ra in pa:
            for cb, rb in pb:
                terms = [to_z3(c, memo) for c in list(ca) + list(cb)] + [to_z3(ra, memo) != to_z3(rb, memo)]
                disj.append(z3.And(*terms))
    except UnsupportedOp as e:
        return "UNKNOWN", None, {"why": f"unsupported op {e}"}
    info = {"dag_nodes": len(memo), "tree_nodes": max(tree_size(r) for _, r in pa + pb)}
    if info["dag_nodes"] > MAX_DAG_NODES:
        info["why"] = f"query too large ({info['dag_nodes']} DAG nodes > budget {MAX_DAG_NODES})"
        return "UNKNOWN", None, info
    formula = z3.Or(*disj)
    if dump and info["tree_nodes"] < 200_000:
        dz = z3.Solver(); dz.add(formula); open(dump, "w").write(dz.to_smt2())
    # Restart portfolio: counterexample search is heavy-tailed in the random seed, so run several short
    # seeded attempts, then one long attempt with the remaining budget.
    short = min(2000, Z3_TIMEOUT_MS // 5)
    spent = 0
    for seed in range(5):
        budget = short if seed < 4 else max(1000, Z3_TIMEOUT_MS - spent)
        z = z3.Then("simplify", "bit-blast", "sat").solver()
        z.set("timeout", budget); z.set("random_seed", seed); z.set("sat.random_seed", seed)
        z.add(formula)
        t = time.time()
        try:
            res = z.check()
        except z3.Z3Exception:
            info["why"] = "Z3 out of memory"
            return "UNKNOWN", None, info
        spent += int((time.time() - t) * 1000)
        if res == z3.unsat:
            return "UNSAT", None, info
        if res == z3.sat:
            m = z.model()
            ev = lambda nm: m.eval(z3.BitVec(nm.args[0], 32), model_completion=True).as_long()
            return "SAT", (ev(A), ev(B)), info
    info["why"] = "Z3 timeout"
    return "UNKNOWN", None, info


def prove(ref, cand, dump=None, fuzz_n=FUZZ_SAMPLES):
    """Full verdict for one (reference, candidate) pair."""
    t0 = time.time()
    sa, ia = summarize(ref)
    sb, ib = summarize(cand)
    out = {"paths": (ia.get("paths"), ib.get("paths")), "cex": None}
    fa, fb = native_fn(ref), native_fn(cand)

    def fallback(why):
        ok, cex, n = differential_test(fa, fb, n=fuzz_n)
        out["verdict"] = "TESTED" if ok else "NOT_EQUIVALENT"
        out["cex"] = cex
        out["detail"] = f"{why}; fuzz {n} samples" + (f", cex={cex}" if cex else "")

    if sa is None or sb is None:
        out["reason"] = ia.get("reason") or ib.get("reason")
        fallback(f"symbolic gave up ({out['reason']})")
    else:
        res, cex, info = smt_equivalence(sa, sb, dump)
        out.update({k: v for k, v in info.items() if k != "why"})
        if res == "UNSAT":
            out["verdict"] = "PROVED"
            out["detail"] = f"UNSAT: no input differs (paths {ia['paths']}x{ib['paths']})"
        elif res == "SAT":
            va, vb = fa(*cex), fb(*cex)
            out["verdict"] = "NOT_EQUIVALENT"
            out["cex"] = cex
            out["detail"] = (f"Z3 cex a={cex[0]:#010x} b={cex[1]:#010x}: ref={va:#010x} cand={vb:#010x} "
                             f"({'confirmed natively' if va != vb else 'NOT CONFIRMED - lifting bug?'})")
        else:
            out["reason"] = info.get("why", "Z3 timeout")
            fallback(out["reason"])
    out["time"] = time.time() - t0
    return out


# ============================================================ discovery in stripped binaries
def candidates(path):
    proj, cfg = get_proj(path), get_cfg(path)
    obj = proj.loader.main_object
    res = []
    for f in cfg.kb.functions.values():
        if f.is_plt or f.is_simprocedure or f.is_syscall or f.size < 16:
            continue
        if not (obj.min_addr <= f.addr <= obj.max_addr):
            continue
        res.append(Func(path, f.addr, f.size))
    return sorted(res, key=lambda x: x.addr)


def emulate(func, a, b, max_steps=600):
    """Cheap concrete emulation; None if it doesn't behave like a clean (u32,u32)->u32 function."""
    try:
        st = make_state(func.proj, func.addr, a, b)
        sm = func.proj.factory.simgr(st)
        for _ in range(max_steps):
            if not sm.active:
                break
            sm.step()
            if len(sm.active) > 4:
                return None
        if sm.active or len(sm.deadended) != 1:
            return None
        r = sm.deadended[0].regs.rax[31:0]
        return None if r.symbolic else sm.deadended[0].solver.eval(r)
    except Exception:
        return None


def discover(ref, path):
    """Find functions in a (stripped) library that behave like `ref` on the probe inputs.
    A probe mismatch is a sound rejection; surviving candidates still need the symbolic proof."""
    fr = native_fn(ref)
    expected = [fr(a, b) for a, b in PROBES]
    cands = candidates(path)
    survivors = []
    for c in cands:
        if all(emulate(c, a, b) == e for (a, b), e in zip(PROBES, expected)):
            survivors.append(c)
    return cands, survivors


# ============================================================ syntactic baseline (BinDiff stand-in)
def syntactic_features(func):
    code = func.proj.loader.memory.load(func.addr, func.size)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    mn = [i.mnemonic for i in md.disasm(code, func.addr)]
    f = get_cfg(func.path).kb.functions.function(addr=func.addr)
    blocks = len(list(f.blocks)) if f is not None else 1
    return set(zip(mn, mn[1:], mn[2:])), blocks


def syntactic_similarity(f1, f2):
    (t1, b1), (t2, b2) = syntactic_features(f1), syntactic_features(f2)
    return (len(t1 & t2) / max(1, len(t1 | t2)) + min(b1, b2) / max(b1, b2, 1)) / 2


# ============================================================ demo-table comparison
def compare(ref, path, stripped=False, dump=None):
    t0 = time.time()
    if not stripped:
        cand = exported_func(path)
        base = syntactic_similarity(ref, cand)
        out = prove(ref, cand, dump=dump)
        out["baseline"] = base
    else:
        cands, survivors = discover(ref, path)
        # a syntactic differ reports its best-looking match among ALL functions
        base = max((syntactic_similarity(ref, c) for c in cands), default=0.0)
        if not survivors:
            out = {"verdict": "NOT_FOUND", "baseline": base, "paths": (None, None),
                   "detail": f"{len(cands)} functions recovered, 0 consistent with reference on {len(PROBES)} probes"}
        else:
            cand = survivors[0]
            out = prove(ref, cand, dump=dump)
            out["baseline"] = base
            out["detail"] = (f"found {cand.name} ({len(survivors)}/{len(cands)} candidates passed probe); "
                             + out["detail"])
    out["time"] = time.time() - t0
    return out


if __name__ == "__main__":
    Z3_TIMEOUT_MS = 20_000
    ref = exported_func("build/ref_O0.so")
    cases = [
        ("a) recompiled -O3",                 "build/var_a_O3.so",          False),
        ("b) refactored/renamed",             "build/var_b_refactor.so",    False),
        ("c) flattened + opaque preds",       "build/var_c_flatten.so",     False),
        ("e) flatten + 1-layer MBA (8 rnds)", "build/var_e_mba.so",         False),
        ("f) STRIPPED -O3 (+4 decoys)",       "build/stripped_a_O3.so",     True),
        ("g) STRIPPED flatten+opaque (+decoys)", "build/stripped_c_flatten.so", True),
        ("d) input-dependent loop added",     "build/var_d_symloop.so",     False),
        ("N1) lookalike (1 const changed)",   "build/neg_lookalike.so",     False),
        ("N2) unrelated (FNV-style)",         "build/neg_unrelated.so",     False),
        ("N3) STRIPPED lookalike",            "build/stripped_lookalike.so", True),
    ]
    rows = []
    for name, path, stripped in cases:
        print(f"[*] {name} ...", flush=True)
        r = compare(ref, path, stripped, dump=None if stripped else f"build/query_{os.path.basename(path)}.smt2")
        rows.append((name, r))
        print(f"    {r['verdict']}  ({r['time']:.1f}s)  {r['detail']}", flush=True)
    print("\n" + "=" * 118)
    print(f"{'variant':36} {'syntactic':>10} {'Lineage verdict':>16} {'time':>7}   detail")
    print("-" * 118)
    for name, r in rows:
        print(f"{name:36} {r['baseline']*100:9.1f}% {r['verdict']:>16} {r['time']:6.1f}s   {r['detail'][:60]}")
