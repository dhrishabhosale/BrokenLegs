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
import os, re, sys, time, random, ctypes, logging
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


# ============================================================ function signatures
class Sig:
    """Mini signature language, e.g. "u32,u32->u32", "u8,u16,u64->u16", "buf16,len16->u32".
    u8/u16/u32/u64 (i* accepted; treated as bit-patterns), bufN = pointer to N symbolic bytes (read-only as far as
    verification is concerned), lenN = constant size_t N.  1-6 register arguments; return value in rax."""
    def __init__(self, text="u32,u32->u32"):
        self.text = text.replace(" ", "")
        if "->" not in self.text:
            raise ValueError("signature must look like 'u32,u32->u32'")
        a, r = self.text.split("->", 1)
        m = re.fullmatch(r"[ui](8|16|32|64)", r)
        if not m:
            raise ValueError(f"bad return type '{r}' (use u8/u16/u32/u64)")
        self.ret, self.args = int(m.group(1)), []
        for tok in filter(None, a.split(",")):
            m = re.fullmatch(r"[ui](8|16|32|64)", tok)
            if m:
                self.args.append(("int", int(m.group(1))))
                continue
            m = re.fullmatch(r"(buf|len)(\d{1,3})", tok)
            if m and 1 <= int(m.group(2)) <= 256:
                self.args.append((m.group(1), int(m.group(2))))
                continue
            raise ValueError(f"bad argument '{tok}' (use u8/u16/u32/u64, bufN or lenN with N<=256)")
        if not 1 <= len(self.args) <= 6:
            raise ValueError("1 to 6 arguments are supported")

    @property
    def default(self):
        return self.text == "u32,u32->u32"


DEFAULT_SIG = Sig()
_INPUTS = {}


def symbolic_inputs(sig):
    """Shared symbolic inputs for a signature (both functions must see the SAME variables)."""
    if sig.text not in _INPUTS:
        if sig.default:
            _INPUTS[sig.text] = [A, B]
        else:
            ins = []
            for i, (k, p) in enumerate(sig.args):
                ins.append(claripy.BVS(f"x{i}", p) if k == "int" else
                           [claripy.BVS(f"b{i}_{j}", 8) for j in range(p)] if k == "buf" else p)
            _INPUTS[sig.text] = ins
    return _INPUTS[sig.text]


def _zero(sig):
    return [0 if k == "int" else bytes(p) if k == "buf" else p for k, p in sig.args]


def random_inputs(sig, rng):
    return [rng.getrandbits(p) if k == "int" else rng.randbytes(p) if k == "buf" else p for k, p in sig.args]


def edge_inputs(sig, rng):
    """Boundary values, varying one argument at a time against a random base, plus all-zero / all-ones."""
    base, out = random_inputs(sig, rng), []
    for i, (k, p) in enumerate(sig.args):
        if k == "len":
            continue
        alts = (sorted({0, 1, 2, (1 << (p - 1)) - 1, 1 << (p - 1), (1 << p) - 1, 0xDEADBEEF & ((1 << p) - 1)}) if k == "int"
                else [bytes(p), b"\xff" * p, bytes(range(p)), b"\x80" * p])
        for e in alts:
            v = list(base)
            v[i] = e
            out.append(v)
    out.append(_zero(sig))
    out.append([(1 << p) - 1 if k == "int" else b"\xff" * p if k == "buf" else p for k, p in sig.args])
    return out


def probes(sig):
    if sig.default:
        return [list(p) for p in PROBES]
    rng = random.Random(1234)
    return [_zero(sig)] + [random_inputs(sig, rng) for _ in range(5)]


def fmt_args(sig, vals):
    return ", ".join(f"{chr(97 + i)}=" + (f"{v:#x}" if isinstance(v, int) else v.hex()) for i, v in enumerate(vals))


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


def exported_func(path, symbol=None):
    proj = get_proj(path)
    sym = proj.loader.find_symbol(symbol or SYMBOL)
    if sym is None:
        raise LookupError(f"symbol '{symbol or SYMBOL}' not found in {os.path.basename(path)} "
                          "(stripped? give a function address or use auto-discover)")
    return Func(path, sym.rebased_addr, sym.size, symbol or SYMBOL)


def func_at_va(path, va):
    """Function at a link-time virtual address (as shown by objdump)."""
    obj = get_proj(path).loader.main_object
    addr = va - obj.linked_base + obj.mapped_base
    f = get_cfg(path).kb.functions.function(addr=addr)
    if f is None:
        raise LookupError(f"no function recovered at {va:#x} in {os.path.basename(path)}")
    return Func(path, addr, f.size)


# ============================================================ native execution
def _native_base(path):
    real = os.path.realpath(path)
    for line in open("/proc/self/maps"):
        p = line.split()
        if len(p) >= 6 and p[5] == real and int(p[2], 16) == 0:
            return int(p[0].split("-")[0], 16)
    raise RuntimeError("library not mapped")


_CT = {8: ctypes.c_uint8, 16: ctypes.c_uint16, 32: ctypes.c_uint32, 64: ctypes.c_uint64}


def native_fn(func, sig=None):
    """Callable f(*vals) for ANY function (exported or not) by address arithmetic on the mapped library."""
    sig = sig or DEFAULT_SIG
    if func.path not in _LIB:
        _LIB[func.path] = ctypes.CDLL(os.path.realpath(func.path))
    addr = _native_base(func.path) + (func.addr - func.proj.loader.main_object.mapped_base)
    ats = [_CT[p] if k == "int" else ctypes.c_void_p if k == "buf" else ctypes.c_size_t for k, p in sig.args]
    cf = ctypes.CFUNCTYPE(_CT[sig.ret], *ats)(addr)
    if all(k == "int" for k, _ in sig.args):
        return cf                                   # fast path

    def call(*vals):
        args, keep = [], []
        for (k, p), v in zip(sig.args, vals):
            if k == "buf":
                b = ctypes.create_string_buffer(bytes(v), len(v))
                keep.append(b)
                args.append(ctypes.cast(b, ctypes.c_void_p))
            else:
                args.append(p if k == "len" else v)
        return cf(*args)
    return call


def callable_for(func, sig=None):
    """(callable, emulated?) - native if the library can be dlopen'ed, else a slow angr-emulated stand-in."""
    sig = sig or DEFAULT_SIG
    try:
        return native_fn(func, sig), False
    except Exception:
        return (lambda *v: emulate(func, sig, list(v))), True


def differential_test(fa, fb, sig=None, n=FUZZ_SAMPLES, seed=0xC0FFEE):
    sig = sig or DEFAULT_SIG
    rng = random.Random(seed)
    for v in edge_inputs(sig, rng):
        if fa(*v) != fb(*v):
            return False, v, 0
    for i in range(n):
        v = random_inputs(sig, rng)
        if fa(*v) != fb(*v):
            return False, v, i
    return True, None, n


# ============================================================ symbolic extraction + SMT
def make_state(proj, addr, sig, vals):
    """Call state with args written straight into the ABI argument registers (and buffers into memory).
    (Passing claripy values through call_state() relies on prototype guessing, which breaks on some angr versions.)"""
    st = proj.factory.call_state(addr, add_options={
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    bits, nxt = proj.arch.bits, 0x600000
    for reg, (k, p), v in zip(proj.factory.cc().ARG_REGS, sig.args, vals):
        if k == "int":
            bv = claripy.BVV(v, p) if isinstance(v, int) else v
            val = claripy.ZeroExt(bits - p, bv) if p < bits else bv
        elif k == "buf":
            bs = [claripy.BVV(x, 8) for x in v] if isinstance(v, (bytes, bytearray)) else list(v)
            st.memory.store(nxt, bs[0] if len(bs) == 1 else claripy.Concat(*bs))
            val = claripy.BVV(nxt, bits)
            nxt += 0x1000
        else:
            val = claripy.BVV(p, bits)
        setattr(st.regs, reg, val)
    return st


def summarize(func, sig=None):
    """Symbolically run func on shared symbolic inputs. Returns ([(constraints, ret)], info) or (None, info). Cached."""
    sig = sig or DEFAULT_SIG
    key = (func.path, func.addr, sig.text)
    if key in _SUMMARY:
        return _SUMMARY[key]
    proj = func.proj
    simgr = proj.factory.simgr(make_state(proj, func.addr, sig, symbolic_inputs(sig)))
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
        paths = [(list(s.solver.constraints), s.regs.rax[sig.ret - 1:0]) for s in simgr.deadended]
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


def _extract(m, sig):
    ev = lambda v, bits: m.eval(z3.BitVec(v.args[0], bits), model_completion=True).as_long()
    out = []
    for (k, p), v in zip(sig.args, symbolic_inputs(sig)):
        out.append(ev(v, p) if k == "int" else bytes(ev(b, 8) for b in v) if k == "buf" else p)
    return out


def smt_equivalence(pa, pb, dump=None, sig=None):
    """Any input and pair of paths feasible together with ret_A != ret_B?
    Returns ('UNSAT'|'SAT'|'UNKNOWN', cex values or None, info)."""
    sig = sig or DEFAULT_SIG
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
        dz = z3.Solver()
        dz.add(formula)
        open(dump, "w").write(dz.to_smt2())
    # Restart portfolio: counterexample search is heavy-tailed in the random seed, so run several short
    # seeded attempts, then one long attempt with the remaining budget.
    short = min(2000, Z3_TIMEOUT_MS // 5)
    spent = 0
    for seed in range(5):
        budget = short if seed < 4 else max(1000, Z3_TIMEOUT_MS - spent)
        z = z3.Then("simplify", "bit-blast", "sat").solver()
        z.set("timeout", budget)
        z.set("random_seed", seed)
        z.set("sat.random_seed", seed)
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
            return "SAT", _extract(z.model(), sig), info
    info["why"] = "Z3 timeout"
    return "UNKNOWN", None, info


def prove(ref, cand, dump=None, fuzz_n=FUZZ_SAMPLES, sig=None):
    """Full verdict for one (reference, candidate) pair under signature `sig`."""
    sig = sig or DEFAULT_SIG
    t0 = time.time()
    sa, ia = summarize(ref, sig)
    sb, ib = summarize(cand, sig)
    out = {"paths": (ia.get("paths"), ib.get("paths")), "cex": None, "signature": sig.text}
    (fa, ea), (fb, eb) = callable_for(ref, sig), callable_for(cand, sig)
    out["emulated"] = ea or eb          # no native execution available: weaker evidence, fewer samples
    if out["emulated"]:
        fuzz_n = min(fuzz_n, 300)

    def fallback(why):
        ok, cex, n = differential_test(fa, fb, sig, n=fuzz_n)
        out["verdict"] = "TESTED" if ok else "NOT_EQUIVALENT"
        out["cex"] = cex
        out["detail"] = f"{why}; fuzz {n} samples" + (f", cex: {fmt_args(sig, cex)}" if cex else "")

    if sa is None or sb is None:
        out["reason"] = ia.get("reason") or ib.get("reason")
        fallback(f"symbolic gave up ({out['reason']})")
    else:
        res, cex, info = smt_equivalence(sa, sb, dump, sig)
        out.update({k: v for k, v in info.items() if k != "why"})
        if res == "UNSAT":
            out["verdict"] = "PROVED"
            out["detail"] = f"UNSAT: no input differs (paths {ia['paths']}x{ib['paths']})"
        elif res == "SAT":
            va, vb = fa(*cex), fb(*cex)
            out["verdict"] = "NOT_EQUIVALENT"
            out["cex"] = cex
            out["detail"] = (f"Z3 cex {fmt_args(sig, cex)}: ref={va:#x} cand={vb:#x} "
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


def emulate(func, sig, vals, max_steps=600):
    """Cheap concrete emulation; None if it doesn't behave like a clean function with this signature."""
    try:
        sm = func.proj.factory.simgr(make_state(func.proj, func.addr, sig, vals))
        for _ in range(max_steps):
            if not sm.active:
                break
            sm.step()
            if len(sm.active) > 4:
                return None
        if sm.active or len(sm.deadended) != 1:
            return None
        r = sm.deadended[0].regs.rax[sig.ret - 1:0]
        return None if r.symbolic else sm.deadended[0].solver.eval(r)
    except Exception:
        return None


def discover(ref, path, sig=None):
    """Find functions in a (stripped) library that behave like `ref` on the probe inputs.
    A probe mismatch is a sound rejection; surviving candidates still need the symbolic proof."""
    sig = sig or DEFAULT_SIG
    fr, _ = callable_for(ref, sig)
    pr = probes(sig)
    expected = [fr(*v) for v in pr]
    cands = candidates(path)
    survivors = [c for c in cands if all(emulate(c, sig, v) == e for v, e in zip(pr, expected))]
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
def compare(ref, path, stripped=False, dump=None, sig=None):
    t0 = time.time()
    if not stripped:
        cand = exported_func(path)
        base = syntactic_similarity(ref, cand)
        out = prove(ref, cand, dump=dump, sig=sig)
        out["baseline"] = base
    else:
        cands, survivors = discover(ref, path, sig)
        # a syntactic differ reports its best-looking match among ALL functions
        base = max((syntactic_similarity(ref, c) for c in cands), default=0.0)
        if not survivors:
            out = {"verdict": "NOT_FOUND", "baseline": base, "paths": (None, None),
                   "detail": f"{len(cands)} functions recovered, 0 consistent with reference on {len(probes(sig or DEFAULT_SIG))} probes"}
        else:
            cand = survivors[0]
            out = prove(ref, cand, dump=dump, sig=sig)
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
