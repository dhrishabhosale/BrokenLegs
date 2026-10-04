#!/usr/bin/env python3
"""Run one comparison described by <dir>/spec.json and write <dir>/result.json (used by the web app)."""
import sys, os, json, hashlib
import angr
import lineage as L

d = sys.argv[1]
spec = json.load(open(os.path.join(d, "spec.json")))
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]
res = {"label": spec.get("label"), "ref_file": spec.get("ref_name"), "cand_file": spec.get("cand_name"),
       "ref_sha256_16": sha(spec["ref"]), "cand_sha256_16": sha(spec["cand"]), "angr": angr.__version__,
       "budgets": {"max_paths": L.MAX_PATHS, "max_dag_nodes": L.MAX_DAG_NODES,
                   "z3_timeout_s": int(spec.get("z3_timeout", 20)), "fuzz_samples": L.FUZZ_SAMPLES}}


def pick(path, sym, addr):
    return L.func_at_va(path, int(addr, 16)) if addr else L.exported_func(path, sym or None)


try:
    sig = L.Sig(spec.get("sig") or "u32,u32->u32")
    res["signature"] = sig.text
    L.Z3_TIMEOUT_MS = int(spec.get("z3_timeout", 20)) * 1000
    print("analysing reference...", flush=True)
    ref = pick(spec["ref"], spec.get("ref_symbol"), spec.get("ref_addr"))
    res["ref_function"] = repr(ref)
    print("comparing (symbolic execution + Z3, fuzz fallback)...", flush=True)
    if spec.get("cand_auto"):
        out = L.compare(ref, spec["cand"], stripped=True, sig=sig)
    else:
        cand = pick(spec["cand"], spec.get("cand_symbol"), spec.get("cand_addr"))
        res["cand_function"] = repr(cand)
        out = L.prove(ref, cand, sig=sig)
        out["baseline"] = L.syntactic_similarity(ref, cand)
    for k in ("verdict", "detail", "baseline", "time", "paths", "dag_nodes", "tree_nodes", "cex", "reason", "emulated"):
        if k in out:
            res[k] = out[k]
    if res.get("cex"):
        res["cex"] = [f"{v:#x}" if isinstance(v, int) else v.hex() for v in res["cex"]]
    res["status"] = "ok"
except Exception as e:
    res.update(status="error", error=f"{type(e).__name__}: {e}")
json.dump(res, open(os.path.join(d, "result.json"), "w"), indent=1, default=str)
print("done:", res.get("verdict") or res.get("error"), flush=True)
