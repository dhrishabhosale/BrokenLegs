#!/usr/bin/env python3
"""Lineage control panel.  pip install flask && python3 webapp.py  ->  http://127.0.0.1:5000
 1. Compare two files (.so libraries or .c sources) and get a verdict + report
 2. Tests: run a preset pair from build/ against the reference
 3. Batch experiments (demo table, mutation sweep, scaling grid) as detached background jobs
AI report: set ANTHROPIC_API_KEY (optional LINEAGE_MODEL). Only the JSON result summary is sent, never the files.
Without a key a deterministic template report is used. Uploaded code is compiled and EXECUTED locally to confirm
results: only upload files you trust. Binds to localhost."""
import os, re, json, signal, secrets, subprocess, sys, time, urllib.request
from flask import Flask, jsonify, request, send_from_directory, Response

ROOT = os.path.dirname(os.path.abspath(__file__))
JOBS_DIR = os.path.join(ROOT, "jobs")
BUILD = os.path.join(ROOT, "build")
os.makedirs(JOBS_DIR, exist_ok=True)

JOBS = {
    "build":   dict(title="Build binaries", cmd="./build.sh", eta="~10 s", desc="Compiles the reference, variants, stripped libraries, fuzzer."),
    "main":    dict(title="Demo table", cmd="python3 lineage.py", eta="~1.5 min", desc="All variants vs. the syntactic baseline."),
    "sweep":   dict(title="Mutation sweep", cmd="python3 mutation_sweep.py", eta="~1.5 min", desc="67 mutants: SMT proof vs. fuzzing. Writes results/sweep.*"),
    "scaling": dict(title="Scaling grid", cmd="python3 scaling.py --rerun", eta="~5 min", desc="Rounds x obfuscation level. Writes results/scaling.*"),
}
IMAGES = {"sweep": "results/sweep_detection.png", "scaling": "results/scaling.png"}
# preset tests: key -> (label, candidate file in build/, candidate is stripped?)
TESTS = {
    "a":  ("a) recompiled -O3", "var_a_O3.so", False), "b": ("b) refactored / renamed", "var_b_refactor.so", False),
    "c":  ("c) flattened + opaque predicates", "var_c_flatten.so", False), "e": ("e) flattened + 1-layer MBA (solver wall)", "var_e_mba.so", False),
    "d":  ("d) input-dependent loop (path explosion)", "var_d_symloop.so", False), "f": ("f) STRIPPED -O3 + decoys", "stripped_a_O3.so", True),
    "g":  ("g) STRIPPED flattened + decoys", "stripped_c_flatten.so", True), "N1": ("N1) lookalike, one constant changed", "neg_lookalike.so", False),
    "N2": ("N2) unrelated hash", "neg_unrelated.so", False), "N3": ("N3) STRIPPED lookalike", "stripped_lookalike.so", True),
}

ALL_TESTS = {k: dict(label=v[0], ref="ref_O0.so", cand=v[1], stripped=v[2], sig="u32,u32->u32") for k, v in TESTS.items()}
for _k, _l, _r, _c, _s in [
        ("s1", "u64: recompiled -O3  [u64,u64->u64]", "sig/u64_ref.so", "sig/u64_O3.so", "u64,u64->u64"),
        ("s2", "u64: lookalike, one constant changed", "sig/u64_ref.so", "sig/u64_lookalike.so", "u64,u64->u64"),
        ("s3", "mixed widths: recompiled -O3  [u8,u16,u32->u16]", "sig/mixed_ref.so", "sig/mixed_O3.so", "u8,u16,u32->u16"),
        ("s4", "mixed widths: lookalike (shift changed)", "sig/mixed_ref.so", "sig/mixed_lookalike.so", "u8,u16,u32->u16"),
        ("s5", "16-byte buffer hash: recompiled -O3  [buf16,len16->u32]", "sig/buf_ref.so", "sig/buf_O3.so", "buf16,len16->u32"),
        ("s6", "16-byte buffer hash: ignores the last byte", "sig/buf_ref.so", "sig/buf_skip.so", "buf16,len16->u32")]:
    ALL_TESTS[_k] = dict(label=_l, ref=_r, cand=_c, stripped=False, sig=_s)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 40 * 1024 * 1024


def f(job, ext):
    return os.path.join(JOBS_DIR, f"{job}.{ext}")


def read(path, default=""):
    try:
        return open(path).read().strip()
    except OSError:
        return default


def status(job):
    if not os.path.exists(f(job, "pid")):
        return "idle"
    if os.path.exists(f(job, "exit")):
        return "done" if read(f(job, "exit")) == "0" else "failed"
    try:
        os.kill(int(read(f(job, "pid"))), 0)
        return "running"
    except (OSError, ValueError):
        return "stopped"


def running_job():
    names = [n[:-4] for n in os.listdir(JOBS_DIR) if n.endswith(".pid")]
    return next((j for j in names if status(j) == "running"), None)


def launch(job, cmd):
    for ext in ("exit", "pid"):
        if os.path.exists(f(job, ext)):
            os.remove(f(job, ext))
    proc = subprocess.Popen(["sh", "-c", f"{cmd}; echo $? > '{f(job, 'exit')}'"], cwd=ROOT, stdout=open(f(job, "log"), "w"),
                            stderr=subprocess.STDOUT, start_new_session=True, env=dict(os.environ, PYTHONUNBUFFERED="1"))
    open(f(job, "start"), "w").write(str(time.time()))
    open(f(job, "pid"), "w").write(str(proc.pid))


def tail(job, n=300):
    return "\n".join(l for l in read(f(job, "log")).splitlines() if "unicorn" not in l)[-20000:] if n else ""


# ------------------------------------------------------------------ batch jobs
@app.get("/api/status")
def api_status():
    out = {}
    for j, meta in JOBS.items():
        img = IMAGES.get(j)
        ok = img and os.path.exists(os.path.join(ROOT, img))
        st = read(f(j, "start"), "0")
        out[j] = dict(meta, status=status(j), image=img if ok else None, image_v=os.path.getmtime(os.path.join(ROOT, img)) if ok else None,
                      elapsed=(time.time() - float(st)) if status(j) == "running" and st else None)
    return jsonify(out)


@app.post("/api/start/<job>")
def api_start(job):
    if job not in JOBS:
        return jsonify(error="unknown job"), 404
    if (r := running_job()):
        return jsonify(error=f"'{r}' is already running (one at a time so timings stay meaningful)"), 409
    if job != "build" and not os.path.exists(os.path.join(BUILD, "ref_O0.so")):
        return jsonify(error="Run 'Build binaries' first"), 400
    launch(job, JOBS[job]["cmd"])
    return jsonify(ok=True)


@app.post("/api/stop/<job>")
def api_stop(job):
    if re.fullmatch(r"[\w]+", job) and status(job) == "running":
        os.killpg(int(read(f(job, "pid"))), signal.SIGTERM)
    return jsonify(ok=True)


@app.get("/api/log/<job>")
def api_log(job):
    return Response(tail(job) if job in JOBS else "", mimetype="text/plain")


@app.get("/results/<path:name>")
def results(name):
    return send_from_directory(os.path.join(ROOT, "results"), name)


# ------------------------------------------------------------------ comparisons
def new_cmp(spec):
    cid = "cmp_" + time.strftime("%H%M%S") + secrets.token_hex(2)
    d = os.path.join(JOBS_DIR, cid)
    os.makedirs(d)
    return cid, d


def start_cmp(cid, d, spec):
    json.dump(spec, open(os.path.join(d, "spec.json"), "w"))
    launch(cid, f"'{sys.executable}' compare_job.py '{d}'")


@app.get("/api/tests")
def api_tests():
    return jsonify([dict(key=k, label=t["label"], available=os.path.exists(os.path.join(BUILD, t["cand"]))) for k, t in ALL_TESTS.items()])


@app.post("/api/test/<key>")
def api_test(key):
    t = ALL_TESTS.get(key)
    if not t:
        return jsonify(error="unknown test"), 404
    if (r := running_job()):
        return jsonify(error=f"'{r}' is already running"), 409
    if not os.path.exists(os.path.join(BUILD, t["cand"])):
        return jsonify(error="Run 'Build binaries' first"), 400
    cid, d = new_cmp(None)
    start_cmp(cid, d, dict(label=t["label"], ref=os.path.join(BUILD, t["ref"]), ref_name=t["ref"] + " (reference)",
                           cand=os.path.join(BUILD, t["cand"]), cand_name=t["cand"], cand_auto=t["stripped"], sig=t["sig"], z3_timeout=20))
    return jsonify(id=cid)


@app.post("/api/compare")
def api_compare():
    if (r := running_job()):
        return jsonify(error=f"'{r}' is already running"), 409
    cid, d = new_cmp(None)
    form, spec = request.form, {"label": "Uploaded files", "z3_timeout": max(5, min(300, int(form.get("z3_timeout") or 20)))}
    for role in ("ref", "cand"):
        up = request.files.get(role)
        if not up or not up.filename:
            return jsonify(error=f"missing {role} file"), 400
        path = os.path.join(d, role + (".c" if up.filename.lower().endswith(".c") else ".so"))
        up.save(path)
        if path.endswith(".c"):
            opt = form.get(role + "_opt", "-O0")
            if opt not in ("-O0", "-O1", "-O2", "-O3"):
                opt = "-O0"
            out = os.path.join(d, role + ".so")
            r = subprocess.run(["gcc", "-shared", "-fPIC", "-fcf-protection=none", "-fno-stack-protector", opt, path, "-o", out],
                               capture_output=True, text=True, timeout=60)
            if r.returncode:
                return jsonify(error=f"{role}: gcc failed: {r.stderr[:400]}"), 400
            path = out
        spec[role], spec[role + "_name"] = path, os.path.basename(up.filename)
        spec[role + "_symbol"] = form.get(role + "_symbol", "").strip()
        spec[role + "_addr"] = form.get(role + "_addr", "").strip()
    spec["cand_auto"] = form.get("cand_auto") == "on"
    spec["sig"] = (form.get("signature") or "u32,u32->u32").strip()
    start_cmp(cid, d, spec)
    return jsonify(id=cid)


@app.get("/api/cmp/<cid>")
def api_cmp(cid):
    if not re.fullmatch(r"cmp_\w+", cid):
        return jsonify(error="bad id"), 400
    d = os.path.join(JOBS_DIR, cid)
    res = read(os.path.join(d, "result.json"))
    rep = read(os.path.join(d, "report.json"))
    return jsonify(status=status(cid), result=json.loads(res) if res else None, report=json.loads(rep) if rep else None, log=tail(cid))


EXPLAIN = {
    "PROVED": "Z3 showed no input exists on which the two functions differ: they compute the same function (under the tool's lifting assumptions).",
    "TESTED": "No difference was found on random inputs, but a proof was not possible. This is statistical evidence, not proof; a rare-trigger difference could be missed.",
    "NOT_EQUIVALENT": "A concrete input exists on which the functions give different outputs, so they are not the same function.",
    "NOT_FOUND": "No function in the candidate behaved like the reference on the probe inputs.",
}


def template_report(r):
    v = r.get("verdict", "ERROR")
    lines = [f"VERDICT: {v}", EXPLAIN.get(v, r.get("error", "The comparison did not complete.")), "", "EVIDENCE"]
    lines.append(f"- Reference: {r.get('ref_file')} ({r.get('ref_function', '?')}); candidate: {r.get('cand_file')} {r.get('cand_function', '')}")
    if r.get("detail"):
        lines.append(f"- {r['detail']}")
    if r.get("baseline") is not None:
        lines.append(f"- A syntactic differ would score these {r['baseline'] * 100:.0f}% similar" +
                     (" (despite the verdict above: syntax is not behaviour)." if v in ("PROVED", "NOT_EQUIVALENT") else "."))
    if r.get("reason"):
        lines.append(f"- Symbolic proof not completed because: {r['reason']}")
    if r.get("emulated"):
        lines.append("- Native execution was unavailable; fewer, emulated samples were used (weaker evidence).")
    b = r.get("budgets", {})
    lines += ["", "LIMITS", f"- Budgets: {b.get('max_paths')} paths, {b.get('z3_timeout_s')} s Z3, {b.get('max_dag_nodes')} expression nodes.",
              f"- Assumes signature {r.get('signature', 'u32,u32->u32')} on x86-64 (buffers are fixed-length and read-only). Equivalence is not proof of copying: independent implementations of one spec are also equivalent."]
    return "\n".join(lines)


SYSTEM = ("You write short technical comparison reports for a binary-equivalence tool called Lineage. Use ONLY the facts in the JSON given. "
          "Sections: Verdict, Evidence, What this does and does not show, Suggested next step. PROVED = equal for all inputs per Z3 (under lifting "
          "assumptions). TESTED = no difference in N random inputs: statistical, not proof. NOT_EQUIVALENT = counterexample exists (say if it was "
          "confirmed natively). NOT_FOUND = no candidate function matched the reference on probes. Never assert code theft or any legal conclusion; "
          "equivalence is not proof of copying. Mention any budget/timeout that limited the result. Under 250 words, plain text.")


def ai_report(r):
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return template_report(r), "template (set ANTHROPIC_API_KEY for an AI-written report)"
    body = json.dumps(dict(model=os.environ.get("LINEAGE_MODEL", "claude-sonnet-5-5"), max_tokens=900, system=SYSTEM,
                           messages=[dict(role="user", content="Result JSON:\n" + json.dumps(r, indent=1, default=str))])).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, method="POST",
                                 headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    try:
        out = json.load(urllib.request.urlopen(req, timeout=60))
        return "".join(b.get("text", "") for b in out["content"]).strip(), "AI (" + out.get("model", "claude") + ")"
    except Exception as e:
        return template_report(r), f"template (AI call failed: {type(e).__name__})"


@app.post("/api/report/<cid>")
def api_report(cid):
    if not re.fullmatch(r"cmp_\w+", cid):
        return jsonify(error="bad id"), 400
    d = os.path.join(JOBS_DIR, cid)
    raw = read(os.path.join(d, "result.json"))
    if not raw:
        return jsonify(error="no result yet"), 400
    text, source = ai_report(json.loads(raw))
    json.dump(dict(text=text, source=source), open(os.path.join(d, "report.json"), "w"))
    return jsonify(text=text, source=source)


PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Lineage</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#fff;--fg:#1c1e21;--card:#f5f6f8;--mut:#6b7280;--line:#dfe2e6;--ok:#15803d;--bad:#b91c1c;--run:#1d4ed8;--btn:#1d4ed8;--warn:#b45309}
@media(prefers-color-scheme:dark){:root{--bg:#14161a;--fg:#e6e8eb;--card:#1d2026;--mut:#9aa3af;--line:#2c313a;--ok:#4ade80;--bad:#f87171;--run:#60a5fa;--btn:#3b82f6;--warn:#fbbf24}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}main{max-width:980px;margin:0 auto;padding:24px 16px}
h1{margin:0;font-size:22px}h2{font-size:16px;margin:0 0 8px}p.sub{color:var(--mut);margin:2px 0 18px}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:14px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.grow{flex:1}label{font-size:13px;color:var(--mut);display:block}input,select{font:inherit;padding:5px 7px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);max-width:100%}
input[type=text],input[type=number]{width:130px}.badge{font-size:12px;padding:2px 9px;border-radius:99px;border:1px solid var(--line);color:var(--mut)}
.running{color:var(--run);border-color:var(--run)}.done,.PROVED{color:var(--ok);border-color:var(--ok)}.failed,.stopped,.NOT_EQUIVALENT,.error{color:var(--bad);border-color:var(--bad)}.TESTED,.NOT_FOUND{color:var(--warn);border-color:var(--warn)}
button{background:var(--btn);color:#fff;border:0;border-radius:6px;padding:7px 14px;font-size:14px;cursor:pointer}button.stop{background:var(--bad)}button.alt{background:transparent;color:var(--btn);border:1px solid var(--btn)}button:disabled{opacity:.4}
.sub2{color:var(--mut);font-size:13px}.warn{color:var(--warn);font-size:12.5px;margin-top:8px}pre{background:#0d1117;color:#d1d5db;border-radius:8px;padding:10px;font-size:12px;max-height:280px;overflow:auto;margin:8px 0 0}
pre.rep{background:var(--bg);color:var(--fg);border:1px solid var(--line);white-space:pre-wrap;font:14px/1.5 system-ui;max-height:none}table{border-collapse:collapse;font-size:13.5px;margin-top:8px}td{padding:2px 14px 2px 0;vertical-align:top}td:first-child{color:var(--mut)}
img{max-width:100%;margin-top:10px;border-radius:8px;border:1px solid var(--line);background:#fff}#err{color:var(--bad);min-height:20px}details summary{cursor:pointer;color:var(--mut);font-size:13px;margin-top:8px}
</style></head><body><main>
<h1>Lineage</h1><p class="sub">Do two compiled functions compute the same thing? Proof where possible, evidence where not.</p><div id="err"></div>

<div class="card"><h2>1. Compare two files</h2>
<form id="cf"><div class="row">
 <div><label>Reference (.so or .c)</label><input type="file" name="ref" required></div>
 <div><label>Candidate (.so or .c)</label><input type="file" name="cand" required></div></div>
<div class="row" style="margin-top:10px">
 <div><label>ref symbol</label><input type="text" name="ref_symbol" placeholder="lineage_f"></div>
 <div><label>cand symbol</label><input type="text" name="cand_symbol" placeholder="lineage_f"></div>
 <div><label>ref addr (hex, optional)</label><input type="text" name="ref_addr" placeholder="0x1129"></div>
 <div><label>cand addr (hex, optional)</label><input type="text" name="cand_addr" placeholder="0x1129"></div>
 <div><label>signature</label><input type="text" name="signature" value="u32,u32->u32" style="width:190px"></div></div>
<div class="row" style="margin-top:10px">
 <div><label>.c ref opt</label><select name="ref_opt"><option>-O0</option><option>-O1</option><option>-O2</option><option>-O3</option></select></div>
 <div><label>.c cand opt</label><select name="cand_opt"><option>-O3</option><option>-O0</option><option>-O1</option><option>-O2</option></select></div>
 <div><label>Z3 timeout (s)</label><input type="number" name="z3_timeout" value="20" min="5" max="300" style="width:80px"></div>
 <label style="align-self:end"><input type="checkbox" name="cand_auto"> candidate is stripped: auto-discover the function</label>
 <div class="grow"></div><button id="cbtn" style="align-self:end">Compare</button></div></form>
<p class="sub2" style="margin-bottom:0">x86-64, integer/pointer args in registers (1-6). Signature examples: <code>u32,u32->u32</code>, <code>u64,u64->u64</code>, <code>u8,u16,u32->u16</code>, <code>buf16,len16->u32</code> (pointer to 16 symbolic bytes + its length). Default symbol: <code>lineage_f</code>.</p>
<div class="warn">Uploaded code is compiled and executed locally to confirm results. Only upload files you trust.</div></div>

<div class="card"><h2>2. Tests</h2><div class="row"><select id="tsel" class="grow"></select><button id="tbtn">Run test</button></div>
<p class="sub2" style="margin-bottom:0">Each test compares a prepared variant from <code>build/</code> against the reference. Run "Build binaries" below first.</p></div>

<div class="card" id="res" style="display:none"><div class="row"><h2 id="rt" class="grow" style="margin:0"></h2><span id="rb" class="badge"></span></div>
<p id="rx" class="sub2"></p><table id="rtab"></table>
<div class="row" style="margin-top:12px"><button class="alt" id="rep">Generate report</button><span id="rsrc" class="sub2"></span></div>
<pre class="rep" id="rtext" style="display:none"></pre><details><summary>Log</summary><pre id="rlog"></pre></details></div>

<h2 style="margin:22px 0 8px">3. Batch experiments</h2><div id="jobs"></div>
</main><script>
let cur=null, busy=false;const $=id=>document.getElementById(id);
const EX={PROVED:"Equal for all inputs (Z3 proof).",TESTED:"No difference found on random inputs; not a proof.",NOT_EQUIVALENT:"A counterexample exists: not the same function.",NOT_FOUND:"No function in the candidate matched the reference."};
async function api(url,opt){const r=await fetch(url,opt);const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||r.statusText);return j}
const fail=e=>$('err').textContent=e.message||e, clear=()=>$('err').textContent='';
function begin(id){cur=id;$('res').style.display='';$('rtext').style.display='none';$('rsrc').textContent='';$('rep').disabled=true;pollCmp()}
$('cf').onsubmit=async e=>{e.preventDefault();clear();try{begin((await api('/api/compare',{method:'POST',body:new FormData($('cf'))})).id)}catch(x){fail(x)}};
$('tbtn').onclick=async()=>{clear();try{begin((await api('/api/test/'+$('tsel').value,{method:'POST'})).id)}catch(x){fail(x)}};
$('rep').onclick=async()=>{$('rep').disabled=true;$('rsrc').textContent='writing report...';try{const r=await api('/api/report/'+cur,{method:'POST'});showRep(r)}catch(x){fail(x)}$('rep').disabled=false};
function showRep(r){$('rtext').textContent=r.text;$('rtext').style.display='';$('rsrc').textContent='source: '+r.source}
async function pollCmp(){if(!cur)return;const d=await api('/api/cmp/'+cur);const r=d.result;
  $('rt').textContent=(r&&r.label)||'Running...';const v=r?(r.verdict||'error'):d.status;$('rb').textContent=v;$('rb').className='badge '+v;
  $('rx').textContent=r?(EX[r.verdict]||r.error||''):'analysing: symbolic execution, Z3, fuzz fallback...';
  const t=$('rtab');t.innerHTML='';if(r){const rows=[['reference',r.ref_file],['candidate',r.cand_file],['detail',r.detail],['syntactic similarity',r.baseline!=null?(r.baseline*100).toFixed(0)+'%':null],
    ['time',r.time!=null?r.time.toFixed(1)+' s':null],['expression DAG nodes',r.dag_nodes],['fallback reason',r.reason],['signature',r.signature],['counterexample',r.cex?r.cex.join(', '):null],['error',r.error]];
    for(const[k,val]of rows)if(val!=null&&val!==''){const tr=t.insertRow();tr.insertCell().textContent=k;tr.insertCell().textContent=val}}
  $('rlog').textContent=d.log||'';$('rep').disabled=!r;if(d.report&&$('rtext').style.display==='none')showRep(d.report);
  if(d.status==='running'&&!r)setTimeout(pollCmp,1500)}
async function loadTests(){const ts=await api('/api/tests');$('tsel').innerHTML='';for(const t of ts){const o=document.createElement('option');o.value=t.key;o.textContent=t.label+(t.available?'':'  (build first)');$('tsel').appendChild(o)}}
const open_={};const fmt=s=>s==null?'':(s<90?Math.round(s)+' s':(s/60).toFixed(1)+' min');
async function act(url){try{clear();await api(url,{method:'POST'});refresh()}catch(e){fail(e)}}
async function refresh(){const st=await api('/api/status');busy=Object.values(st).some(j=>j.status==='running');const root=$('jobs');
  for(const[id,j]of Object.entries(st)){let c=document.getElementById('c_'+id);
    if(!c){c=document.createElement('div');c.className='card';c.id='c_'+id;c.innerHTML=`<div class="row"><h2 class="grow" style="margin:0"></h2><span class="badge"></span><span class="el sub2"></span><button class="go">Run</button><button class="stop">Stop</button></div><p class="sub2 d"></p><div class="out"></div><details><summary>Log</summary><pre></pre></details>`;
      c.querySelector('.go').onclick=()=>act('/api/start/'+id);c.querySelector('.stop').onclick=()=>act('/api/stop/'+id);c.querySelector('details').ontoggle=e=>{open_[id]=e.target.open};root.appendChild(c)}
    c.querySelector('h2').textContent=j.title+' ('+j.eta+')';const b=c.querySelector('.badge');b.textContent=j.status;b.className='badge '+j.status;c.querySelector('.el').textContent=j.elapsed?fmt(j.elapsed):'';
    c.querySelector('.go').disabled=busy;c.querySelector('.stop').style.display=j.status==='running'?'':'none';c.querySelector('.d').textContent=j.desc;
    const out=c.querySelector('.out');if(j.image&&out.dataset.v!=String(j.image_v)){out.dataset.v=j.image_v;out.innerHTML=`<img src="/results/${j.image.split('/')[1]}?v=${j.image_v}">`}
    const det=c.querySelector('details');if(det.open){const t=await(await fetch('/api/log/'+id)).text();const pre=c.querySelector('pre');const end=pre.scrollTop+pre.clientHeight>=pre.scrollHeight-20;pre.textContent=t||'(no output yet)';if(end)pre.scrollTop=pre.scrollHeight}}
  $('cbtn').disabled=$('tbtn').disabled=busy}
loadTests();refresh();setInterval(()=>refresh().catch(()=>{}),2500);
</script></body></html>"""


@app.get("/")
def index():
    return PAGE


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, threaded=True)
