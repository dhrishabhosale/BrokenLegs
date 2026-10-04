#!/usr/bin/env python3
"""Lineage control panel: start the demo jobs in the background, watch logs, view results.
Run:  pip install flask && python3 webapp.py   ->  http://127.0.0.1:5000
Jobs are detached processes: closing the tab or restarting this server does not stop them.
Only the fixed commands below can be run (no user input reaches a shell). Binds to localhost."""
import os, signal, subprocess, time
from flask import Flask, jsonify, send_from_directory, Response

ROOT = os.path.dirname(os.path.abspath(__file__))
JOBS_DIR = os.path.join(ROOT, "jobs")
os.makedirs(JOBS_DIR, exist_ok=True)

JOBS = {
    "build":   dict(title="1. Build binaries", cmd="./build.sh", eta="~10 s",
                    desc="Compiles the reference, disguised variants, stripped libraries and the C fuzzer."),
    "main":    dict(title="2. Demo table", cmd="python3 lineage.py", eta="~1.5 min",
                    desc="PROVED / TESTED / NOT_EQUIVALENT / NOT_FOUND for every variant vs. the syntactic baseline."),
    "sweep":   dict(title="3. Mutation sweep", cmd="python3 mutation_sweep.py", eta="~1.5 min",
                    desc="67 mutants: SMT proof vs. 300k and 50M-sample fuzzing. Writes results/sweep.*"),
    "scaling": dict(title="4. Scaling grid", cmd="python3 scaling.py --rerun", eta="~5 min",
                    desc="Rounds x obfuscation level, including where MBA defeats the solver. Writes results/scaling.*"),
}
IMAGES = {"sweep": "results/sweep_detection.png", "scaling": "results/scaling.png"}

app = Flask(__name__)


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
    return next((j for j in JOBS if status(j) == "running"), None)


@app.get("/api/status")
def api_status():
    out = {}
    for j, meta in JOBS.items():
        img = IMAGES.get(j)
        img_m = os.path.getmtime(os.path.join(ROOT, img)) if img and os.path.exists(os.path.join(ROOT, img)) else None
        started = float(read(f(j, "start"), "0") or 0)
        out[j] = dict(meta, status=status(j), started=started, image=img if img_m else None, image_v=img_m,
                      elapsed=(time.time() - started) if status(j) == "running" and started else None)
    return jsonify(out)


@app.post("/api/start/<job>")
def api_start(job):
    if job not in JOBS:
        return jsonify(error="unknown job"), 404
    if (r := running_job()):
        return jsonify(error=f"'{r}' is already running (one at a time so timings stay meaningful)"), 409
    if job != "build" and not os.path.exists(os.path.join(ROOT, "build", "ref_O0.so")):
        return jsonify(error="Run '1. Build binaries' first"), 400
    for ext in ("exit", "pid"):
        if os.path.exists(f(job, ext)):
            os.remove(f(job, ext))
    log = open(f(job, "log"), "w")
    proc = subprocess.Popen(["sh", "-c", f"{JOBS[job]['cmd']}; echo $? > '{f(job, 'exit')}'"], cwd=ROOT,
                            stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                            env=dict(os.environ, PYTHONUNBUFFERED="1"))
    open(f(job, "start"), "w").write(str(time.time()))
    open(f(job, "pid"), "w").write(str(proc.pid))
    return jsonify(ok=True)


@app.post("/api/stop/<job>")
def api_stop(job):
    if job in JOBS and status(job) == "running":
        os.killpg(int(read(f(job, "pid"))), signal.SIGTERM)
    return jsonify(ok=True)


@app.get("/api/log/<job>")
def api_log(job):
    if job not in JOBS:
        return Response("", 404)
    lines = [l for l in read(f(job, "log")).splitlines() if "unicorn" not in l]
    return Response("\n".join(lines[-400:]), mimetype="text/plain")


@app.get("/results/<path:name>")
def results(name):
    return send_from_directory(os.path.join(ROOT, "results"), name)


PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Lineage control panel</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#fff;--fg:#1c1e21;--card:#f5f6f8;--mut:#6b7280;--line:#dfe2e6;--ok:#15803d;--bad:#b91c1c;--run:#1d4ed8;--btn:#1d4ed8}
@media(prefers-color-scheme:dark){:root{--bg:#14161a;--fg:#e6e8eb;--card:#1d2026;--mut:#9aa3af;--line:#2c313a;--ok:#4ade80;--bad:#f87171;--run:#60a5fa;--btn:#3b82f6}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px}h1{margin:0 0 4px;font-size:22px}p.sub{color:var(--mut);margin:0 0 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:14px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.row h2{font-size:16px;margin:0;flex:1}
.badge{font-size:12px;padding:2px 9px;border-radius:99px;border:1px solid var(--line);color:var(--mut)}
.running{color:var(--run);border-color:var(--run)}.done{color:var(--ok);border-color:var(--ok)}.failed,.stopped{color:var(--bad);border-color:var(--bad)}
button{background:var(--btn);color:#fff;border:0;border-radius:6px;padding:6px 14px;font-size:14px;cursor:pointer}
button.stop{background:var(--bad)}button:disabled{opacity:.4;cursor:default}
.desc{color:var(--mut);margin:6px 0 0;font-size:14px}
pre{background:#0d1117;color:#d1d5db;border-radius:8px;padding:10px;font-size:12px;max-height:300px;overflow:auto;margin:10px 0 0;white-space:pre}
img{max-width:100%;margin-top:10px;border-radius:8px;border:1px solid var(--line);background:#fff}
#err{color:var(--bad);min-height:20px;margin-bottom:8px}details summary{cursor:pointer;color:var(--mut);font-size:13px;margin-top:8px}
</style></head><body><main>
<h1>Lineage control panel</h1>
<p class="sub">Jobs run in the background on this machine, one at a time. You can close this tab and come back.</p>
<div id="err"></div><div id="jobs"></div></main>
<script>
const open_ = {}; let busy = false;
async function api(url, method){const r = await fetch(url,{method}); const j = await r.json().catch(()=>({})); if(!r.ok) throw new Error(j.error||r.statusText); return j;}
async function act(url){try{document.getElementById('err').textContent='';await api(url,'POST');refresh();}catch(e){document.getElementById('err').textContent=e.message;}}
const fmt = s => s==null ? '' : (s<90 ? Math.round(s)+' s' : (s/60).toFixed(1)+' min');
async function refresh(){
  const st = await api('/api/status'); busy = Object.values(st).some(j=>j.status==='running');
  const root = document.getElementById('jobs');
  for (const [id,j] of Object.entries(st)){
    let c = document.getElementById('c_'+id);
    if(!c){c=document.createElement('div');c.className='card';c.id='c_'+id;
      c.innerHTML=`<div class="row"><h2></h2><span class="badge"></span><span class="el" style="color:var(--mut);font-size:13px"></span><button class="go">Run</button><button class="stop">Stop</button></div>
      <p class="desc"></p><div class="out"></div><details><summary>Log</summary><pre></pre></details>`;
      c.querySelector('.go').onclick=()=>act('/api/start/'+id); c.querySelector('.stop').onclick=()=>act('/api/stop/'+id);
      c.querySelector('details').ontoggle=e=>{open_[id]=e.target.open}; root.appendChild(c);}
    c.querySelector('h2').textContent=j.title+'  ('+j.eta+')';
    const b=c.querySelector('.badge'); b.textContent=j.status; b.className='badge '+j.status;
    c.querySelector('.el').textContent=j.elapsed?fmt(j.elapsed):'';
    c.querySelector('.go').disabled=busy; c.querySelector('.stop').style.display=j.status==='running'?'':'none';
    c.querySelector('.desc').textContent=j.desc;
    const out=c.querySelector('.out');
    if(j.image && out.dataset.v!=String(j.image_v)){out.dataset.v=j.image_v;out.innerHTML=`<img src="/results/${j.image.split('/')[1]}?v=${j.image_v}">`;}
    const det=c.querySelector('details');
    if(j.status==='running' || open_[id] || (id==='main' && j.status!=='idle')){
      if(id==='main' && open_[id]===undefined){det.open=true;open_[id]=true;}
      if(det.open){const t=await (await fetch('/api/log/'+id)).text(); const pre=c.querySelector('pre');
        const atEnd=pre.scrollTop+pre.clientHeight>=pre.scrollHeight-20; pre.textContent=t||'(no output yet)'; if(atEnd)pre.scrollTop=pre.scrollHeight;}
    }
  }
}
refresh(); setInterval(()=>refresh().catch(()=>{}),2000);
</script></body></html>"""


@app.get("/")
def index():
    return PAGE


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, threaded=True)
