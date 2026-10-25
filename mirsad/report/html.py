"""Self-contained HTML report — no CDN, no network, opens anywhere."""

from __future__ import annotations

import html
import json
import time

TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MIRSAD · __TARGET__</title>
<style>
:root{
  --bg:#0a0e14; --panel:#111823; --panel2:#0e141d; --line:#1e2a38;
  --txt:#e6edf5; --dim:#8497ab; --cyan:#22d3ee; --green:#34d399;
  --amber:#fbbf24; --red:#f87171; --violet:#a78bfa; --pink:#f472b6;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);
  font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  background-image:radial-gradient(900px 500px at 12% -10%,rgba(34,211,238,.10),transparent 60%),
                   radial-gradient(700px 400px at 90% 0%,rgba(167,139,250,.08),transparent 60%);}
a{color:var(--cyan);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:1240px;margin:0 auto;padding:28px 22px 80px}
header.top{display:flex;flex-wrap:wrap;gap:18px;align-items:flex-end;justify-content:space-between;
  border-bottom:1px solid var(--line);padding-bottom:18px;margin-bottom:26px}
.brand{font-size:12px;letter-spacing:.34em;color:var(--dim);text-transform:uppercase}
h1{margin:6px 0 0;font-size:30px;letter-spacing:-.02em;word-break:break-all}
h1 .type{font-size:12px;letter-spacing:.16em;text-transform:uppercase;color:var(--cyan);
  border:1px solid rgba(34,211,238,.35);border-radius:999px;padding:3px 9px;margin-left:10px;vertical-align:middle}
.meta{color:var(--dim);font-size:12px;text-align:right}
.grid{display:grid;gap:16px}
.cards{grid-template-columns:repeat(auto-fit,minmax(160px,1fr))}
.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);
  border-radius:14px;padding:16px}
.card .k{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim)}
.card .v{font-size:26px;font-weight:650;margin-top:6px;letter-spacing:-.02em}
.card .s{font-size:12px;color:var(--dim);margin-top:2px}
.scorecard{display:flex;gap:22px;align-items:center;flex-wrap:wrap}
.gauge{width:132px;height:132px;position:relative;flex:0 0 auto}
.gauge svg{transform:rotate(-90deg)}
.gauge .num{position:absolute;inset:0;display:grid;place-items:center;font-size:30px;font-weight:700}
.band{font-size:12px;letter-spacing:.2em;text-transform:uppercase;padding:4px 10px;border-radius:999px;display:inline-block}
.band.low{background:rgba(52,211,153,.14);color:var(--green)}
.band.moderate{background:rgba(251,191,36,.14);color:var(--amber)}
.band.elevated{background:rgba(251,146,60,.16);color:#fb923c}
.band.critical{background:rgba(248,113,113,.16);color:var(--red)}
.drivers{list-style:none;margin:0;padding:0;display:grid;gap:8px}
.drivers li{display:flex;gap:10px;align-items:baseline;border-bottom:1px dashed var(--line);padding-bottom:7px}
.drivers .pts{color:var(--cyan);font-variant-numeric:tabular-nums;font-weight:600;min-width:44px}
.drivers .lbl{font-weight:600}
.drivers .det{color:var(--dim);font-size:12px}
section{margin-top:26px}
h2{font-size:13px;letter-spacing:.2em;text-transform:uppercase;color:var(--dim);margin:0 0 12px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden}
#graph{width:100%;height:440px;display:block;cursor:grab}
.legend{display:flex;gap:14px;flex-wrap:wrap;padding:10px 14px;border-top:1px solid var(--line);font-size:12px;color:var(--dim)}
.legend i{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:6px}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
input[type=search],select{background:var(--panel2);border:1px solid var(--line);color:var(--txt);
  border-radius:9px;padding:8px 12px;font:inherit;outline:none;min-width:220px}
input[type=search]:focus,select:focus{border-color:rgba(34,211,238,.5)}
.chip{border:1px solid var(--line);background:var(--panel2);color:var(--dim);border-radius:999px;
  padding:5px 12px;font-size:12px;cursor:pointer}
.chip.on{color:#06121a;background:var(--cyan);border-color:var(--cyan);font-weight:600}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--dim);font-weight:600;
  position:sticky;top:0;background:var(--panel2);z-index:1}
tr:last-child td{border-bottom:none}
tbody tr:hover{background:rgba(34,211,238,.04)}
.plat{font-weight:600}
.sub{color:var(--dim);font-size:12px}
.badge{font-size:11px;padding:2px 8px;border-radius:999px;border:1px solid var(--line);color:var(--dim)}
.badge.found{color:var(--green);border-color:rgba(52,211,153,.35);background:rgba(52,211,153,.08)}
.badge.high{color:var(--red);border-color:rgba(248,113,113,.35);background:rgba(248,113,113,.08)}
.badge.info{color:var(--cyan);border-color:rgba(34,211,238,.3);background:rgba(34,211,238,.07)}
.bar{height:5px;border-radius:3px;background:var(--line);overflow:hidden;min-width:70px}
.bar i{display:block;height:100%;background:linear-gradient(90deg,var(--cyan),var(--violet))}
.empty{padding:26px;color:var(--dim);text-align:center}
footer{margin-top:40px;color:var(--dim);font-size:12px;border-top:1px solid var(--line);padding-top:16px;
  display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.kv{display:grid;grid-template-columns:140px 1fr;gap:4px 14px;font-size:13px}
.kv dt{color:var(--dim)}
.kv dd{margin:0;word-break:break-word}
.tags{display:flex;gap:6px;flex-wrap:wrap;margin-top:4px}
.tag{font-size:11px;color:var(--dim);border:1px solid var(--line);border-radius:6px;padding:1px 6px}
details summary{cursor:pointer;color:var(--cyan);font-size:12px}
@media print{body{background:#fff;color:#111}header.top,.panel{border-color:#ddd}.no-print{display:none}}
</style>
</head>
<body>
<div class="wrap">
<header class="top">
  <div>
    <div class="brand">MIRSAD · identity intelligence</div>
    <h1>__TARGET__<span class="type">__TYPE__</span></h1>
  </div>
  <div class="meta">
    run __RUN__ · __DATE__<br>
    __DURATION__s · __REQUESTS__ requests · __CACHED__ cached
  </div>
</header>

<div class="grid cards">
  <div class="card"><div class="k">exposure</div><div class="v" style="color:__SCORE_COLOR__">__SCORE__<span style="font-size:14px;color:var(--dim)">/100</span></div>
    <div class="s"><span class="band __BAND__">__BAND__</span></div></div>
  <div class="card"><div class="k">accounts</div><div class="v">__ACCOUNTS__</div><div class="s">__HIGH_VALUE__ high-value</div></div>
  <div class="card"><div class="k">breaches</div><div class="v">__BREACHES__</div><div class="s">credential risk __CRED__/100</div></div>
  <div class="card"><div class="k">identities</div><div class="v">__IDENTITIES__</div><div class="s">names, emails, phones</div></div>
  <div class="card"><div class="k">checked</div><div class="v">__CHECKED__</div><div class="s">platforms probed</div></div>
</div>

<section>
  <h2>why this score</h2>
  <div class="panel" style="padding:16px">
    <ul class="drivers">__DRIVERS__</ul>
  </div>
</section>

<section>
  <h2>identity graph</h2>
  <div class="panel">
    <canvas id="graph"></canvas>
    <div class="legend">
      <span><i style="background:#22d3ee"></i>target</span>
      <span><i style="background:#34d399"></i>account</span>
      <span><i style="background:#a78bfa"></i>email</span>
      <span><i style="background:#f472b6"></i>username</span>
      <span><i style="background:#fbbf24"></i>domain</span>
      <span><i style="background:#f87171"></i>breach</span>
      <span><i style="background:#94a3b8"></i>other</span>
    </div>
  </div>
</section>

<section>
  <h2>findings</h2>
  <div class="toolbar no-print">
    <input type="search" id="q" placeholder="filter by platform, value, tag…">
    <button class="chip on" data-kind="all">all</button>
    <button class="chip" data-kind="account">accounts</button>
    <button class="chip" data-kind="breach">breaches</button>
    <button class="chip" data-kind="identity">identities</button>
    <button class="chip" data-kind="dns">infrastructure</button>
    <span class="sub" id="count"></span>
  </div>
  <div class="panel">
    <table>
      <thead><tr><th style="width:22%">platform</th><th style="width:10%">kind</th>
      <th style="width:12%">confidence</th><th>detail</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
    <div class="empty" id="empty" style="display:none">nothing matches this filter</div>
  </div>
</section>

<footer>
  <div>generated by MIRSAD · open-source identity intelligence · data is public at collection time</div>
  <div><a href="#" onclick="downloadJson();return false">download JSON</a></div>
</footer>
</div>

<script>
const DATA = __DATA__;
const KIND_COLORS = {target:"#22d3ee",account:"#34d399",email:"#a78bfa",username:"#f472b6",
  domain:"#fbbf24",breach:"#f87171",profile:"#60a5fa",name:"#c084fc",phone:"#fb7185",other:"#94a3b8"};

/* ---------------------------------------------------------------- table */
const rows = document.getElementById('rows');
const empty = document.getElementById('empty');
const countEl = document.getElementById('count');
let activeKind = 'all';
let query = '';

function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}

function detailFor(f){
  if(f.kind==='breach'){
    const b=(f.data.breaches||[]).map(x=>x.name).filter(Boolean);
    if(b.length) return b.slice(0,8).join(', ') + (b.length>8?` +${b.length-8} more`:'');
    if(f.data.stealer) return 'infostealer log · '+(f.data.computer||'')+' '+(f.data.date||'');
    return f.data.reason||f.data.note||'';
  }
  if(f.kind==='identity'){
    const d=f.data;
    if(d.emails) return d.emails.slice(0,6).join(', ');
    if(d.names) return d.names.slice(0,6).join(', ');
    if(d.orgs) return d.orgs.map(o=>o.login).join(', ');
    if(d.provider) return d.provider;
    if(d.subdomains) return d.subdomains.slice(0,6).join(', ');
    return JSON.stringify(d).slice(0,160);
  }
  if(f.kind==='dns'){
    const d=f.data;
    return [d.provider, d.mx&&d.mx.length?`MX ${d.mx.length}`:'', d.spf?'SPF':'no SPF', d.dmarc?'DMARC':'no DMARC']
      .filter(Boolean).join(' · ');
  }
  if(f.url) return f.url;
  return f.data.title||f.data.description||f.data.reason||'';
}

function render(){
  const list = DATA.findings.filter(f=>f.status==='found'||f.status==='info');
  const filtered = list.filter(f=>{
    if(activeKind!=='all' && f.kind!==activeKind) return false;
    if(!query) return true;
    const hay = [f.platform,f.identifier,f.url,f.kind,JSON.stringify(f.data),...(f.tags||[])].join(' ').toLowerCase();
    return hay.includes(query);
  });
  countEl.textContent = `${filtered.length} of ${list.length}`;
  empty.style.display = filtered.length? 'none':'block';
  rows.innerHTML = filtered.map(f=>{
    const conf = Math.round((f.confidence||0)*100);
    const badge = f.status==='found'?'found':'info';
    return `<tr>
      <td><div class="plat">${esc(f.platform)}</div>
          <div class="tags">${(f.tags||[]).slice(0,3).map(t=>`<span class="tag">${esc(t)}</span>`).join('')}</div></td>
      <td><span class="badge ${badge}">${esc(f.kind)}</span></td>
      <td><div class="bar"><i style="width:${conf}%"></i></div><div class="sub">${conf}%</div></td>
      <td>${esc(detailFor(f))}${f.url?`<div class="sub"><a href="${esc(f.url)}" target="_blank" rel="noopener">${esc(f.url)}</a></div>`:''}</td>
    </tr>`;
  }).join('');
}
document.getElementById('q').addEventListener('input',e=>{query=e.target.value.toLowerCase();render();});
document.querySelectorAll('.chip').forEach(btn=>btn.addEventListener('click',()=>{
  document.querySelectorAll('.chip').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on'); activeKind=btn.dataset.kind; render();
}));

function downloadJson(){
  const blob = new Blob([JSON.stringify(DATA,null,2)],{type:'application/json'});
  const a = document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download = `mirsad-${DATA.target.replace(/[^a-z0-9]/gi,'_')}.json`; a.click();
}

/* ---------------------------------------------------------------- graph */
const canvas = document.getElementById('graph');
const ctx = canvas.getContext('2d');
let W=0,H=0,DPR=window.devicePixelRatio||1;
function resize(){
  const rect = canvas.getBoundingClientRect();
  W=rect.width; H=rect.height;
  canvas.width=W*DPR; canvas.height=H*DPR;
  ctx.setTransform(DPR,0,0,DPR,0,0);
}
window.addEventListener('resize',()=>{resize();});

const nodes = DATA.graph.nodes.map((n,i)=>({...n, x:Math.random()*600, y:Math.random()*400, vx:0, vy:0,
  r:n.type==='target'?13:(n.type==='account'?8:6)}));
const index = new Map(nodes.map(n=>[n.id,n]));
const links = DATA.graph.edges.map(e=>({s:index.get(e.source),t:index.get(e.target),rel:e.relation})).filter(l=>l.s&&l.t);

function tick(){
  for(const n of nodes){
    if(n.type==='target'){ n.x += (W/2-n.x)*0.02; n.y += (H/2-n.y)*0.02; }
    for(const m of nodes){
      if(n===m) continue;
      let dx=n.x-m.x, dy=n.y-m.y, d2=dx*dx+dy*dy||1;
      if(d2>90000) continue;
      const f=900/d2; n.vx+=dx*f*0.02; n.vy+=dy*f*0.02;
    }
  }
  for(const l of links){
    let dx=l.t.x-l.s.x, dy=l.t.y-l.s.y, d=Math.hypot(dx,dy)||1;
    const f=(d-110)*0.004;
    dx/=d; dy/=d;
    l.s.vx+=dx*f; l.s.vy+=dy*f; l.t.vx-=dx*f; l.t.vy-=dy*f;
  }
  for(const n of nodes){
    n.vx*=0.86; n.vy*=0.86;
    n.x+=n.vx; n.y+=n.vy;
    n.x=Math.max(n.r+8,Math.min(W-n.r-8,n.x));
    n.y=Math.max(n.r+8,Math.min(H-n.r-8,n.y));
  }
}

function draw(){
  ctx.clearRect(0,0,W,H);
  ctx.lineWidth=1;
  for(const l of links){
    ctx.strokeStyle='rgba(120,150,180,.20)';
    ctx.beginPath(); ctx.moveTo(l.s.x,l.s.y); ctx.lineTo(l.t.x,l.t.y); ctx.stroke();
  }
  for(const n of nodes){
    const color = KIND_COLORS[n.type]||KIND_COLORS.other;
    ctx.beginPath(); ctx.arc(n.x,n.y,n.r,0,Math.PI*2);
    ctx.fillStyle=color+'33'; ctx.fill();
    ctx.strokeStyle=color; ctx.lineWidth=1.6; ctx.stroke();
    if(n.type==='target'||n.type==='account'||n.r>7){
      ctx.fillStyle='rgba(230,237,245,.82)'; ctx.font='11px ui-sans-serif,system-ui';
      ctx.textAlign='center';
      const label=(n.label||n.value||'').slice(0,26);
      ctx.fillText(label,n.x,n.y+n.r+13);
    }
  }
}
let raf=null, frames=0;
function loop(){ tick(); draw(); frames++; if(frames<900) raf=requestAnimationFrame(loop); }
resize(); render(); loop();

canvas.addEventListener('mousemove',e=>{
  const rect=canvas.getBoundingClientRect();
  const mx=e.clientX-rect.left, my=e.clientY-rect.top;
  let hit=null;
  for(const n of nodes){ if(Math.hypot(n.x-mx,n.y-my)<n.r+6){hit=n;break;} }
  canvas.style.cursor = hit?'pointer':'grab';
  canvas.title = hit? `${hit.type}: ${hit.value}` : '';
});
</script>
</body>
</html>
"""


def render(report) -> str:
    data = report.to_dict()
    score = data.get("score") or {}
    stats = data.get("stats") or {}
    band = score.get("band", "low")
    colors = {"low": "#34d399", "moderate": "#fbbf24", "elevated": "#fb923c", "critical": "#f87171"}
    found = [f for f in data["findings"] if f["status"] == "found"]
    identities = [f for f in found if f["kind"] == "identity"]

    drivers = "".join(
        f'<li><span class="pts">+{d["points"]}</span><span><span class="lbl">{html.escape(d["label"])}</span>'
        f'<div class="det">{html.escape(str(d["detail"]))}</div></span></li>'
        for d in (score.get("drivers") or [])
    ) or '<li><span class="pts">0</span><span class="lbl">No exposure drivers detected</span></li>'

    checked = stats.get("requests", 0)
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")

    replacements = {
        "__TARGET__": html.escape(report.target),
        "__TYPE__": html.escape(report.target_type),
        "__RUN__": report.run_id,
        "__DATE__": time.strftime("%Y-%m-%d %H:%M", time.localtime(report.started)),
        "__DURATION__": f"{(report.finished or time.time()) - report.started:.1f}",
        "__REQUESTS__": str(checked),
        "__CACHED__": str(stats.get("cached", 0)),
        "__SCORE__": str(score.get("score", 0)),
        "__SCORE_COLOR__": colors.get(band, "#e6edf5"),
        "__BAND__": band,
        "__ACCOUNTS__": str(score.get("accounts_found", 0)),
        "__HIGH_VALUE__": str(score.get("high_value_accounts", 0)),
        "__BREACHES__": str(score.get("breaches", 0)),
        "__CRED__": str(score.get("credential_risk", 0)),
        "__IDENTITIES__": str(len(identities)),
        "__CHECKED__": str(stats.get("nodes", 0)),
        "__DRIVERS__": drivers,
        "__DATA__": payload,
    }
    out = TEMPLATE
    for key, value in replacements.items():
        out = out.replace(key, value)
    return out
