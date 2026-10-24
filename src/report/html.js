'use strict';
// Self-contained HTML report. Scanned code is attacker-controlled, so: data is embedded as inert JSON,
// rendered with textContent only (never innerHTML), and the page ships a hash-pinned CSP.
const crypto = require('crypto');
const { CATEGORIES } = require('../owasp');

function safeJson(obj) {
  return JSON.stringify(obj).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

const CSS = `
:root{--bg:#f7f7f5;--panel:#fff;--ink:#16181d;--muted:#5d6370;--line:#e3e4e8;--code:#f1f2f4;--accent:#3b5bdb;
--crit:#c92a2a;--high:#e8590c;--med:#d9a400;--low:#1c7ed6;--info:#868e96;--ok:#2b8a3e}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0f1115;--panel:#171a21;--ink:#e6e8ee;--muted:#9aa1ae;--line:#272b35;--code:#1e222b;--accent:#748ffc}}
:root[data-theme=dark]{--bg:#0f1115;--panel:#171a21;--ink:#e6e8ee;--muted:#9aa1ae;--line:#272b35;--code:#1e222b;--accent:#748ffc}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
header{padding:28px 24px 18px;border-bottom:1px solid var(--line);background:var(--panel)}
h1{margin:0 0 6px;font-size:22px;letter-spacing:-.01em}.meta{color:var(--muted);font-size:13px;word-break:break-all}
main{max-width:1200px;margin:0 auto;padding:20px 16px 60px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:18px 0}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.kpi b{display:block;font-size:24px;font-variant-numeric:tabular-nums}.kpi span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.kpi.critical b{color:var(--crit)}.kpi.high b{color:var(--high)}.kpi.medium b{color:var(--med)}.kpi.low b{color:var(--low)}
.gate{display:inline-block;margin-top:10px;padding:3px 10px;border-radius:99px;font-weight:600;font-size:12px}
.gate.pass{background:color-mix(in srgb,var(--ok) 15%,transparent);color:var(--ok)}.gate.fail{background:color-mix(in srgb,var(--crit) 15%,transparent);color:var(--crit)}
.cats{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:8px;margin-bottom:18px}
.cat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 12px;cursor:pointer;text-align:left;color:inherit;font:inherit}
.cat[aria-pressed=true]{outline:2px solid var(--accent)}.cat small{color:var(--muted);display:block}.bar{display:flex;height:6px;border-radius:3px;overflow:hidden;margin-top:8px;background:var(--line)}
.bar i{display:block}.controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0 14px}
input[type=search]{flex:1 1 240px;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--ink);font:inherit}
.chip{border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:99px;padding:4px 10px;cursor:pointer;font:inherit;font-size:12px}
.chip[aria-pressed=false]{opacity:.45}
.f{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:8px;margin:8px 0}
.f.critical{border-left-color:var(--crit)}.f.high{border-left-color:var(--high)}.f.medium{border-left-color:var(--med)}.f.low{border-left-color:var(--low)}
.f summary{cursor:pointer;padding:10px 12px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap;list-style:none}.f summary::-webkit-details-marker{display:none}
.sev{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;min-width:62px}.sev.critical{color:var(--crit)}.sev.high{color:var(--high)}.sev.medium{color:var(--med)}.sev.low{color:var(--low)}.sev.info{color:var(--info)}
.rid{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted)}.loc{font:12px ui-monospace,monospace;color:var(--accent);margin-left:auto;word-break:break-all}
.tag{font-size:11px;padding:1px 7px;border-radius:99px;background:var(--code);color:var(--muted)}
.body{padding:0 14px 14px}.body p{margin:6px 0}pre{background:var(--code);padding:10px;border-radius:6px;overflow:auto;font:12px/1.45 ui-monospace,monospace;white-space:pre-wrap;word-break:break-word}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}th{color:var(--muted);font-weight:600}
.k{color:var(--muted);font-size:12px}h2{font-size:16px;margin:26px 0 8px}button.theme{float:right;background:none;border:1px solid var(--line);color:var(--ink);border-radius:8px;padding:4px 10px;cursor:pointer}
.empty{color:var(--muted);padding:20px;text-align:center}
`;

const SCRIPT = `
(function(){
var D=JSON.parse(document.getElementById('data').textContent);
var el=function(t,a,c){var e=document.createElement(t);if(a)for(var k in a){if(k==='class')e.className=a[k];else e.setAttribute(k,a[k]);}
(c||[]).forEach(function(x){if(x==null)return;e.appendChild(typeof x==='string'?document.createTextNode(x):x)});return e;};
var SEV=['critical','high','medium','low','info'];var on={};SEV.forEach(function(s){on[s]=true});var cat=null;var q='';var showClosed=false;
var t=document.querySelector('button.theme');t.onclick=function(){var r=document.documentElement;r.dataset.theme=r.dataset.theme==='dark'?'light':'dark';};
var chips=document.getElementById('chips');
SEV.forEach(function(s){var b=el('button',{class:'chip','aria-pressed':'true'},[s+' ('+D.summary.bySeverity[s]+')']);b.onclick=function(){on[s]=!on[s];b.setAttribute('aria-pressed',on[s]);render();};chips.appendChild(b);});
var cb=el('button',{class:'chip','aria-pressed':'false'},['show triaged/suppressed']);cb.onclick=function(){showClosed=!showClosed;cb.setAttribute('aria-pressed',showClosed);render();};chips.appendChild(cb);
document.getElementById('q').oninput=function(e){q=e.target.value.toLowerCase();render();};
var cats=document.getElementById('cats');
Object.keys(D.categories).forEach(function(k){var c=D.summary.byCategory[k];var bar=el('div',{class:'bar'});
['critical','high','medium','low','info'].forEach(function(s){if(c[s]){var i=el('i');i.style.flex=c[s];i.style.background='var(--'+({critical:'crit',high:'high',medium:'med',low:'low',info:'info'})[s]+')';bar.appendChild(i);}});
var b=el('button',{class:'cat','aria-pressed':'false'},[el('b',null,[k+' ']),D.categories[k].name,el('small',null,[c.total+' open']),bar]);
b.onclick=function(){cat=cat===k?null:k;[].forEach.call(cats.children,function(x){x.setAttribute('aria-pressed','false')});if(cat)b.setAttribute('aria-pressed','true');render();};cats.appendChild(b);});
var list=document.getElementById('list');
function render(){list.textContent='';var n=0;
D.findings.forEach(function(f){if(!on[f.severity])return;if(cat&&f.owasp!==cat)return;if(!showClosed&&f.status!=='open')return;
if(q&&(f.ruleId+' '+f.title+' '+f.file+' '+(f.cwe||[]).join(' ')+' '+(f.cves||[]).join(' ')+' '+(f.snippet||'')).toLowerCase().indexOf(q)<0)return;n++;
var tags=[el('span',{class:'tag'},[f.owasp]),el('span',{class:'tag'},['conf: '+f.confidence])];
if(f.status!=='open')tags.push(el('span',{class:'tag'},[f.status]));if(f.triage)tags.push(el('span',{class:'tag'},['triage: '+f.triage.verdict]));if(f.baseline==='new')tags.push(el('span',{class:'tag'},['new']));
var sum=el('summary',null,[el('span',{class:'sev '+f.severity},[f.severity]),el('span',null,[f.title]),el('span',{class:'rid'},[f.ruleId])].concat(tags).concat([el('span',{class:'loc'},[f.file+':'+f.line])]));
var body=el('div',{class:'body'},[
f.snippet?el('pre',null,[f.snippet]):null,
f.detail?el('p',null,[el('span',{class:'k'},['Detail: ']),f.detail]):null,
f.taint?el('p',null,[el('span',{class:'k'},['Data flow: ']),(f.taint.source||f.taint.name||'unknown')+((f.taint.line||f.taint.from)?' (tainted at line '+(f.taint.line||f.taint.from)+')':'')+' reaches this sink']):null,
el('p',null,[f.message]),el('p',null,[el('b',null,['Fix: ']),f.fix]),
f.triage?el('p',null,[el('b',null,['Triage ('+f.triage.verdict+'): ']),f.triage.rationale]):null,
el('p',{class:'k'},[(f.cwe||[]).map(function(c){return 'CWE-'+c}).join(', ')+((f.cves&&f.cves.length)?' · '+f.cves.join(', '):'')+' · '+f.id+' · fp '+f.fingerprint]),
(f.refs&&f.refs.length)?el('p',{class:'k'},f.refs.slice(0,4).map(function(r){var a=el('a',{href:r,rel:'noopener noreferrer',target:'_blank'},[r]);return el('span',null,[a,' '])})):null]);
list.appendChild(el('details',{class:'f '+f.severity},[sum,body]));});
if(!n)list.appendChild(el('div',{class:'empty'},['No findings match the current filters.']));
document.getElementById('count').textContent=n+' shown';}
render();
var sb=document.getElementById('surface');if(D.surface&&D.surface.length){var tb=el('tbody');D.surface.slice(0,500).forEach(function(r){tb.appendChild(el('tr',null,[el('td',null,[r.method]),el('td',null,[el('code',null,[r.path])]),el('td',null,[r.auth]),el('td',{class:'k'},[r.file+':'+r.line])]))});
sb.appendChild(el('table',null,[el('thead',null,[el('tr',null,[el('th',null,['Method']),el('th',null,['Path']),el('th',null,['Auth evidence']),el('th',null,['Location'])])]),tb]));}else sb.appendChild(el('p',{class:'k'},['No HTTP entry points detected.']));
})();
`;

function toHtml(result, { gate, coverageGate = require('../coverage').coverageGate(result) } = {}) {
  const data = { summary: result.summary, findings: result.findings, surface: result.surface, categories: Object.fromEntries(Object.entries(CATEGORIES).map(([k, v]) => [k, { name: v.name }])) };
  const hash = crypto.createHash('sha256').update(SCRIPT).digest('base64');
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const t = result.target;
  const s = result.summary.bySeverity;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-${hash}'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>kayfabe report — ${esc(t.name)}</title><style>${CSS}</style></head>
<body><header><button class="theme" type="button">◐ theme</button>
<h1>kayfabe report — ${esc(t.name)}</h1>
<div class="meta">${esc(t.url || t.root)}${t.commit ? ' @ ' + esc(t.commit.slice(0, 12)) : ''}${t.ref ? ' (ref ' + esc(t.ref) + ')' : ''} · ${esc(result.scannedAt)} · ${result.stats.files} files · ${result.stats.dependencies} deps · kayfabe ${esc(result.tool.version)}${result.triage ? ' · triaged by ' + esc(result.triage.reviewer) + (result.triage.model ? ' (' + esc(result.triage.model) + ')' : '') : ' · not yet triaged'}</div>
${gate ? `<span class="gate ${gate.passed ? 'pass' : 'fail'}">${gate.passed ? 'SEVERITY GATE PASS' : 'SEVERITY GATE FAIL'} — ${esc(gate.reason)}</span>` : ''}
<p><strong>Analysis coverage:</strong> ${esc(require('../coverage').coverageText(result))}</p>
${coverageGate.required ? `<p><strong>Coverage gate: ${coverageGate.passed ? 'PASS' : 'FAIL'}</strong> — ${esc(coverageGate.reason)}</p>` : ''}
</header><main>
<div class="kpis">${['critical', 'high', 'medium', 'low', 'info'].map((k) => `<div class="kpi ${k}"><b>${s[k]}</b><span>${k}</span></div>`).join('')}<div class="kpi"><b>${result.summary.open}</b><span>open total</span></div></div>
<h2>OWASP Top 10:2025</h2><div class="cats" id="cats"></div>
<h2>Findings <span class="k" id="count"></span></h2>
<div class="controls"><input type="search" id="q" placeholder="Filter by rule, file, CWE, CVE, code…" aria-label="Filter findings"><span id="chips"></span></div>
<div id="list"></div>
<h2>Attack surface</h2><div id="surface"></div>
${(result.warnings || []).length ? `<h2>Warnings</h2><ul>${result.warnings.map((w) => `<li>${esc(w)}</li>`).join('')}</ul>` : ''}
</main>
<script type="application/json" id="data">${safeJson(data)}</script>
<script>${SCRIPT}</script>
</body></html>`;
}

module.exports = { toHtml };
