// App shell shared by every console page: sidebar nav, workspace header, helpers.
// A page sets <body data-nav="overview" data-title="Overview" data-sub="..."> and puts its
// content in <main id="page">. This script wraps it in the sidebar + top bar.
(function(){
const NAV=[
  ['overview','Overview','/app','<path d="M3 13h8V3H3zm0 8h8v-6H3zm10 0h8V11h-8zm0-18v6h8V3z"/>'],
  ['scans','Scans','/app/scans','<path d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5zm-1 14-4-4 1.4-1.4L11 13.2l4.6-4.6L17 10z"/>'],
  ['registry','Registry','/app/registry','<path d="M4 4h16v4H4zm0 6h16v4H4zm0 6h16v4H4z"/>'],
  ['policies','Policies','/app/policies','<path d="M12 3 2 8l10 5 10-5zm-8 8v5l8 4 8-4v-5l-8 4z"/>'],
  ['integrations','Integrations','/app/integrations','<path d="M8 3v4H5v3a4 4 0 0 0 4 4h1v7h4v-7h1a4 4 0 0 0 4-4V7h-3V3h-2v4h-4V3z"/>'],
];
window.esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
window.ago=t=>{if(!t)return'';const s=Date.now()/1000-t;if(s<60)return'just now';if(s<3600)return Math.floor(s/60)+'m ago';
  if(s<86400)return Math.floor(s/3600)+'h ago';return Math.floor(s/86400)+'d ago'};
window.store={get:(k,d='')=>{try{return localStorage.getItem(k)??d}catch(e){return d}},set:(k,v)=>{try{localStorage.setItem(k,v)}catch(e){}}};
window.getJSON=async u=>{const r=await fetch(u);if(!r.ok)throw new Error((await r.json().catch(()=>({}))).detail||r.statusText);return r.json()};
window.toast=(msg,kind='')=>{let t=document.getElementById('toast');if(!t){t=document.createElement('div');t.id='toast';document.body.appendChild(t)}
  t.className='toast show '+kind;t.textContent=msg;clearTimeout(t._h);t._h=setTimeout(()=>t.className='toast',2600)};
window.copyText=(txt,msg='Copied')=>{navigator.clipboard?.writeText(txt).then(()=>toast(msg),()=>toast('Copy failed','bad'))};

const b=document.body, page=document.getElementById('page'), active=b.dataset.nav;
const ws=store.get('tq-workspace','Demo workspace'), me=store.get('tq-reviewer','');
const initials=(me||'Reviewer').split(/\s+/).map(x=>x[0]).join('').slice(0,2).toUpperCase();
const side=document.createElement('aside'); side.className='side';
side.innerHTML=`<a class="sbrand" href="/"><span class="logo">TQ</span><span>Tool Quarantine</span></a>
  <button class="wsw" id="wsw" title="Rename workspace"><span class="wsav">${esc(ws[0]||'W')}</span>
    <span class="wsn"><b>${esc(ws)}</b><small>Hackathon edition</small></span><span class="dim">⌄</span></button>
  <nav class="snav">${NAV.map(([k,l,h,ic])=>`<a href="${h}" class="${k===active?'on':''}">
    <svg viewBox="0 0 24 24" aria-hidden="true">${ic}</svg><span>${l}</span>${k==='scans'?'<em class="cnt hide" id="pendcnt"></em>':''}</a>`).join('')}</nav>
  <div class="sfoot">
    <a href="/api/registry" target="_blank" class="slink">API</a><a href="https://github.com/Hemanth-Raja/tool-qarantine" target="_blank" class="slink">GitHub</a>
    <div class="sys"><span class="dot" id="sysdot"></span><span id="systxt">Checking sandbox…</span></div>
    <div class="dim" style="font-size:11.5px">Sandboxes on <b style="color:var(--muted)">Vultr</b> · Frankfurt</div>
  </div>`;
const main=document.createElement('div'); main.className='main';
main.innerHTML=`<header class="tbar"><button class="burger" id="burger" aria-label="Menu">☰</button>
  <div class="crumbs"><span class="dim">${esc(ws)}</span><span class="dim">/</span><b>${esc(b.dataset.title||'')}</b></div>
  <div class="sp"></div>
  <button class="kbtn hide-sm" id="kopen"><svg viewBox="0 0 24 24"><path d="M10 4a6 6 0 1 0 3.7 10.7l4.8 4.8 1.4-1.4-4.8-4.8A6 6 0 0 0 10 4zm0 2a4 4 0 1 1 0 8 4 4 0 0 1 0-8z"/></svg>Search or jump to…<kbd>${navigator.platform.includes('Mac')?'⌘':'Ctrl'} K</kbd></button>
  <span class="pill hide-sm">agent <b id="agentname">…</b></span>
  <button class="iconbtn" id="theme" title="Switch light / dark" aria-label="Switch light or dark theme"></button>
  <a class="btn" href="/app/scans#new">+ New scan</a>
  <button class="avatar" id="me" title="${esc(me||'Set your reviewer name')}">${esc(initials)}</button></header>`;
b.prepend(side); b.appendChild(main);
if(b.dataset.title&&!b.dataset.hidehead){const h=document.createElement('div');h.className='phead';
  h.innerHTML=`<div><h1>${esc(b.dataset.title)}</h1>${b.dataset.sub?`<p class="sub">${esc(b.dataset.sub)}</p>`:''}</div><div class="sp"></div><div id="pactions"></div>`;
  page.prepend(h)}
main.appendChild(page);
b.classList.add('app');
// ---- theme
const SUN='<svg viewBox="0 0 24 24"><path d="M12 7a5 5 0 1 0 0 10 5 5 0 0 0 0-10zm0-5 1.5 3h-3zm0 20-1.5-3h3zM2 12l3-1.5v3zm20 0-3 1.5v-3zM4.9 4.9l3.2 1-2.1 2.2zm14.2 14.2-3.2-1 2.1-2.2zM4.9 19.1l1-3.2 2.2 2.1zM19.1 4.9l-1 3.2-2.2-2.1z"/></svg>';
const MOON='<svg viewBox="0 0 24 24"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';
window.setTheme=t=>{document.documentElement.dataset.theme=t;store.set('tq-theme',t);
  document.getElementById('theme').innerHTML=t==='dark'?SUN:MOON;document.dispatchEvent(new CustomEvent('tqtheme',{detail:t}))};
setTheme(document.documentElement.dataset.theme||'dark');
document.getElementById('theme').onclick=()=>setTheme(document.documentElement.dataset.theme==='dark'?'light':'dark');
// ---- command palette
const SAMPLES=[['csv-analyst','csv_analyst','honest'],['unit-converter','unit_converter','honest'],['notes-search','notes_search','over-reaching'],
  ['doc-converter','doc_converter','persistence'],['json-formatter','json_formatter','exfiltration'],['weather-forecast','weather_forecast','tool poisoning'],
  ['github-helper','github_helper','rug pull']];
async function startSample(f,n){toast('Starting '+n+' in a fresh sandbox…');
  const r=await fetch('/api/runs',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({entry:`python /tool/${f}.py`,name:n})});
  const j=await r.json(); if(r.ok)location.href='/run/'+j.id; else toast(j.detail||'Could not start','bad')}
let K=null, items=[], sel=0, runsCache=null;
function baseItems(){
  const it=NAV.map(([k,l,h])=>({g:'Go to',t:l,k:'page',run:()=>location.href=h}));
  it.push({g:'Actions',t:'New scan',k:'action',run:()=>location.href='/app/scans#new'},
    {g:'Actions',t:'Switch to '+(document.documentElement.dataset.theme==='dark'?'light':'dark')+' theme',k:'action',run:()=>document.getElementById('theme').click()},
    {g:'Actions',t:'Set your reviewer name',k:'action',run:()=>document.getElementById('me').click()},
    {g:'Actions',t:'Rename workspace',k:'action',run:()=>document.getElementById('wsw').click()},
    {g:'Actions',t:'Copy registry check URL',k:'action',run:()=>copyText(location.origin+'/api/registry/check?hash=','Registry check URL copied')},
    {g:'Actions',t:'Open product page',k:'action',run:()=>location.href='/'});
  SAMPLES.forEach(([n,f,kind])=>it.push({g:'Quarantine a sample',t:n,sub:kind,k:'sample',run:()=>startSample(f,n)}));
  (runsCache||[]).slice(0,25).forEach(r=>it.push({g:'Recent scans',t:r.tool,sub:r.verdict?`${r.verdict.label} · ${r.verdict.score}`:r.status,
    badge:r.verdict&&r.verdict.label,when:r.started,k:'run',run:()=>location.href='/run/'+r.id}));
  return it;
}
function openK(){
  if(!K){K=document.createElement('div');K.className='kpal';K.innerHTML=`<div class="kbox" role="dialog" aria-label="Command palette">
    <div class="kin"><svg viewBox="0 0 24 24"><path d="M10 4a6 6 0 1 0 3.7 10.7l4.8 4.8 1.4-1.4-4.8-4.8A6 6 0 0 0 10 4zm0 2a4 4 0 1 1 0 8 4 4 0 0 1 0-8z"/></svg>
    <input id="kq" placeholder="Search pages, scans, samples, actions…" autocomplete="off"><kbd>esc</kbd></div><div class="klist" id="klist"></div>
    <div class="kfoot"><span><kbd>↑</kbd><kbd>↓</kbd> move</span><span><kbd>↵</kbd> open</span><span><kbd>esc</kbd> close</span></div></div>`;
    document.body.appendChild(K);
    K.addEventListener('mousedown',e=>{if(e.target===K)closeK()});
    const q=K.querySelector('#kq');
    q.oninput=()=>{sel=0;renderK()};
    q.onkeydown=e=>{if(e.key==='ArrowDown'){sel=Math.min(sel+1,items.length-1);renderK();e.preventDefault()}
      else if(e.key==='ArrowUp'){sel=Math.max(sel-1,0);renderK();e.preventDefault()}
      else if(e.key==='Enter'){const x=items[sel];if(x){closeK();x.run()}}
      else if(e.key==='Escape')closeK()};
  }
  K.classList.add('show');const q=K.querySelector('#kq');q.value='';sel=0;renderK();setTimeout(()=>q.focus(),10);
  if(!runsCache)fetch('/api/runs').then(r=>r.json()).then(r=>{runsCache=r;renderK()}).catch(()=>{});
}
function closeK(){K&&K.classList.remove('show')}
function renderK(){
  const q=K.querySelector('#kq').value.trim().toLowerCase();
  items=baseItems().filter(x=>!q||(x.t+' '+(x.sub||'')+' '+x.g).toLowerCase().includes(q));
  if(!q)items=items.filter(x=>x.g!=='Recent scans'||items.filter(y=>y.g==='Recent scans').indexOf(x)<6);
  let g='', html='';
  items.forEach((x,i)=>{if(x.g!==g){g=x.g;html+=`<div class="kg">${esc(g)}</div>`}
    html+=`<div class="ki ${i===sel?'on':''}" data-i="${i}"><span class="kt">${esc(x.t)}</span>${x.sub?`<span class="${x.badge?'badge b-'+x.badge:'dim'}" style="font-size:11.5px">${esc(x.sub)}</span>`:''}
      <span class="sp"></span>${x.when?`<span class="dim" style="font-size:12px">${ago(x.when)}</span>`:''}<span class="kk">${x.k==='sample'?'run':x.k==='run'?'open':x.k==='page'?'go':'do'}</span></div>`});
  const L=K.querySelector('#klist'); L.innerHTML=html||'<div class="empty">Nothing matches.</div>';
  L.querySelectorAll('.ki').forEach(el=>{el.onmouseenter=()=>{sel=+el.dataset.i;L.querySelectorAll('.ki').forEach(e=>e.classList.toggle('on',e===el))};
    el.onclick=()=>{const x=items[+el.dataset.i];closeK();x.run()}});
  const on=L.querySelector('.ki.on'); on&&on.scrollIntoView({block:'nearest'});
}
window.openPalette=openK;
document.getElementById('kopen').onclick=openK;
document.addEventListener('keydown',e=>{if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='k'){e.preventDefault();K&&K.classList.contains('show')?closeK():openK()}
  else if(e.key==='/'&&!/INPUT|TEXTAREA/.test(document.activeElement.tagName)){e.preventDefault();openK()}});
document.getElementById('burger').onclick=()=>b.classList.toggle('navopen');
document.getElementById('wsw').onclick=()=>{const n=prompt('Workspace name',ws);if(n&&n.trim()){store.set('tq-workspace',n.trim());location.reload()}};
document.getElementById('me').onclick=()=>{const n=prompt('Your name (shown on approvals and policy changes)',me);if(n!==null){store.set('tq-reviewer',n.trim());location.reload()}};
fetch('/api/config').then(r=>r.json()).then(c=>{document.getElementById('agentname').textContent=c.agent;window.TQCONFIG=c;
  document.dispatchEvent(new CustomEvent('tqconfig',{detail:c}))}).catch(()=>{});
fetch('/healthz').then(r=>{const ok=r.ok;document.getElementById('sysdot').className='dot '+(ok?'ok':'bad');
  document.getElementById('systxt').textContent=ok?'All systems operational':'Service degraded'}).catch(()=>{
  document.getElementById('sysdot').className='dot bad';document.getElementById('systxt').textContent='Unreachable'});
fetch('/api/stats?days=1').then(r=>r.json()).then(s=>{const e=document.getElementById('pendcnt');
  if(s.pending_count){e.textContent=s.pending_count;e.title=s.pending_count+' tool versions waiting for a decision';e.classList.remove('hide')}}).catch(()=>{});
})();
