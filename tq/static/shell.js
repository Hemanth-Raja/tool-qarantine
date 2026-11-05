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
  <div class="sp"></div><span class="pill hide-sm">agent <b id="agentname">…</b></span>
  <a class="btn" href="/app/scans#new">+ New scan</a>
  <button class="avatar" id="me" title="${esc(me||'Set your reviewer name')}">${esc(initials)}</button></header>`;
b.prepend(side); b.appendChild(main);
if(b.dataset.title&&!b.dataset.hidehead){const h=document.createElement('div');h.className='phead';
  h.innerHTML=`<div><h1>${esc(b.dataset.title)}</h1>${b.dataset.sub?`<p class="sub">${esc(b.dataset.sub)}</p>`:''}</div><div class="sp"></div><div id="pactions"></div>`;
  page.prepend(h)}
main.appendChild(page);
b.classList.add('app');
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
