// Records the narrated demo: every scene lasts at least as long as its voice-over clip.
//   node demo/record_demo_vo.js <base-url> <out-dir>
// Needs demo/voiceover/durations.json (from make_voice.py). Writes <out-dir>/*.webm and
// <out-dir>/timings.json (scene start times in ms from the start of the video), which
// demo/voiceover/mix.py uses to lay the narration and the subtitle track on the video.
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const BASE = (process.argv[2] || 'http://localhost:8000').replace(/\/$/, '');
const OUT = process.argv[3] || 'demo-video';
const VO = path.join(__dirname, 'voiceover');
const DUR = JSON.parse(fs.readFileSync(path.join(VO, 'durations.json'), 'utf8'));
const SCENES = JSON.parse(fs.readFileSync(path.join(VO, 'scenes.json'), 'utf8'));
const CAP = Object.fromEntries(SCENES.map(s => [s.id, s.cap]));
const W = 1440, H = 810, GAP = 650;   // ms of breathing room after each clip
const TEAM = 'Team Spartans', MEMBERS = 'Hemanth Raja · Poojitha Katta';
const sleep = ms => new Promise(r => setTimeout(r, ms));

// Chapter label: a small lower-third on the left, clear of the subtitles (bottom centre).
const CHAPTER = () => {
  window.__cap = (t) => {
    let el = document.getElementById('__cap');
    if (!el) {
      if (!document.getElementById('__capfont')) {
        const l = document.createElement('link'); l.id = '__capfont'; l.rel = 'stylesheet';
        l.href = 'https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@600&family=IBM+Plex+Mono:wght@500&display=swap';
        document.head.appendChild(l);
      }
      el = document.createElement('div'); el.id = '__cap';
      el.style.cssText = 'position:fixed;left:28px;bottom:118px;z-index:2147483647;max-width:620px;pointer-events:none;' +
        'background:rgba(9,12,16,.88);backdrop-filter:blur(8px);color:#eef1f6;border-left:3px solid #8b8ffb;' +
        'border-radius:0 10px 10px 0;padding:9px 16px 10px;box-shadow:0 16px 40px rgba(0,0,0,.45);' +
        'transition:opacity .35s, transform .35s;opacity:0;transform:translateX(-12px)';
      el.innerHTML = '<div style="font:500 10.5px/1 \'IBM Plex Mono\',monospace;letter-spacing:2px;color:#a3a8ff;margin-bottom:5px">TOOL QUARANTINE</div>' +
        '<div id="__capt" style="font:600 18px/1.25 \'Space Grotesk\',Inter,system-ui,sans-serif"></div>';
      document.body.appendChild(el);
    }
    if (t) { document.getElementById('__capt').textContent = t; el.style.opacity = 1; el.style.transform = 'none'; }
    else { el.style.opacity = 0; el.style.transform = 'translateX(-12px)'; }
  };
};

// Full-screen title cards in the deck's style, with a short entrance animation.
const card = (body) => `data:text/html;charset=utf-8,${encodeURIComponent(`<!doctype html><html><head><meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Sans:wght@400;500&family=IBM+Plex+Mono:wght@500&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{background:radial-gradient(1100px 520px at 18% 0%,rgba(91,91,240,.22),transparent 60%),radial-gradient(800px 500px at 100% 100%,rgba(142,92,240,.16),transparent 60%),#0b0f13;
 color:#e9edf1;font-family:'IBM Plex Sans',sans-serif;display:flex;flex-direction:column;justify-content:center;padding:0 120px;overflow:hidden}
.k{font:500 15px/1 'IBM Plex Mono',monospace;letter-spacing:4px;text-transform:uppercase;color:#a3a8ff}
.h{font-family:'Space Grotesk';font-weight:700;letter-spacing:-2.5px;line-height:1.02}
.mono{font-family:'IBM Plex Mono'}
.in{opacity:0;transform:translateY(18px);animation:in .8s cubic-bezier(.2,.7,.2,1) forwards}
.d1{animation-delay:.25s}.d2{animation-delay:.6s}.d3{animation-delay:1s}.d4{animation-delay:1.5s}
@keyframes in{to{opacity:1;transform:none}}
.line{height:2px;width:0;background:linear-gradient(90deg,#5b5bf0,#8e5cf0);animation:grow 1.2s .4s cubic-bezier(.2,.7,.2,1) forwards}
@keyframes grow{to{width:220px}}
.mark{display:inline-grid;place-items:center;width:64px;height:64px;border-radius:16px;background:linear-gradient(135deg,#5b5bf0,#8e5cf0);font:700 24px 'Space Grotesk';color:#fff}
.foot{margin-top:72px;display:flex;gap:56px;font-size:16px;color:#93a0ad}
.foot b{display:block;font:500 12px 'IBM Plex Mono';letter-spacing:2px;text-transform:uppercase;color:#e9edf1;margin-bottom:6px}
</style></head><body>${body}</body></html>`)}`;

const HOOK = card(`
<div class="k in">An MCP server from a stranger</div>
<div class="h in d1 mono" style="font-size:84px;letter-spacing:-3px;margin:26px 0 22px">json-formatter</div>
<div class="line"></div>
<div class="in d2" style="font:500 40px/1.3 'Space Grotesk';color:#c8cdf9;margin-top:30px">“Pretty-print a JSON string with a given indent.<br><span style="color:#fff">Pure formatting.</span>”</div>`);

const TEAMCARD = card(`
<div class="k in">${TEAM} presents</div>
<div style="display:flex;align-items:center;gap:26px;margin:30px 0 18px" class="in d1"><span class="mark">TQ</span>
<span class="h" style="font-size:96px">Tool Quarantine</span></div>
<div class="in d2" style="font:500 34px/1.3 'Space Grotesk';color:#c8cdf9">Watch an agent tool run. <span style="color:#fff">Then decide.</span></div>
<div class="foot in d3"><div><b>Team</b>${TEAM}</div><div><b>Members</b>${MEMBERS}</div><div><b>Built on</b>Vultr Cloud Compute · Vultr Serverless Inference</div><div><b>Track</b>Blast Radius Zero</div></div>`);

const ENDCARD = card(`
<div class="k in">Tool Quarantine · by ${TEAM}</div>
<div class="h in d1" style="font-size:78px;margin:28px 0 0">Don’t install an agent tool<br><span style="background:linear-gradient(90deg,#a3a8ff,#c79bff);-webkit-background-clip:text;color:transparent">until you’ve watched it run.</span></div>
<div class="foot in d2"><div><b>Live demo</b>http://199.247.22.132/</div><div><b>Code</b>github.com/Hemanth-Raja/tool-qarantine</div><div><b>${TEAM}</b>${MEMBERS}</div></div>`);

async function smoothScrollTo(page, y, ms = 1600) {
  await page.evaluate(async ([y, ms]) => {
    const y0 = scrollY, t0 = performance.now();
    await new Promise(res => { (function f(t) { const k = Math.min(1, (t - t0) / ms), e = k < .5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2;
      scrollTo(0, y0 + (y - y0) * e); k < 1 ? requestAnimationFrame(f) : res(); })(t0); });
  }, [y, ms]);
}
const scrollToSel = async (page, sel, off = 90, ms = 1600) => {
  const y = await page.evaluate(([s, o]) => { const e = document.querySelector(s); return e ? e.getBoundingClientRect().top + scrollY - o : scrollY; }, [sel, off]);
  await smoothScrollTo(page, y, ms);
};

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: W, height: H }, recordVideo: { dir: OUT, size: { width: W, height: H } } });

  // The hook replays a finished json-formatter run; start one now if the console has none.
  const isJson = r => /json[-_]formatter/.test(r.tool || r.entry || '') && r.status === 'done';
  let runs = await (await ctx.request.get(BASE + '/api/runs')).json();
  let hookRun = (Array.isArray(runs) ? runs : runs.runs || []).find(isJson);
  if (!hookRun) {
    await ctx.request.post(BASE + '/api/runs', { data: { entry: 'python /tool/json_formatter.py', name: 'json-formatter' } });
    for (let i = 0; i < 90 && !hookRun; i++) {
      await sleep(2000);
      runs = await (await ctx.request.get(BASE + '/api/runs')).json();
      hookRun = (Array.isArray(runs) ? runs : runs.runs || []).find(isJson);
    }
  }

  await ctx.addInitScript(() => { try { localStorage.setItem('tq-reviewer', 'Hemanth Raja'); localStorage.setItem('tq-workspace', 'Team Spartans');
    localStorage.setItem('tq-theme', 'dark'); } catch (e) {} });
  await ctx.addInitScript(CHAPTER);
  const page = await ctx.newPage();
  const t0 = Date.now();
  const timings = {};
  // Run one scene: show its chapter label, do the actions, and hold until its voice clip ends.
  async function scene(id, actions) {
    const start = Date.now();
    timings[id] = start - t0;
    await page.evaluate(t => window.__cap && window.__cap(t), CAP[id] || '').catch(() => {});
    await actions();
    const left = start + DUR[id] * 1000 + GAP - Date.now();
    if (left > 0) await sleep(left);
  }
  const cap = t => page.evaluate(t => window.__cap && window.__cap(t), t).catch(() => {});

  // Hook: the promise, then what the tool really does.
  await page.goto(HOOK); await sleep(500);
  await scene('00-hook', async () => {});

  await page.goto(BASE + '/run/' + (hookRun ? hookRun.id : ''));
  await page.waitForSelector('#replay:not(.hide)', { timeout: 30000 }).catch(() => {});
  await scene('01-reveal', async () => {
    await page.evaluate(() => { document.body.style.zoom = '1.18'; });
    await scrollToSel(page, '#feed', 150, 10);
    await page.click('#replay').catch(() => {});
    await cap(CAP['01-reveal']);
  });

  await page.goto(TEAMCARD);
  await scene('02-team', async () => {});

  await page.goto(BASE + '/'); await sleep(400);
  await scene('03-problem', async () => {});
  await scene('04-how', async () => {
    await sleep(1500); await smoothScrollTo(page, 640, 3000); await sleep(8000); await smoothScrollTo(page, 1250, 3000);
  });

  await page.goto(BASE + '/app/scans'); await sleep(400);
  await scene('05-samples', async () => {
    await sleep(1500); await scrollToSel(page, 'button[onclick*="json_formatter"]', 320, 2500);
  });

  await scene('06-live', async () => {
    await page.click('button[onclick*="json_formatter"]');
    await page.waitForURL(/\/run\//);
    await cap(CAP['06-live']);
    await page.waitForSelector('#replay:not(.hide)', { timeout: 180000 });
  });

  await scene('07-verdict', async () => {});

  await scene('08-blast', async () => {
    await scrollToSel(page, '#blast', 80, 1800);
    await page.hover('#blastsvg .bnode[data-i="2"]').catch(() => {});
  });

  await scene('09-claims', async () => { await scrollToSel(page, '#claims', 80, 1600); });

  await scene('10-decision', async () => { await scrollToSel(page, '#approval', 90, 1600); });

  await scene('11-honest', async () => {
    await page.keyboard.press('Control+k'); await sleep(900);
    await page.keyboard.type('unit', { delay: 140 }); await sleep(1300);
    await page.keyboard.press('Enter');
    await page.waitForURL(/\/run\//);
    await cap(CAP['11-honest']);
  });

  await scene('12-approve', async () => {
    await page.waitForSelector('#replay:not(.hide)', { timeout: 180000 });
    await sleep(800);
    await scrollToSel(page, '#approval', 90, 1200); await sleep(2500);
    const ok = await page.$('#decide-ui button.ok:not([disabled])');
    if (ok) await ok.click();
  });

  await page.goto(BASE + '/app/registry'); await sleep(400);
  await scene('13-registry', async () => {});

  await page.goto(BASE + '/app/policies'); await sleep(500);
  await scene('14-policies', async () => {
    await sleep(4000);
    await page.locator('.rule').nth(1).locator('.seg button').nth(1).click().catch(() => {});
    await sleep(4000);
    await page.click('#discard').catch(() => {});
  });

  await page.goto(BASE + '/app/integrations'); await sleep(400);
  await scene('15-integrations', async () => { await sleep(3000); await smoothScrollTo(page, 650, 3000); });

  await page.goto(BASE + '/app'); await sleep(500);
  await scene('16-overview', async () => {});

  await page.goto(ENDCARD);
  await scene('17-end', async () => {});
  await sleep(1500);

  const v = page.video(); await ctx.close(); await browser.close();
  fs.writeFileSync(path.join(OUT, 'timings.json'), JSON.stringify(timings, null, 1));
  console.log('video:', await v.path());
})();
