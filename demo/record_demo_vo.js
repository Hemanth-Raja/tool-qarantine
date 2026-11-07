// Records the narrated demo: every scene lasts at least as long as its voice-over clip.
//   node demo/record_demo_vo.js <base-url> <out-dir>
// Needs demo/voiceover/durations.json (from make_voice.py). Writes <out-dir>/*.webm and
// <out-dir>/timings.json (scene start times in ms from the start of the video), which
// demo/voiceover/mix.py uses to lay the narration on the video.
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const BASE = (process.argv[2] || 'http://localhost:8000').replace(/\/$/, '');
const OUT = process.argv[3] || 'demo-video';
const VO = path.join(__dirname, 'voiceover');
const DUR = JSON.parse(fs.readFileSync(path.join(VO, 'durations.json'), 'utf8'));
const SCENES = JSON.parse(fs.readFileSync(path.join(VO, 'scenes.json'), 'utf8'));
const CAP = Object.fromEntries(SCENES.map(s => [s.id, s.cap]));
const W = 1440, H = 810, GAP = 700;   // ms of breathing room after each clip
const sleep = ms => new Promise(r => setTimeout(r, ms));

const CAPTION = () => {
  window.__cap = (t) => {
    let el = document.getElementById('__cap');
    if (!el) {
      el = document.createElement('div'); el.id = '__cap';
      el.style.cssText = 'position:fixed;left:50%;bottom:26px;transform:translateX(-50%);z-index:2147483647;max-width:1100px;' +
        'background:rgba(10,12,20,.9);color:#fff;border:1px solid rgba(140,150,255,.45);border-radius:12px;padding:10px 20px;' +
        'font:600 19px/1.35 Inter,system-ui,sans-serif;box-shadow:0 20px 50px rgba(0,0,0,.5);text-align:center;transition:opacity .3s';
      document.body.appendChild(el);
    }
    el.style.opacity = t ? 1 : 0; if (t) el.textContent = t;
  };
};
const card = (title, sub, foot) => `data:text/html;charset=utf-8,${encodeURIComponent(`<!doctype html><html><head><meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet"></head>
<body style="margin:0;height:100vh;display:grid;place-items:center;background:radial-gradient(900px 400px at 30% 10%,rgba(108,124,255,.25),transparent),#07090f;color:#eef1f7;font-family:Inter,sans-serif">
<div style="text-align:center;max-width:1100px;padding:0 40px">
<div style="display:inline-grid;place-items:center;width:84px;height:84px;border-radius:22px;background:linear-gradient(135deg,#6c7cff,#b06cff);font-weight:800;font-size:30px;margin-bottom:28px">TQ</div>
<div style="font-size:64px;font-weight:800;letter-spacing:-2px;line-height:1.05">${title}</div>
<div style="font-size:26px;color:#aab4ff;margin-top:18px">${sub}</div>
<div style="font-size:18px;color:#8b93a7;margin-top:34px">${foot || ''}</div></div></body></html>`)}`;

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
  await ctx.addInitScript(() => { try { localStorage.setItem('tq-reviewer', 'Hemanth Raja'); localStorage.setItem('tq-workspace', 'Acme Platform Team');
    localStorage.setItem('tq-theme', 'dark'); } catch (e) {} });
  await ctx.addInitScript(CAPTION);
  const page = await ctx.newPage();
  const t0 = Date.now();
  const timings = {};
  // Run one scene: show its caption, start its voice clip, do the actions, and hold until the clip ends.
  async function scene(id, actions) {
    const start = Date.now();
    timings[id] = start - t0;
    await page.evaluate(t => window.__cap && window.__cap(t), CAP[id] || '').catch(() => {});
    await actions();
    const left = start + DUR[id] * 1000 + GAP - Date.now();
    if (left > 0) await sleep(left);
  }
  const cap = t => page.evaluate(t => window.__cap && window.__cap(t), t).catch(() => {});

  await page.goto(card('Tool Quarantine', 'Watch an agent tool run in a sealed sandbox before you trust it.', 'Vultr Agent Rush · Blast Radius Zero'));
  await sleep(600);
  await scene('01-title', async () => {});

  await page.goto(BASE + '/'); await sleep(500);
  await scene('02-how', async () => {
    await sleep(6000); await smoothScrollTo(page, 640, 3000); await sleep(7000); await smoothScrollTo(page, 1250, 3000);
  });

  await page.goto(BASE + '/app/scans'); await sleep(400);
  await scene('03-samples', async () => {
    await sleep(1500); await scrollToSel(page, 'button[onclick*="json_formatter"]', 320, 2500);
  });

  await scene('04-live', async () => {
    await page.click('button[onclick*="json_formatter"]');
    await page.waitForURL(/\/run\//);
    await cap(CAP['04-live']);
    await page.waitForSelector('#replay:not(.hide)', { timeout: 180000 });
  });

  await scene('05-verdict', async () => {});

  await scene('06-blast', async () => {
    await scrollToSel(page, '#blast', 80, 1800);
    await page.hover('#blastsvg .bnode[data-i="2"]').catch(() => {});
  });

  await scene('07-claims', async () => { await scrollToSel(page, '#claims', 80, 1600); });

  await scene('08-decision', async () => { await scrollToSel(page, '#approval', 90, 1600); });

  await scene('09-honest', async () => {
    await page.keyboard.press('Control+k'); await sleep(900);
    await page.keyboard.type('unit', { delay: 140 }); await sleep(1300);
    await page.keyboard.press('Enter');
    await page.waitForURL(/\/run\//);
    await cap(CAP['09-honest']);
  });

  await scene('10-approve', async () => {
    await page.waitForSelector('#replay:not(.hide)', { timeout: 180000 });
    await sleep(800);
    await scrollToSel(page, '#approval', 90, 1200); await sleep(2500);
    const ok = await page.$('#decide-ui button.ok:not([disabled])');
    if (ok) await ok.click();
  });

  await page.goto(BASE + '/app/registry'); await sleep(400);
  await scene('11-registry', async () => {});

  await page.goto(BASE + '/app/policies'); await sleep(500);
  await scene('12-policies', async () => {
    await sleep(4000);
    await page.locator('.rule').nth(1).locator('.seg button').nth(1).click().catch(() => {});
    await sleep(4500);
    await page.click('#discard').catch(() => {});
  });

  await page.goto(BASE + '/app/integrations'); await sleep(400);
  await scene('13-integrations', async () => { await sleep(3000); await smoothScrollTo(page, 650, 3000); });

  await page.goto(BASE + '/app'); await sleep(500);
  await scene('14-overview', async () => {});
  await cap('');

  await page.goto(card('Don’t install an agent tool<br>until you’ve watched it run.', 'Tool Quarantine · sandboxes on Vultr · agent on Vultr Serverless Inference', 'github.com/Hemanth-Raja/tool-qarantine'));
  await scene('15-end', async () => {});
  await sleep(1200);

  const v = page.video(); await ctx.close(); await browser.close();
  fs.writeFileSync(path.join(OUT, 'timings.json'), JSON.stringify(timings, null, 1));
  console.log('video:', await v.path());
})();
