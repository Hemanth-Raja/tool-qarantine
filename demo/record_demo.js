// Records the Tool Quarantine demo video with on-screen captions.
//   npm i playwright && npx playwright install chromium     (once)
//   node demo/record_demo.js http://199.247.22.132 out-dir
// Produces out-dir/<random>.webm ; convert with:
//   ffmpeg -i out-dir/*.webm -c:v libx264 -pix_fmt yuv420p -crf 20 tool-quarantine-demo.mp4
const { chromium } = require('playwright');
const BASE = (process.argv[2] || 'http://localhost:8000').replace(/\/$/, '');
const OUT = process.argv[3] || 'demo-video';
const W = 1440, H = 810;
const sleep = ms => new Promise(r => setTimeout(r, ms));

const CAPTION = () => {
  window.__cap = (t, s) => {
    let el = document.getElementById('__cap');
    if (!el) {
      el = document.createElement('div'); el.id = '__cap';
      el.style.cssText = 'position:fixed;left:50%;bottom:28px;transform:translateX(-50%);z-index:2147483647;max-width:1100px;' +
        'background:rgba(10,12,20,.92);color:#fff;border:1px solid rgba(140,150,255,.45);border-radius:14px;padding:14px 22px;' +
        'font:600 22px/1.35 Inter,system-ui,sans-serif;box-shadow:0 20px 50px rgba(0,0,0,.5);text-align:center;transition:opacity .3s';
      document.body.appendChild(el);
    }
    if (!t) { el.style.opacity = 0; return; }
    el.style.opacity = 1;
    el.innerHTML = t + (s ? `<div style="font-weight:450;font-size:16px;color:#b8c0ff;margin-top:4px">${s}</div>` : '');
  };
};
const card = (title, sub, foot) => `data:text/html,${encodeURIComponent(`<!doctype html><html><head><meta charset="utf-8">
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
const cap = (page, t, s) => page.evaluate(([t, s]) => window.__cap && window.__cap(t, s), [t, s || '']);

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: W, height: H }, recordVideo: { dir: OUT, size: { width: W, height: H } } });
  await ctx.addInitScript(() => { try { localStorage.setItem('tq-reviewer', 'Hemanth Raja'); localStorage.setItem('tq-workspace', 'Acme Platform Team');
    localStorage.setItem('tq-theme', 'dark'); } catch (e) {} });
  await ctx.addInitScript(CAPTION);
  const page = await ctx.newPage();

  // 0. title
  await page.goto(card('Tool Quarantine', 'Watch an agent tool run in a sealed sandbox before you trust it.', 'Vultr Agent Rush · Blast Radius Zero'));
  await sleep(4500);

  // 1. the problem + product page
  await page.goto(BASE + '/'); await sleep(800);
  await cap(page, 'AI agents install MCP tools from strangers on the internet.', 'A tool’s description is a promise. Nobody checks it.');
  await sleep(4500);
  await cap(page, 'Tool Quarantine runs the tool in a disposable, network-sinkholed sandbox', 'an agent on Vultr Serverless Inference uses it like a real user, and we record everything it touches');
  await smoothScrollTo(page, 620, 2500); await sleep(3500);
  await smoothScrollTo(page, 0, 1200);

  // 2. a malicious tool
  await page.goto(BASE + '/app/scans'); await sleep(600);
  await cap(page, 'Seven sample MCP servers. All of them look harmless.', 'Let’s quarantine “json-formatter”, which says it does “pure formatting”.');
  await scrollToSel(page, 'button[onclick*="json_formatter"]', 300, 1400); await sleep(3500);
  await page.click('button[onclick*="json_formatter"]');
  await page.waitForURL(/\/run\//); await sleep(500);
  await cap(page, 'Live: every file it opens and every host it calls, as it happens', 'The box has no route to the internet. Decoy credentials are planted.');
  await page.waitForSelector('#replay:not(.hide)', { timeout: 120000 }); await sleep(1500);
  await cap(page, 'Verdict: DANGEROUS. A “formatter” read cloud keys and tried to reach the internet.', 'The sinkhole caught the attempt, nothing got out, and workspace policy blocked this version automatically.');
  await sleep(5000);
  await scrollToSel(page, '#blast', 80, 1800);
  await cap(page, 'Blast radius: every reach stopped at the sandbox wall', 'Zero bytes, files or hosts reached outside.');
  await page.hover('#blastsvg .bnode[data-i="2"]').catch(() => {}); await sleep(4500);
  await scrollToSel(page, '#claims', 80, 1600);
  await cap(page, 'Claims vs. reality', 'What the tool says about itself, next to what the sandbox saw it do.');
  await sleep(4500);
  await scrollToSel(page, '#approval', 90, 1600);
  await cap(page, 'Approval is enforced, not a label', 'Policy forbids approving it. Every agent or gateway that asks the registry is refused.');
  await sleep(5000);

  // 3. an honest tool, opened from the command palette
  await cap(page, 'Ctrl+K: jump anywhere, or start a scan', '');
  await page.keyboard.press('Control+k'); await sleep(700);
  await page.keyboard.type('unit', { delay: 120 }); await sleep(1200);
  await page.keyboard.press('Enter');
  await page.waitForURL(/\/run\//); await sleep(400);
  await cap(page, 'An honest tool: “unit-converter”', 'Pure computation. Touches nothing.');
  await page.waitForSelector('#replay:not(.hide)', { timeout: 120000 }); await sleep(1500);
  await scrollToSel(page, '#approval', 90, 1200);
  await cap(page, 'TRUSTED 100/100. Approve pins this exact code (sha256) to the allowlist', 'Change one byte and the tool must be quarantined again, so an update can’t sneak in a rug pull.');
  await sleep(2500);
  const ok = await page.$('#decide-ui button.ok:not([disabled])');
  if (ok) { await ok.click(); await sleep(4500); } else await sleep(3000);

  // 4. registry, policies, integrations
  await page.goto(BASE + '/app/registry'); await sleep(500);
  await cap(page, 'The registry: approved and blocked versions, pinned by fingerprint', 'Agents and MCP gateways ask /api/registry/check before they launch a tool.');
  await sleep(5000);
  await page.goto(BASE + '/app/policies'); await sleep(800);
  await cap(page, 'Workspace policies decide what gets blocked automatically', 'Change a rule and the impact preview shows what it would do to your tools before you save.');
  await sleep(2500);
  const seg = page.locator('.rule').nth(1).locator('.seg button').nth(1);
  await seg.click().catch(() => {}); await sleep(3500);
  await page.click('#discard').catch(() => {}); await sleep(1200);
  await page.goto(BASE + '/app/integrations'); await sleep(600);
  await cap(page, 'Drop-in checks for MCP gateways, the CLI and GitHub Actions', '');
  await sleep(2500); await smoothScrollTo(page, 700, 2500); await sleep(1500);

  // 5. overview
  await page.goto(BASE + '/app'); await sleep(800);
  await cap(page, 'One view of every tool your team has quarantined', 'Threats contained, exfiltration attempts sinkholed, versions waiting for a decision.');
  await sleep(5000);
  await page.click('#theme'); await sleep(2500); await page.click('#theme'); await sleep(800);
  await cap(page, '');

  // 6. end card
  await page.goto(card('Don’t install an agent tool<br>until you’ve watched it run.', 'Tool Quarantine · sandboxes on Vultr · agent on Vultr Serverless Inference', 'github.com/Hemanth-Raja/tool-qarantine'));
  await sleep(5000);
  const v = page.video(); await ctx.close(); await browser.close();
  console.log('video:', await v.path());
})();
