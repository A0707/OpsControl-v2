// Audit transversal du 01/11 : stabilité visuelle de l'accueil (CLS), <h1> présent et accessible,
// titre de document propre à chaque écran, état accessible des vues Proxmox, thème appliqué avant
// le premier rendu. Fixture synthétique : aucune requête ne quitte le navigateur.
const {chromium, launchOptions} = require('./browser-test.cjs');
const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict');

const now = new Date().toISOString();
const hosts = [{key: 'web01', name: 'web01', ip: '192.0.2.10', registered: true, active_scope: true, status: 'ok', role: 'Web',
  environment: 'PROD', services: [], findings: [], checks: [], coverage: {measured: 15, total: 15}, collected_at: now}];

function observeShifts() {
  window.__cls = 0;
  new PerformanceObserver(list => list.getEntries().forEach(e => { if (!e.hadRecentInput) window.__cls += e.value; }))
    .observe({type: 'layout-shift', buffered: true});
}

async function open(browser, viewport, hash, theme) {
  const page = await browser.newPage({viewport});
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.addInitScript(observeShifts);
  await page.addInitScript(() => { window.EventSource = class extends EventTarget { close() {} }; });
  if (theme) await page.addInitScript(t => { try { localStorage.setItem('infraops-theme', t); } catch { /* indisponible */ } }, theme);
  // Premier rendu observé avant tout JavaScript applicatif : le thème doit déjà être le bon.
  await page.addInitScript(() => document.addEventListener('DOMContentLoaded', () => { window.__firstTheme = document.documentElement.dataset.theme; }, {once: true}));
  await page.route('http://stability.test/**', async route => {
    const url = new URL(route.request().url());
    if (route.request().method() !== 'GET') return route.fulfill({status: 403, json: {detail: 'lecture seule'}});
    if (url.pathname === '/api/overview') return route.fulfill({json: {hosts, counts: {ok: 1}, job: {running: false}, jobs: {ssh: {running: false}}, monitoring: {interval: 0}, availability: {sources: []}}});
    if (url.pathname === '/api/daily') return route.fulfill({json: {counts: {}, priorities: [], sources: [], attention: [], batches: {}}});
    if (url.pathname === '/api/whoami') return route.fulfill({json: {mode: 'local', authenticated: false, role: 'viewer', can_operate: false, can_admin: false}});
    if (url.pathname.startsWith('/api/')) return route.fulfill({status: 404, json: {detail: 'Non simulé'}});
    const file = path.join(__dirname, 'web', url.pathname === '/' ? 'index.html' : url.pathname);
    if (!fs.existsSync(file)) return route.fulfill({status: 404, body: ''});
    return route.fulfill({body: fs.readFileSync(file), contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.png') ? 'image/png' : 'text/html',
      headers: {'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'"}});
  });
  await page.goto('http://stability.test/' + hash);
  await page.waitForFunction(() => document.documentElement.dataset.shellReady === '1');
  await page.waitForTimeout(1500);
  return {page, errors};
}

(async () => {
  const browser = await chromium.launch(launchOptions);
  try {
    for (const viewport of [{width: 1440, height: 900}, {width: 390, height: 844}]) {
      const {page, errors} = await open(browser, viewport, '#/Vue%20globale', 'light');
      const cls = await page.evaluate(() => window.__cls);
      assert.ok(cls < 0.1, `CLS de l'accueil à ${viewport.width} px : ${cls.toFixed(3)} (objectif < 0,1)`);
      // Le <h1> reste dans la page et dans l'arbre accessible, même masqué visuellement.
      assert.equal(await page.locator('h1').count(), 1);
      assert.equal(await page.getByRole('heading', {level: 1, name: 'Vue globale'}).count(), 1);
      assert.equal(await page.title(), 'Vue globale — OpsControl');
      assert.equal(await page.evaluate(() => window.__firstTheme), 'light', 'thème appliqué avant le premier rendu');
      if (viewport.width === 1440) {
        // Fiches 01.2 et 01.3 : indicateurs et priorités visibles sans défilement sur 1440×900 ;
        // disponibilité nommée « réseau » ; chroniques à un clic.
        const bottom = await page.evaluate(() => document.querySelector('.v2-attention-now').getBoundingClientRect().bottom);
        assert.ok(bottom <= 900, 'priorités visibles sans défilement : ' + Math.round(bottom));
        await page.getByText('Joignables (réseau)').waitFor();
        await page.locator('[data-v2-chronic]').click();
        await page.waitForFunction(() => page === 'Incidents' && incFilters.chronic === 'only');
      }
      assert.deepEqual(errors, []);
      await page.close();
    }
    // Titre par écran, et vues Proxmox exposées comme un groupe de boutons à état.
    const {page, errors} = await open(browser, {width: 1440, height: 900}, '#/Incidents');
    assert.equal(await page.title(), 'Incidents — OpsControl');
    await page.evaluate(() => navigate('Proxmox'));
    await page.waitForFunction(() => document.title === 'Proxmox — OpsControl');
    await page.locator('[data-pve-mode="overview"][aria-pressed="true"]').waitFor();
    assert.equal(await page.locator('[data-pve-mode][aria-pressed="false"]').count(), 2);
    assert.deepEqual(errors, []);
    console.log('PASS: accueil stable (CLS < 0,1, bureau et mobile), <h1> accessible, titre par écran, vues Proxmox à état, thème avant rendu');
  } finally { await browser.close(); }
})().catch(e => { console.error(e); process.exitCode = 1; });
