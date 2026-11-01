// Navigateur entièrement simulé : aucune API d'exploitation n'est contactée.
const {chromium, launchOptions} = require('./browser-test.cjs');
const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict');
(async () => {
  const browser = await chromium.launch(launchOptions);
  try {
    const page = await browser.newPage(), errors = [], sent = [];
    let disabled = false;
    page.on('pageerror', e => errors.push(e.message));
    await page.addInitScript(() => { window.EventSource = class extends EventTarget { close() {} }; });
    await page.route('http://ai.test/**', async route => {
      const request = route.request(), url = new URL(request.url());
      if (url.pathname === '/api/ai/status') return disabled
        ? route.fulfill({status: 503, json: {detail: 'Assistant désactivé : OPSCONTROL_AI_ENABLED=1 requis.'}})
        : route.fulfill({json: {connected: true, model: 'fixture-local', code_access: false, data_policy: {destination: 'modèle local (boucle locale)', endpoint: '127.0.0.1:1234', sent: 'question', redaction: 'secrets masqués', history: '100 derniers échanges'}}});
      if (url.pathname === '/api/ai/chat') {
        sent.push({body: JSON.parse(request.postData()), headers: request.headers()});
        return route.fulfill({contentType: 'text/event-stream', body: 'event: result\ndata: ' + JSON.stringify({answer: 'Hypothèse à confirmer.\n```bash\nsystemctl status fixture\n```\n<img src=x onerror="window.compromised=true">', conversation: 'a'.repeat(32), sources: [{path: 'README.md', line: 1}], model: 'fixture-local'}) + '\n\n'});
      }
      if (url.pathname === '/api/ai/document') return route.fulfill({json: {path: 'README.md', line: 1, text: 'Supervision en lecture seule'}});
      if (url.pathname === '/api/ai/history') return route.fulfill({json: {items: []}});
      if (url.pathname === '/api/overview') return route.fulfill({json: {hosts: [], counts: {}, job: {running: false}, jobs: {}, monitoring: {interval: 0}}});
      if (url.pathname === '/api/whoami') return route.fulfill({json: {role: 'viewer', can_admin: false, can_operate: false}});
      if (url.pathname === '/api/ssh/host-keys') return route.fulfill({json: {hosts: []}});
      if (url.pathname === '/api/daily') return route.fulfill({json: {counts: {}, priorities: [], sources: [], attention: [], batches: {}}});
      if (url.pathname.startsWith('/api/')) return route.fulfill({status: 404, json: {detail: 'Non simulé'}});
      const file = path.join(__dirname, 'web', url.pathname === '/' ? 'index.html' : url.pathname);
      return route.fulfill({body: fs.readFileSync(file), contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.png') ? 'image/png' : 'text/html'});
    });
    await page.goto('http://ai.test/');
    await page.locator('#nav [data-page="Assistant IA"]').click();
    await page.getByText('LM Studio connecté · fixture-local', {exact: true}).waitFor();
    await page.locator('#ai-message').fill('Pourquoi ce service est-il indisponible ?');
    await page.locator('#ai-send').click();
    await page.getByText('Réponse terminée · sources consultables ci-dessus.', {exact: true}).waitFor();
    assert.equal(sent.length, 1);
    assert.equal(sent[0].headers['x-cockpit-request'], '1');
    assert.equal(sent[0].body.stream, true);
    assert.equal(await page.locator('#ai-transcript img').count(), 0);
    assert.equal(await page.evaluate(() => !!window.compromised), false);
    await page.getByRole('button', {name: 'README.md:1', exact: true}).click();
    await page.waitForFunction(() => document.querySelector('#ai-source').textContent.includes('lecture seule'));
    await page.locator('#ai-new').click();
    assert.equal(await page.locator('#ai-transcript article').count(), 0);
    await page.locator('#ai-history').click();
    // Audit UI du 31/10 (fiches 18.1 et 18.2) : destination affichée ; désactivé = rien d'actionnable.
    assert.ok((await page.locator('#ai-policy').innerText()).includes('modèle local (boucle locale) (127.0.0.1:1234)'));
    disabled = true;
    await page.locator('#nav [data-page="Vue globale"]').click();
    await page.locator('#nav [data-page="Assistant IA"]').click();
    await page.locator('#ai-unavailable').filter({hasText: 'OPSCONTROL_AI_ENABLED=1'}).waitFor();
    assert.equal(await page.locator('#ai-send').isDisabled(), true);
    assert.equal(await page.locator('#ai-history').isDisabled(), true);
    assert.deepEqual(errors, []);
    console.log('PASS: navigation IA, chat SSE, sources, XSS neutralisé, nouvelle conversation et historique.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
