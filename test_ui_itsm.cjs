// Parcours GLPI entièrement simulé, sans serveur ni écriture distante.
const {chromium, launchOptions} = require('./browser-test.cjs');
const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict');
(async () => {
  const browser = await chromium.launch(launchOptions);
  try {
    const page = await browser.newPage({viewport: {width: 1280, height: 900}});
    const errors = [], posts = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.addInitScript(() => { window.EventSource = class extends EventTarget {close() {}}; });
    const stamp = new Date().toISOString();
    let local = false, backendAvailable = true;
    let dossier = {id: 'test-case', origin: 'incident', kind: 'Ticket', reference: 'OC-test',
      owner: 'admin', owner_auth: 'proxy', taken_at: stamp, status: 'pending', remote_id: null,
      snapshot: {title: 'Service indisponible', source: 'Zabbix', severity: 'critical', state: 'acknowledged', opened_at: stamp}, events: []};
    // Correspondances GLPI (GET /api/itsm/links) : ticket clos alors que l'alerte est toujours
    // affichée, et incident résolu dont le ticket reste ouvert (incohérence calculée serveur).
    const links = [
      {id: 'case-alert', origin: 'alert', origin_id: 'SSH:disk:critical|2026-10-19T08:00:00+00:00', kind: 'Ticket', reference: 'OC-ALERT',
        status: 'linked', remote_id: 28, remote_status: '6', remote_status_label: 'Clos', remote_checked_at: stamp, origin_state: 'active', mismatch: null},
      {id: 'case-inc', origin: 'incident', origin_id: 'Zabbix|srv|down', kind: 'Ticket', reference: 'OC-INC', status: 'linked', remote_id: 29,
        remote_status: '2', remote_status_label: 'En cours (attribué)', origin_state: 'resolved', mismatch: 'Anomalie résolue dans OpsControl, ticket GLPI encore ouvert'}];
    const alerte = {id: 'SSH:disk:critical', source: 'SSH', severity: 'critical', title: 'Disque plein', fresh: true, observed_at: stamp,
      max_age_seconds: 900, count: 1, delay: '', chronic: false, ack: null, targets: [{name: 'srv1', observed_at: stamp, started_at: stamp}]};
    await page.route('**/*', async route => {
      const req = route.request(), url = new URL(req.url());
      if (req.method() === 'POST') {
        const body = req.postDataJSON();
        posts.push({path: url.pathname, body});
        if (url.pathname === '/api/itsm/take') {
          dossier = {...dossier, status: 'pending', kind: body.kind, remote_id: null, url: null};
          return route.fulfill({json: dossier});
        }
        if (url.pathname === '/api/itsm/preview') return route.fulfill({json: {kind: 'Ticket', observer_id: 6,
          preview_hash: 'reviewed', payload: {name: '[OC-test] Service indisponible', content: '<h3>Diagnostic et preuves</h3><p>&lt;script&gt;preuve échappée&lt;/script&gt;</p>', entities_id: 0, _users_id_requester: 61}}});
        if (url.pathname === '/api/itsm/create') {
          dossier = {...dossier, status: 'linked', remote_id: 123, url: 'https://glpi.example.test/front/ticket.form.php?id=123'};
          return route.fulfill({json: dossier});
        }
        if (url.pathname === '/api/itsm/reconcile') return route.fulfill({json: dossier});
        return route.fulfill({json: {}});
      }
      if (url.pathname === '/api/itsm/status') return backendAvailable ? route.fulfill({json: {available: true, protocol: 1}}) : route.fulfill({status: 404, json: {detail: 'Not Found'}});
      if (url.pathname === '/api/itsm/cases') return route.fulfill({json: {items: [dossier]}});
      if (url.pathname === '/api/itsm/links') return route.fulfill({json: {items: links, sync: {}}});
      if (url.pathname === '/api/alerts') return route.fulfill({json: {alerts: [alerte], generated_at: stamp, counts: {critical: 1}, levels: [], policy: [], sources: [], scope: ''}});
      if (url.pathname === '/api/itsm/detail') return route.fulfill({json: dossier});
      if (url.pathname === '/api/whoami') return route.fulfill({json: {role: 'admin', authenticated: !local, user: local ? null : 'admin', can_admin: true, can_operate: true}});
      if (url.pathname === '/api/overview') return route.fulfill({json: {hosts: [], counts: {}, job: {running: false}, monitoring: {interval: 0}, jobs: {}, availability: {sources: []}}});
      if (url.pathname.startsWith('/api/')) return route.fulfill({json: {}});
      const file = path.join(__dirname, 'web', url.pathname === '/' ? 'index.html' : url.pathname);
      if (!fs.existsSync(file)) return route.fulfill({status: 404, body: ''});
      return route.fulfill({body: fs.readFileSync(file), contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.png') ? 'image/png' : 'text/html'});
    });
    await page.goto('http://itsm.test/#/Dossiers%20ITSM');
    await page.locator('[data-itsm-open]').click();
    await page.getByRole('button', {name: 'Prévisualiser le ticket', exact: true}).click();
    await page.getByRole('button', {name: 'Confirmer et créer dans GLPI'}).waitFor();
    assert.equal(posts.length, 1, 'prévisualiser ne crée aucun ticket');
    assert.equal(await page.locator('#itsm-preview script').count(), 0);
    await page.getByRole('button', {name: 'Confirmer et créer dans GLPI'}).click();
    const link = page.getByRole('link', {name: 'Ouvrir dans GLPI #123'});
    await link.waitFor();
    assert.equal(posts[1].body.confirmed, true);
    assert.equal(posts[1].body.preview_hash, 'reviewed');
    assert.equal(await page.locator('[data-itsm-create]').count(), 0);
    await page.setViewportSize({width: 390, height: 844});
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await page.locator('[data-itsm-close]').click();
    local = true;
    dossier = {...dossier, status: 'pending', remote_id: null, url: null};
    await page.reload();
    await page.locator('[data-itsm-open]').waitFor();
    await page.locator('[data-itsm-open]').click();
    const currentName = page.locator('[data-itsm-by]');
    await currentName.waitFor();
    assert.equal(await currentName.inputValue(), '');
    const beforeAnonymous = posts.length;
    await page.locator('[data-itsm-preview]').click();
    assert.equal(posts.length, beforeAnonymous, 'un nom vide ne déclenche aucun POST');
    assert.equal(await currentName.evaluate(el => el === document.activeElement), true);
    await currentName.fill('  Operator  ');
    await page.locator('[data-itsm-preview]').click();
    await page.locator('[data-itsm-create]').waitFor();
    assert.equal(posts.at(-1).body.by, 'Operator');
    await page.locator('[data-itsm-close]').click();
    await page.reload();
    await page.locator('[data-itsm-open]').click();
    assert.equal(await page.locator('[data-itsm-by]').inputValue(), 'Operator', 'nom conservé après rechargement et réouverture');
    await page.locator('[data-itsm-preview]').click();
    await page.locator('[data-itsm-create]').waitFor();
    assert.equal(posts.at(-1).body.by, 'Operator');
    await page.locator('[data-itsm-by]').fill('Intervenant courant');
    await page.locator('[data-itsm-create]').click();
    await page.locator('[data-itsm-reconcile]').waitFor();
    assert.equal(posts.at(-1).body.by, 'Intervenant courant');
    await page.locator('[data-itsm-reconcile]').click();
    await page.waitForFunction(() => !document.querySelector('[data-itsm-reconcile]')?.disabled);
    assert.equal(posts.at(-1).path, '/api/itsm/reconcile');
    assert.equal(posts.at(-1).body.by, 'Intervenant courant');
    assert.equal(dossier.owner, 'admin', 'le responsable du dossier reste inchangé');
    await page.locator('[data-itsm-close]').click();
    await page.evaluate(() => itsmStart('finding', 'service:wazuh-indexer-performance-analyzer.service', 'srv'));
    const form = page.locator('#itsm-take');
    assert.equal(await form.locator('input[name=by]').getAttribute('required'), '');
    await form.locator('select').selectOption('Problem');
    assert.equal(await form.locator('textarea').getAttribute('required'), '');
    const fields = await form.locator('label').evaluateAll(labels => labels.map(label => {
      const r = label.getBoundingClientRect(); return {top: r.top, bottom: r.bottom};
    }));
    assert.ok(fields.every((r, i) => !i || r.top >= fields[i - 1].bottom), 'champs empilés sans chevauchement');
    assert.ok(await page.locator('#itsm-dialog').evaluate(d => d.scrollWidth <= d.clientWidth + 1), 'dialogue mobile sans débordement');
    await form.locator('textarea').fill('Service récurrent nécessitant une analyse structurelle');
    await form.locator('input[name=by]').fill('Opérateur local');
    await form.getByRole('button', {name: 'Prendre en charge / consulter le dossier'}).click();
    await page.locator('[data-itsm-preview]').waitFor();
    assert.equal(posts.at(-1).path, '/api/itsm/take');
    assert.equal(posts.at(-1).body.kind, 'Problem');
    await page.locator('[data-itsm-close]').click();
    backendAvailable = false;
    const before = posts.length;
    await page.evaluate(() => itsmStart('finding', 'disk', 'srv'));
    await page.locator('#itsm-take .form-error').getByText(/Redémarrez OpsControl/).waitFor();
    assert.equal(await page.locator('#itsm-take [type=submit]').isDisabled(), true);
    assert.equal(posts.length, before, 'backend ancien : aucun POST envoyé');
    backendAvailable = true;
    await page.setViewportSize({width: 1280, height: 900});
    await page.evaluate(() => itsmDialog.close());
    await page.goto('http://itsm.test/#/Alertes');
    const badge = page.locator('.alert-item .itsm-badge');
    await badge.waitFor();
    assert.equal((await badge.textContent()).trim(), 'GLPI #28 · Clos');
    assert.match(await page.locator('.alert-item .itsm-mismatch').textContent(), /Ticket GLPI clos, anomalie toujours active/);
    assert.equal(await page.locator('.alert-item [data-itsm-origin="alert"]').count(), 1, 'le bouton Ticket GLPI reste disponible');
    const incident = await page.evaluate(() => itsmBadge('incident', 'Zabbix|srv|down'));
    assert.match(incident, /GLPI #29 · En cours \(attribué\)/);
    assert.match(incident, /ticket GLPI encore ouvert/);
    assert.equal(await page.evaluate(() => itsmBadge('incident', 'inconnu')), '');
    await badge.click();
    await page.locator('#itsm-dialog[open]').waitFor();
    assert.deepEqual(errors, []);
    console.log('PASS: prévisualisation, confirmation, association GLPI, badges de statut, HTML échappé et mobile');
  } finally { await browser.close(); }
})().catch(e => {console.error(e); process.exitCode = 1;});
