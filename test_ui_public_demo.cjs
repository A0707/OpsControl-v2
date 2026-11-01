// La vitrine doit fonctionner sans backend ni accès réseau externe.
const {chromium, launchOptions} = require('./browser-test.cjs');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

(async () => {
  const browser = await chromium.launch(launchOptions);
  try {
    for (const viewport of [{width: 1440, height: 1000}, {width: 390, height: 844}]) {
      const page = await browser.newPage({viewport});
      const errors = [], external = [];
      page.on('pageerror', error => errors.push(error.message));
      await page.route('**/*', async route => {
        const url = new URL(route.request().url());
        if (url.origin !== 'http://demo.test') {
          external.push(url.origin);
          return route.abort();
        }
        const name = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
        const root = path.resolve(__dirname, 'public-demo');
        const file = path.resolve(root, name);
        if (!file.startsWith(root + path.sep) || !fs.existsSync(file)) {
          return route.fulfill({status: 404, body: ''});
        }
        const types = {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png'};
        return route.fulfill({body: fs.readFileSync(file), contentType: types[path.extname(file)]});
      });
      await page.goto('http://demo.test/');
      await page.getByRole('heading', {name: 'Vue globale', exact: true}).waitFor();
      assert.equal(await page.locator('.stat').first().locator('strong').textContent(), '12');
      for (const view of ['servers', 'security', 'backups', 'network', 'sources', 'overview']) {
        await page.locator(`nav [data-view="${view}"]`).click();
        assert.equal(await page.locator(`nav [data-view="${view}"]`).getAttribute('aria-current'), 'page');
      }
      await page.locator('nav [data-view="servers"]').click();
      await page.locator('#search').fill('db-01');
      assert.equal(await page.locator('#server-results tbody tr').count(), 1);
      await page.locator('[data-host="db-01"]').click();
      await page.locator('dialog[open]').waitFor();
      assert.match(await page.locator('#dialog-content').textContent(), /192\.0\.2\.21/);
      await page.locator('#close-dialog').click();
      await page.locator('#search').fill('');
      await page.locator('#status-filter').selectOption('critical');
      assert.equal(await page.locator('#server-results tbody tr').count(), 1);
      const theme = await page.locator('html').getAttribute('data-theme');
      await page.locator('#theme').click();
      assert.notEqual(await page.locator('html').getAttribute('data-theme'), theme);
      await page.locator('#refresh').click();
      assert.match(await page.locator('#snapshot').textContent(), /simul/i);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
      assert.deepEqual(external, []);
      assert.deepEqual(errors, []);
      if (viewport.width === 1440) {
        await page.locator('nav [data-view="overview"]').click();
        await page.screenshot({path: path.join(__dirname, 'data', 'public-demo-verified.png'), fullPage: true});
      }
      await page.close();
    }
  } finally {
    await browser.close();
  }
  console.log('Démo : navigation, filtres, fiche, thème, simulation et mobile OK ; aucun accès externe.');
})().catch(error => { console.error(error); process.exitCode = 1; });
