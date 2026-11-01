const path = require('node:path');
const fs = require('node:fs');

// Une installation externe peut être partagée sans ajouter node_modules au dépôt.
const modulePath = path.resolve(process.env.OPS_PLAYWRIGHT_PATH ||
  path.join(__dirname, 'data/browser-test/node_modules/playwright'));
let playwright;
try {
  playwright = require(modulePath);
} catch (error) {
  throw new Error('Playwright introuvable. Installer avec npm install --prefix data/browser-test playwright, ' +
    'ou définir OPS_PLAYWRIGHT_PATH vers le module installé.', { cause: error });
}

// Sans channel, Playwright utilise son Chromium installé, sur Windows comme sur Linux.
const launchOptions = { headless: true };
if (process.env.OPS_BROWSER_CHANNEL) launchOptions.channel = process.env.OPS_BROWSER_CHANNEL;
// Les captures doivent aussi fonctionner si le module est installé hors du dépôt.
fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
module.exports = { ...playwright, launchOptions };
