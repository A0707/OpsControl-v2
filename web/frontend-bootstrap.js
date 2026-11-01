import { esc, escAttr, api, post, SEVERITY } from '/frontend-utils.js?v=1bbce635';
import { createUi } from '/v2-ui.js?v=9acffe14';

// Pont limité aux exports migrés : les autres registres restent classiques à cette étape.
Object.assign(globalThis, {
  esc, escAttr, api, post, SEVERITY,
  ui: createUi({ freshnessMarkup: (...args) => globalThis.freshnessMarkup(...args) })
});

// Tous les scripts sont insérés d'un coup avec async=false : le navigateur les télécharge
// en parallèle et les exécute dans l'ordre du manifeste. L'attente un par un faisait
// 23 allers-retours successifs au démarrage (audit FE-04).
async function start() {
  const manifest = document.getElementById('legacy-scripts');
  const sources = [...manifest.content.querySelectorAll('script[src]')].map(descriptor => {
    const source = new URL(descriptor.getAttribute('src'), document.baseURI);
    if (source.origin !== location.origin) throw new Error('Script hors origine refusé');
    return source;
  });
  const loads = sources.map(source => new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = source.href;
    script.async = false;
    script.onload = resolve;
    script.onerror = () => reject(new Error(source.pathname));
    document.head.append(script);
  }));
  const failed = (await Promise.allSettled(loads)).filter(r => r.status === 'rejected').map(r => r.reason.message);
  // Mode dégradé assumé : un module manquant ne doit pas priver l'opérateur des autres pages,
  // mais l'écart reste affiché en permanence (bandeau dédié, jamais effacé par un rafraîchissement).
  if (typeof globalThis.startApplication !== 'function') {
    throw new Error('scripts indispensables absents (' + failed.join(', ') + ')');
  }
  globalThis.startApplication();
  if (failed.length) degraded('Interface partielle : module(s) non chargé(s) ' + failed.join(', ') +
    '. Les pages concernées sont indisponibles ; recharger la page ou vérifier le déploiement.');
}

function degraded(message) {
  const banner = document.createElement('p');
  banner.className = 'form-error';
  banner.setAttribute('role', 'alert');
  banner.id = 'frontend-degraded';
  banner.textContent = message;
  document.body.prepend(banner);
}

try {
  await start();
} catch (error) {
  const target = document.getElementById('error');
  if (target) target.textContent = 'Démarrage de l’interface impossible : ' + error.message;
  console.error(error);
}
