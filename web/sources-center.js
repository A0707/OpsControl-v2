// Centre « Sources » — vue d'ensemble (lot 3) : chaque source de preuves sur une ligne,
// avec trois notions qui ne se confondent jamais :
//   disponibilité réseau (sondes ping/ports), audit SSH (contrôles sur chaque serveur),
//   état fonctionnel lu par API (Proxmox, Zabbix, Wazuh, Elasticsearch, Bacula).
// Une source jamais interrogée est « inconnue », jamais « disponible » ; une lecture
// réussie mais ancienne est « ancienne », jamais « récente ». Données : /api/self-monitoring
// (dernières collectes enregistrées, aucune requête distante déclenchée par cette page).
subtitles.Sources = 'Toutes les sources de preuves : sondes réseau, audits SSH et API — disponibilité, fraîcheur et dernière erreur.';

let scData = null, scLoadedAt = 0, scError = '', scTimer = null;
const SC_REFRESH_MS = 30000;
const SC_PAGES = { Proxmox: 'Proxmox', Zabbix: 'Zabbix', Wazuh: 'Wazuh', Elasticsearch: 'Elasticsearch', Bacula: 'Sauvegardes' };

function scRatioTone(n, total) {
  if (!total) return 'unknown';
  return n === total ? 'ok' : n / total >= 0.5 ? 'warning' : 'critical';
}

function scDuration(ms) {
  if (ms == null) return 'Non mesurée';
  return ms < 1000 ? ms + ' ms' : (ms / 1000).toLocaleString('fr-FR', { maximumFractionDigits: 1 }) + ' s';
}

function scLocalCard(title, kind, n, total, detail, go, budget) {
  return '<article class="sc-card ' + scRatioTone(n, total) + '"><header><span class="eyebrow">' + esc(kind) + '</span><h3>' + esc(title) + '</h3></header>' +
    '<p class="sc-figure"><b>' + esc(n) + '</b> / ' + esc(total) + ' <small>serveurs avec preuve récente</small></p>' +
    '<p class="note">' + esc(detail) + ' Récent : moins de ' + esc(Math.round(budget / 60)) + ' min.</p>' +
    '<footer><button data-go="' + escAttr(go) + '">Ouvrir ' + esc(go) + '</button></footer></article>';
}

function scApiCard(s, collector, budget) {
  const reach = s.reachable === true ? ['Lecture réussie', 'ok'] : s.reachable === false ? ['Dernière lecture en échec', 'critical'] : ['Jamais interrogée', 'unknown'];
  const fresh = s.fresh ? ['Récente', 'ok'] : [s.last_success ? 'Ancienne' : 'Aucune donnée', 'stale'];
  const tone = s.reachable === false ? 'critical' : !s.fresh ? 'unknown' : 'ok';
  const go = SC_PAGES[s.provider];
  return '<article class="sc-card ' + tone + '" data-source-key="' + escAttr(s.key) + '"><header><span class="eyebrow">API · ' + esc(s.provider) + '</span><h3>' + esc(s.name) + '</h3></header>' +
    '<div class="sc-pills">' + ui.pill(reach[0], reach[1]) + ui.pill(fresh[0], fresh[1]) + '</div>' +
    '<dl class="sc-facts">' +
    '<dt>Dernière réussite</dt><dd>' + (s.last_success ? ui.fresh(s.last_success, 'Lecture', budget) : '<span class="note">Jamais</span>') + '</dd>' +
    '<dt>Dernière tentative</dt><dd>' + (s.last_attempt ? esc(stamp(s.last_attempt)) : '<span class="note">Aucune</span>') + '</dd>' +
    '<dt>Durée de collecte</dt><dd>' + esc(scDuration(collector?.last_duration_ms)) + (collector?.failure ? ' <small>' + esc(collector.failure) + ' échec(s) depuis le démarrage</small>' : '') + '</dd>' +
    '<dt>Identifiants</dt><dd>' + (s.credentials_loaded === false ? ui.pill('Absents dans cette instance', 'critical') : s.credentials_loaded ? 'Chargés' : '<span class="note">Non déterminé</span>') + '</dd>' +
    '</dl>' + (s.error ? '<p class="sc-error">' + esc(s.error) + '</p>' : '') +
    '<footer>' + (go ? '<button data-go="' + escAttr(go) + '">Ouvrir ' + esc(go) + '</button>' : '') + '<button data-go="Connexions API">Connexion</button></footer></article>';
}

function scMarkup() {
  if (!scData) return scError ? ui.empty('Sources illisibles', scError) : '<div class="panel">Lecture de l’état des sources…</div>';
  const d = scData, f = d.freshness, budget = f.budget_seconds;
  const collectors = new Map((d.collectors || []).filter(c => c.kind === 'api').map(c => [c.key, c]));
  const reachable = d.sources.filter(s => s.reachable === true).length;
  const failing = d.sources.filter(s => s.reachable === false).length;
  const never = d.sources.filter(s => s.reachable === null).length;
  return ui.head('Sources de preuves', ui.fresh(d.generated_at, 'État lu', 60) + (scError ? ' <span class="form-error">' + esc(scError) + '</span>' : ''),
    '<button data-sc-reload>Actualiser l’affichage</button>', 'RÉSEAU · SSH · API') +
    '<div class="v2-kpis sc-kpis">' +
    ui.kpi('Sondes réseau récentes', f.network_fresh + ' / ' + f.hosts, 'Disponibilité réseau', scRatioTone(f.network_fresh, f.hosts), 'data-go="Réseau"') +
    ui.kpi('Audits SSH récents', f.ssh_fresh + ' / ' + f.hosts, f.ssh_measured + ' serveur(s) avec mesures', scRatioTone(f.ssh_fresh, f.hosts), 'data-go="Audit"') +
    ui.kpi('Sources API lues', reachable + ' / ' + d.sources.length, failing + ' en échec · ' + never + ' jamais interrogée(s)', d.sources.length ? (failing ? 'critical' : never ? 'unknown' : 'ok') : 'unknown') +
    ui.kpi('Sources API récentes', f.api_fresh + ' / ' + f.api_total, 'Lecture réussie de moins de ' + Math.round(budget / 60) + ' min', scRatioTone(f.api_fresh, f.api_total)) +
    '</div>' +
    '<section class="panel"><div class="panel-head"><h2>Collectes locales</h2></div><div class="sc-grid">' +
    scLocalCard('Sondes réseau', 'DISPONIBILITÉ RÉSEAU', f.network_fresh, f.hosts, 'Ping et ports depuis OpsControl : joignable ne veut pas dire sain.', 'Réseau', budget) +
    scLocalCard('Audit SSH', 'CONTRÔLES SUR LE SERVEUR', f.ssh_fresh, f.hosts, 'Commandes en lecture seule ; un audit ancien reste affiché comme ancien.', 'Audit', budget) +
    '</div></section>' +
    '<section class="panel"><div class="panel-head"><h2>Sources API <span class="state-count">' + d.sources.length + '</span></h2></div>' +
    (d.sources.length ? '<div class="sc-grid">' + d.sources.map(s => scApiCard(s, collectors.get(s.provider + ':' + s.key), budget)).join('') + '</div>'
      : ui.empty('Aucune source API configurée', 'Ajouter une connexion en lecture seule.', '<button data-go="Connexions API">Configurer</button>')) +
    '<p class="v2-formula">L’état fonctionnel d’une source décrit ce que son compte de lecture voit, dans son périmètre ; il ne remplace ni la sonde réseau ni l’audit de chaque serveur.</p></section>';
}

function scDraw() {
  const target = $('#sc-data');
  if (target) target.innerHTML = scMarkup();
}

async function scLoad() {
  try {
    const data = await api('/api/self-monitoring');
    if (!data || !data.freshness || !Array.isArray(data.sources)) throw Error('Réponse inattendue du service : état des sources non lisible.');
    scData = data; scError = '';
  } catch (e) { scError = e.message; }
  scLoadedAt = Date.now();
  if (page === 'Sources' && !selected) scDraw();
}

function scSchedule() {
  clearTimeout(scTimer);
  scTimer = setTimeout(() => {
    if (page !== 'Sources' || selected) { scTimer = null; return; }
    if (!document.hidden) scLoad();
    scSchedule();
  }, SC_REFRESH_MS);
}

pageRenderers.Sources = function () {
  $('#content').innerHTML = '<div id="sc-data"></div>';
  scDraw();
  if (Date.now() - scLoadedAt > SC_REFRESH_MS / 3) scLoad();
  scSchedule();
};

$('#content').addEventListener('click', e => {
  if (e.target.closest('[data-sc-reload]')) scLoad();
});
