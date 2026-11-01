// Page « Santé d’OpsControl » : l'outil se surveille lui-même (/api/self-monitoring).
// Quatre niveaux distincts, jamais fusionnés en un seul voyant :
//   1. OpsControl disponible (processus, base, planificateur) ;
//   2. collecteurs fonctionnels (dernière exécution, durée, échecs) ;
//   3. sources distantes disponibles (dernière lecture API réussie) ;
//   4. données fraîches (preuves récentes SSH, réseau, API).
// Un collecteur sans erreur ne rend pas une source disponible, et une source
// joignable ne rend pas ses données fraîches. Une absence n'est jamais « OK ».
subtitles['Santé d’OpsControl'] = 'L’outil lui-même : disponibilité, collecteurs, sources distantes et fraîcheur des preuves.';

let smData = null, smLoadedAt = 0, smError = '', smTimer = null;
const SM_REFRESH_MS = 15000;
const smStates = { ok: ['Fonctionnel', 'ok'], failing: ['En échec', 'critical'], running: ['En cours', 'info'], never: ['Jamais exécuté', 'unknown'] };

function smDuration(ms) {
  if (ms == null) return 'Durée inconnue';
  return ms < 1000 ? ms + ' ms' : (ms / 1000).toLocaleString('fr-FR', { maximumFractionDigits: 1 }) + ' s';
}

function smUptime(s) {
  if (s == null) return 'Inconnue';
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return (d ? d + ' j ' : '') + (d || h ? h + ' h ' : '') + m + ' min';
}

function smLevel(title, status, label, detail) {
  return '<div class="sm-level ' + ui.tone(status) + '"><span class="eyebrow">' + esc(title) + '</span>' +
    ui.pill(label, status) + '<small>' + esc(detail) + '</small></div>';
}

function smLevels(d) {
  const o = d.opscontrol, sched = o.scheduler || {};
  const failing = d.collectors.filter(c => c.state === 'failing').length;
  const ran = d.collectors.filter(c => c.state !== 'never').length;
  const srcKnown = d.sources.filter(s => s.reachable !== null);
  const srcDown = d.sources.filter(s => s.reachable === false).length;
  const f = d.freshness;
  const freshParts = f.hosts ? [f.ssh_fresh / f.hosts, f.network_fresh / f.hosts] : [];
  if (f.api_total) freshParts.push(f.api_fresh / f.api_total);
  const freshMin = freshParts.length ? Math.min(...freshParts) : null;
  const sshLow = f.hosts > 0 && f.ssh_fresh / f.hosts < 0.5;
  return '<div class="sm-levels">' +
    smLevel('1 · OpsControl', d.ready ? 'ok' : 'critical', d.ready ? 'Disponible' : 'Dégradé',
      d.ready ? 'Base lisible' + (sched.last ? ', planificateur actif' : '') + ' · démarré depuis ' + smUptime(o.uptime_seconds)
        : d.not_ready_reasons.join(' · ')) +
    // Un collecteur qui tourne ne prouve pas la couverture (audit UI du 31/10, fiche 17.1) :
    // sous la moitié de serveurs à audit SSH récent, l'état devient « couverture dégradée ».
    smLevel('2 · Collecteurs', !ran ? 'unknown' : failing || sshLow ? 'warning' : 'ok',
      !ran ? 'Aucune exécution' : failing ? failing + ' en échec' : sshLow ? 'Disponibles · couverture SSH dégradée' : 'Fonctionnels',
      ran + ' collecteur(s) exécuté(s) depuis le démarrage' +
        (ran && sshLow ? ' · audits SSH récents : ' + f.ssh_fresh + ' / ' + f.hosts + ' (objectif ≥ 50 %)' : '')) +
    smLevel('3 · Sources distantes', !srcKnown.length ? 'unknown' : srcDown ? 'warning' : 'ok',
      !srcKnown.length ? 'Jamais interrogées' : srcDown ? srcDown + ' indisponible(s)' : 'Disponibles',
      d.sources.length + ' source(s) déclarée(s) · ' + (d.sources.length - srcKnown.length) + ' sans résultat') +
    smLevel('4 · Fraîcheur', freshMin == null ? 'unknown' : freshMin >= 0.9 ? 'ok' : freshMin >= 0.5 ? 'warning' : 'critical',
      freshMin == null ? 'Non mesurée' : Math.round(freshMin * 100) + ' % au plus bas',
      'Preuve récente : moins de ' + Math.round(f.budget_seconds / 60) + ' min') +
    '</div>';
}

function smProcess(d) {
  const o = d.opscontrol, sched = o.scheduler || {}, db = o.database || {}, size = o.database_size || {};
  const tunnel = o.tunnel || {};
  const rows = [
    ['Base locale', db.status === 'ok' ? ui.pill('Lisible', 'ok') + ' <small>journal ' + esc(db.journal_mode) + '</small>' : ui.pill('Illisible', 'critical')],
    ['Taille de la base', esc(ui.bytes(size.bytes)) + (size.files?.['-wal'] ? ' <small>dont WAL ' + esc(ui.bytes(size.files['-wal'])) + '</small>' : '')],
    ['Planificateur', sched.last ? (sched.healthy ? ui.pill('Actif', 'ok') : ui.pill('En retard', 'critical')) + ' ' + ui.fresh(sched.last, 'Dernier battement', 15) +
      (sched.lag_seconds != null ? ' <small>retard ' + esc(sched.lag_seconds) + ' s</small>' : '') : ui.pill(sched.note || 'Aucun battement', 'unknown')],
    ['Instance unique', o.single_instance ? ui.pill('Verrou détenu', 'ok') : ui.pill('Non verrouillée', 'unknown', 'Instance sans cycle de vie ou verrou désactivé')],
    ['Temps réel', esc(o.sse.clients) + ' connexion(s) ouverte(s) <small>' + esc(o.sse.total_since_start) + ' depuis le démarrage</small>'],
    ['Tunnel Bacula', tunnel.required ? (tunnel.open ? ui.pill('Ouvert', 'ok') : ui.pill('Fermé', 'critical')) : '<span class="note">' + (tunnel.required === false ? 'Non utilisé' : 'État inconnu') + '</span>'],
  ];
  return '<section class="panel" data-sm="process"><div class="panel-head"><h2>Processus OpsControl</h2></div><dl class="sm-facts">' +
    rows.map(([k, v]) => '<dt>' + esc(k) + '</dt><dd>' + v + '</dd>').join('') + '</dl></section>';
}

function smCollectors(d) {
  const jobs = d.jobs || {};
  const jobLine = (name, label) => {
    const j = jobs[name];
    if (!j) return '';
    return '<li><b>' + esc(label) + '</b> ' + (j.running ? ui.pill('En cours ' + (j.completed ?? 0) + '/' + (j.total ?? '?'), 'running') : ui.pill('Au repos', 'inactive')) +
      (j.error ? ' <small class="text-critical">' + esc(j.error) + '</small>' : '') + '</li>';
  };
  const list = d.collectors;
  return '<section class="panel" data-sm="collectors"><div class="panel-head"><h2>Collecteurs <span class="state-count">' + list.length + '</span></h2></div>' +
    '<ul class="sm-jobs">' + jobLine('ssh', 'Audits SSH') + jobLine('network', 'Sondes réseau') + jobLine('batch', 'Inventaire Batch') + '</ul>' +
    (list.length ? '<div class="table"><table><thead><tr><th>Collecteur</th><th>État</th><th>Dernière exécution</th><th>Durée</th><th>Succès / échecs</th><th>Dernière erreur</th></tr></thead><tbody>' +
      list.map(c => {
        const [label, tone] = smStates[c.state] || smStates.never;
        return '<tr><td>' + esc(c.label) + (c.key ? '<small>' + esc(c.key) + '</small>' : '') + '</td><td>' + ui.pill(label, tone) +
          (c.consecutive_failures > 1 ? '<small>' + esc(c.consecutive_failures) + ' échecs consécutifs</small>' : '') + '</td>' +
          '<td>' + (c.last_finished ? ui.fresh(c.last_finished, 'Fin', 3600) : '<span class="note">Jamais terminé</span>') +
          (c.last_success && c.last_success !== c.last_finished ? '<small>Dernier succès : ' + esc(stamp(c.last_success)) + '</small>' : '') + '</td>' +
          '<td>' + esc(smDuration(c.last_duration_ms)) + (c.last_items != null ? '<small>' + esc(c.last_items) + ' élément(s)</small>' : '') + '</td>' +
          '<td>' + (c.runs != null ? esc(c.success) + ' / ' + esc(c.failure) : '<span class="note">Non compté</span>') + '</td>' +
          '<td>' + (c.last_error ? '<small>' + esc(c.last_error) + '</small>' : '<span class="note">Aucune</span>') + '</td></tr>';
      }).join('') + '</tbody></table></div>'
      : ui.empty('Aucun collecteur exécuté depuis le démarrage', 'Les mesures sont internes au processus et repartent de zéro à chaque redémarrage.')) +
    '</section>';
}

function smSources(d) {
  return '<section class="panel" data-sm="sources"><div class="panel-head"><h2>Sources distantes <span class="state-count">' + d.sources.length + '</span></h2></div>' +
    (d.sources.length ? '<div class="table"><table><thead><tr><th>Source</th><th>Disponibilité</th><th>Fraîcheur</th><th>Dernière réussite</th><th>Erreur</th></tr></thead><tbody>' +
      d.sources.map(s => '<tr><td>' + esc(s.name) + '<small>' + esc(s.provider) + (s.credentials_loaded === false ? ' · identifiants absents' : '') + '</small></td>' +
        '<td>' + (s.reachable === true ? ui.pill('Disponible', 'ok') : s.reachable === false ? ui.pill('Indisponible', 'critical') : ui.pill('Jamais interrogée', 'unknown')) + '</td>' +
        '<td>' + (s.fresh ? ui.pill('Récente', 'ok') : ui.pill(s.last_success ? 'Ancienne' : 'Aucune donnée', 'stale')) + '</td>' +
        '<td>' + (s.last_success ? ui.fresh(s.last_success, 'Réussite', d.freshness.budget_seconds) : '<span class="note">Jamais</span>') + '</td>' +
        '<td>' + (s.error ? '<small>' + esc(s.error) + '</small>' : '<span class="note">—</span>') + '</td></tr>').join('') +
      '</tbody></table></div>' : ui.empty('Aucune source API déclarée')) + '</section>';
}

function smFreshness(d) {
  const f = d.freshness, n = f.hosts;
  const ratio = (v, total) => total ? Math.round(v / total * 100) : null;
  return '<section class="panel" data-sm="freshness"><div class="panel-head"><h2>Fraîcheur des preuves</h2></div><div class="sm-gauges">' +
    ui.gauge('Audits SSH récents', ratio(f.ssh_fresh, n), { detail: f.ssh_fresh + ' / ' + n + ' serveurs', thresholds: [101, 101], source: 'SSH' }) +
    ui.gauge('Sondes réseau récentes', ratio(f.network_fresh, n), { detail: f.network_fresh + ' / ' + n + ' serveurs', thresholds: [101, 101], source: 'Réseau' }) +
    ui.gauge('Sources API récentes', ratio(f.api_fresh, f.api_total), { detail: f.api_fresh + ' / ' + f.api_total + ' sources', thresholds: [101, 101], source: 'API' }) +
    '</div><p class="note">Une jauge pleine signifie « preuves récentes », pas « serveurs sains ». Seuil : ' + esc(Math.round(f.budget_seconds / 60)) + ' min.</p></section>';
}

function smErrors(d) {
  return '<section class="panel" data-sm="errors"><div class="panel-head"><h2>Erreurs récentes <span class="state-count">' + d.errors.length + '</span></h2></div>' +
    (d.errors.length ? '<ul class="sm-errors">' + d.errors.slice(0, 20).map(e => '<li><time>' + esc(stamp(e.at)) + '</time> <b>' + esc(e.source) + '</b> ' + esc(e.message) + '</li>').join('') + '</ul>'
      : '<p class="note">Aucune erreur enregistrée depuis le démarrage.</p>') + '</section>';
}

// Web Vitals de cette session (audit UI du 31/10, page 4) : état initial mesuré dans le
// navigateur avant toute optimisation. Rien n'est envoyé au serveur. Les entrées antérieures au
// chargement de cette page sont relues grâce à `buffered` ; l'INP est approché par
// l'interaction la plus lente observée (la définition officielle retient un 98e centile).
const smVitals = {lcp: null, cls: 0, inp: null, interactions: 0};
(function smObserveVitals() {
  const watch = (type, handle, extra = {}) => {
    try { new PerformanceObserver(list => list.getEntries().forEach(handle)).observe({type, buffered: true, ...extra}); }
    catch { /* type non pris en charge par ce navigateur : la mesure reste « non mesurée » */ }
  };
  watch('largest-contentful-paint', e => { smVitals.lcp = e.startTime; });
  watch('layout-shift', e => { if (!e.hadRecentInput) smVitals.cls += e.value; });
  watch('event', e => { if (e.interactionId) { smVitals.interactions++; smVitals.inp = Math.max(smVitals.inp || 0, e.duration); } }, {durationThreshold: 16});
})();
function smNumber(x, digits) { return x.toLocaleString('fr-FR', {minimumFractionDigits: digits, maximumFractionDigits: digits}); }
function smVitalsPanel() {
  const v = smVitals, rows = [
    ['LCP (affichage du contenu principal)', v.lcp == null ? null : v.lcp / 1000, 2.5, 4, x => smNumber(x, 2) + ' s'],
    ['INP approché (interaction la plus lente)', v.inp, 200, 500, x => Math.round(x) + ' ms'],
    ['CLS (décalages de mise en page)', v.cls, 0.1, 0.25, x => smNumber(x, 3)]];
  return '<section class="panel"><h3>Rendu dans ce navigateur</h3><div class="table"><table><thead><tr><th>Indicateur</th><th>Mesure</th><th>Objectif</th></tr></thead><tbody>' +
    rows.map(([label, value, good, poor, fmt]) => '<tr><td>' + esc(label) + '</td><td>' + (value == null ? '<span class="mini">Non mesuré</span>' :
      ui.pill(fmt(value), value <= good ? 'ok' : value <= poor ? 'warning' : 'critical')) + '</td><td>≤ ' + esc(fmt(good)) + '</td></tr>').join('') +
    '</tbody></table></div><p class="note">Session en cours seulement (' + v.interactions + ' interaction(s) observée(s)) : un point de départ à comparer avant et après une optimisation, pas un 75e centile des visites réelles. Aucune donnée n’est transmise.</p></section>';
}

function smMarkup() {
  if (smError && !smData) return ui.empty('Santé d’OpsControl indisponible', smError);
  if (!smData) return '<div class="panel">Lecture de l’état d’OpsControl…</div>';
  const d = smData;
  return ui.head('État interne en direct', ui.fresh(d.generated_at, 'Instantané', 60) + (smError ? ' <span class="text-critical">' + esc(smError) + '</span>' : ''),
    '<button data-sm-reload>Actualiser</button>', 'Supervision de l’outil') +
    smLevels(d) + '<div class="sm-grid">' + smProcess(d) + smFreshness(d) + '</div>' + smCollectors(d) + smSources(d) + smErrors(d) + smVitalsPanel() +
    '<p class="note">' + esc(d.scope) + '</p>';
}

function smDraw() {
  const target = $('#sm-data');
  if (target) target.innerHTML = smMarkup();
}

async function smLoad() {
  try {
    const data = await api('/api/self-monitoring');
    if (!data || !data.opscontrol || !data.freshness || !Array.isArray(data.sources) || !Array.isArray(data.collectors))
      throw Error('Réponse inattendue du service : état d’OpsControl non lisible.');
    smData = data;
    smError = '';
  } catch (e) {
    smError = e.message;
  }
  smLoadedAt = Date.now();
  if (page === 'Santé d’OpsControl' && !selected) smDraw();
}

function smSchedule() {
  clearTimeout(smTimer);
  smTimer = setTimeout(() => {
    // Rafraîchissement seulement tant que la page est affichée et l'onglet visible.
    if (page !== 'Santé d’OpsControl' || selected) { smTimer = null; return; }
    if (!document.hidden) smLoad();
    smSchedule();
  }, SM_REFRESH_MS);
}

pageRenderers['Santé d’OpsControl'] = function () {
  $('#content').innerHTML = '<div id="sm-data"></div>';
  smDraw();
  if (Date.now() - smLoadedAt > SM_REFRESH_MS / 3) smLoad();
  smSchedule();
};

$('#content').addEventListener('click', e => {
  if (e.target.closest('[data-sm-reload]')) smLoad();
});
