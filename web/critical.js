// Serveurs critiques (voie rapide) et fraîcheur des données, sur TOUTES les pages.
//
// - Bandeau de fraîcheur : état du flux temps réel, âge de la dernière sonde et
//   de chaque source. Si le temps réel se coupe, tout l'écran le dit.
// - Le suivi critique alimente les mesures et notifications. Ses anciennes
//   tuiles/pastilles ne sont plus affichées dans les pages.
// - Pastilles d'âge : chaque valeur affiche depuis quand elle est mesurée,
//   recalculée chaque seconde dans le navigateur. Seuils RELATIFS à l'intervalle
//   attendu de sa voie : < 2× normal, < 5× en retard, au-delà périmé.
//
// L'état arrive poussé par SSE (event: tier0, voir realtime.js). Le sondage de
// /api/tier0 n'est qu'un filet : il ne s'active que si le flux se tait.

let t0Data = null, t0LastPush = 0;
const t0Previous = {};
const T0_LABELS = { up: 'Opérationnel', degraded: 'Dégradé', down: 'HORS SERVICE', unknown: 'Non mesuré' };
// Intervalles attendus (s), pour juger l'âge de chaque donnée.
// Zabbix : cycle de 10 s plus la durée de la collecte elle-même (quelques secondes).
const T0_INTERVALS = { probe: 5, zabbix: 15, push: 60, source: 60, batch: 3600, audit: 900 };

function t0Ago(seconds) {
  if (seconds < 60) return Math.max(0, Math.round(seconds)) + ' s';
  if (seconds < 3600) return Math.floor(seconds / 60) + ' min ' + String(Math.round(seconds % 60)).padStart(2, '0') + ' s';
  if (seconds < 86400) return Math.floor(seconds / 3600) + ' h ' + String(Math.floor(seconds % 3600 / 60)).padStart(2, '0');
  const jours = Math.floor(seconds / 86400);
  if (jours < 365) return jours + ' j';
  // Un trigger ouvert depuis des années (constaté : 2 047 j) se lit mieux ainsi.
  const ans = Math.floor(jours / 365), mois = Math.floor((jours % 365) / 30.4);
  return ans + ' an' + (ans > 1 ? 's' : '') + (mois ? ' ' + mois + ' mois' : '');
}

function t0Age(iso, interval, label) {
  return '<span class="age" data-age="' + escAttr(iso || '') + '" data-interval="' + interval + '"' +
    (label ? ' data-label="' + escAttr(label) + '"' : '') + '>—</span>';
}

// Une seule minuterie pour toutes les pastilles de la page.
function t0Tick() {
  const now = Date.now();
  document.querySelectorAll('[data-age]').forEach(el => {
    const t = Date.parse(el.dataset.age), interval = Number(el.dataset.interval) || 60;
    const prefix = el.dataset.label ? el.dataset.label + ' ' : '';
    if (!Number.isFinite(t)) {
      el.textContent = prefix + 'jamais mesuré';
      el.className = 'age age-stale';
      return;
    }
    const s = (now - t) / 1000;
    const etat = s < 2 * interval ? 'ok' : s < 5 * interval ? 'late' : 'stale';
    el.textContent = prefix + (etat === 'stale' ? 'périmé · ' : '') + 'il y a ' + t0Ago(s);
    el.className = 'age age-' + etat;
    el.title = 'Mesuré le ' + new Date(t).toLocaleString('fr-FR') + ' · intervalle attendu ' + interval + ' s';
  });
  document.querySelectorAll('[data-since]').forEach(el => {
    const t = Date.parse(el.dataset.since);
    el.textContent = Number.isFinite(t) ? t0Ago((now - t) / 1000) : 'durée inconnue';
  });
  const bar = $('#t0-live');
  if (bar) {
    const vivant = typeof realtimeLive === 'function' && realtimeLive();
    bar.className = 'fresh-live ' + (vivant ? 'on' : 'off');
    bar.textContent = vivant ? 'Temps réel connecté' : 'Temps réel interrompu — données de secours';
  }
  // Flux temps réel coupé et secours en échec : aucune nouvelle peinture n'arrive, la tuile
  // doit quand même quitter « Opérationnel » quand sa sonde vieillit.
  document.querySelectorAll('[data-probe-at]').forEach(el => {
    if (el.classList.contains('status-down') || el.classList.contains('status-unknown')) return;
    if (!t0ProbeStale(el.dataset.probeAt)) return;
    el.className = el.className.replace(/\bstatus-\w+/, 'status-unknown');
    const label = el.querySelector('.t0-state, .t0-label');
    if (label) label.textContent = 'Mesure périmée';
  });
  // Même tic que le bandeau : la barre d'état suit le même état (sans réécriture si inchangée).
  if (typeof v2UpdateStatus === 'function') v2UpdateStatus();
}

function t0Probe(p) {
  if (!p) return '<span class="note">Première sonde en attente…</span>';
  const mark = ok => ok === true ? '<b class="t0-ok">✓</b>' : ok === false ? '<b class="t0-ko">✗</b>' : '<b>?</b>';
  // TCP n'est re-sondé que toutes les 5 min tant que l'ICMP répond : sa latence
  // porte donc SA date, sinon une valeur de pic passerait pour la valeur actuelle.
  return '<span>ICMP ' + mark(p.ping) + '</span><span>TCP ' + esc(p.port) + ' ' + mark(p.tcp) +
    (p.tcp_ms != null ? ' ' + esc(p.tcp_ms) + ' ms' : '') + ' ' + t0Age(p.tcp_checked_at, 300) + '</span>' +
    t0Age(p.checked_at, T0_INTERVALS.probe, 'sonde');
}

// [valeur, horloge Zabbix en secondes] -> ISO, pour les pastilles d'âge.
function t0Clock(v) { return v && v[1] ? new Date(v[1] * 1000).toISOString() : ''; }
// Mêmes seuils que la politique de gravité (alert_policy.py).
function t0Level(kind, v) {
  if (v == null) return '';
  const grille = { disk: [95, 90, 80], ram: [97, 92, 85], cpu: [101, 90, 101] }[kind];
  return v >= grille[0] ? 't0-crit' : v >= grille[1] ? 't0-warn' : v >= grille[2] ? 't0-prev' : '';
}

function t0Live(h) {
  const l = h.live, m = t0Data.live_meta || {};
  if (!l) {
    return '<div class="t0-block"><h4>Zabbix en direct</h4><p class="note">' +
      esc(m.error || 'Première lecture en attente…') + '</p></div>';
  }
  const metrique = (titre, v, kind, suffixe) => v
    ? '<span class="t0-metric"><small>' + titre + '</small><b class="' + t0Level(kind, v[0]) + '">' + esc(v[0]) + (suffixe || '') +
      '</b>' + t0Age(t0Clock(v), l.delay_s || 60) + '</span>'
    : '<span class="t0-metric"><small>' + titre + '</small><b>—</b><span class="note">non relevé</span></span>';
  const d = l.disk_max;
  const agent = l.agent_ping;
  return '<div class="t0-block"><h4>Zabbix en direct ' + t0Age(l.measured_at ? new Date(l.measured_at * 1000).toISOString() : '', l.delay_s || 60, 'mesure') + '</h4>' +
    '<div class="t0-metrics">' + metrique('CPU', l.cpu_pct, 'cpu', ' %') + metrique('iowait', l.iowait_pct, 'cpu', ' %') +
    metrique('RAM', l.ram_pct, 'ram', ' %') +
    (d ? '<span class="t0-metric"><small>Disque ' + esc(d.mount) + '</small><b class="' + t0Level('disk', d.used_pct) + '">' + esc(d.used_pct) +
      ' %</b>' + t0Age(new Date(d.at * 1000).toISOString(), l.delay_s || 60) + '</span>' : metrique('Disque', null)) +
    '<span class="t0-metric"><small>Agent</small><b class="' + (agent && agent[0] === 1 ? 't0-ok' : 't0-ko') + '">' +
      (agent ? (agent[0] === 1 ? 'répond' : 'muet') : '—') + '</b>' + (agent ? t0Age(t0Clock(agent), l.delay_s || 60) : '') + '</span></div>' +
    (l.delay_s && l.delay_s > 15 ? '<p class="note">Zabbix mesure ces items toutes les ' + t0Ago(l.delay_s) +
      ' : une valeur peut avoir jusqu’à cet âge. Pour moins de 15 s, réduire leur intervalle dans Zabbix.</p>' : '') +
    ((l.errors || []).length ? '<p class="note">Non supporté : ' + esc(l.errors.join(' · ')) + '</p>' : '') + '</div>';
}

// Résultats réels (infraops-batch-report -> Zabbix) ; à défaut, la planification seule.
const T0_BATCH_LABELS = { failed: 'Échec', running: 'En cours', success: 'Réussi', unknown: 'Inconnu' };
const T0_BATCH_CLASSES = { failed: 'critical', running: 'observed', success: 'ok', unknown: 'unknown' };
const T0_BATCH_VISIBLE = 6;

function t0Batches(b, cle) {
  const r = b.results || [];
  const planif = '<p class="note">' + (b.declared || 0) + ' tâche(s) planifiée(s) visible(s) par l’audit ' +
    t0Age(b.collected_at, T0_INTERVALS.batch) + '</p>' +
    ((b.limitations || []).length ? '<p class="note">' + esc(b.limitations.join(' · ')) + '</p>' : '');
  if (!r.length) {
    return '<div class="t0-block"><h4>Traitements batch</h4>' +
      '<p class="note">Résultat des batchs non mesuré : seule la planification est connue. ' +
      'Envelopper les batchs avec infraops-batch-report (deploy/batch-setup.md).</p>' + planif + '</div>';
  }
  const ok = r.filter(x => x.state === 'success').length;
  const ligne = x => '<li><span class="badge ' + T0_BATCH_CLASSES[x.state] + '">' + T0_BATCH_LABELS[x.state] +
    (x.state === 'failed' && x.rc != null ? ' · code ' + esc(x.rc) : '') + '</span> ' + esc(x.name) +
    (x.state === 'running' && x.started_at ? ' <small>depuis <b data-since="' + new Date(x.started_at * 1000).toISOString() + '"></b></small>'
      : (x.finished_at ? ' ' + t0Age(new Date(x.finished_at * 1000).toISOString(), 93600, 'fin') : '')) +
    (x.duration_s != null && x.state !== 'running' ? ' <small>' + t0Ago(x.duration_s) + '</small>' : '') + '</li>';
  return '<div class="t0-block"><h4>Traitements batch · résultats Zabbix</h4>' +
    '<p><b class="' + (b.results_failed ? 't0-ko' : '') + '">' + b.results_failed + ' en échec</b> · ' +
    b.results_running + ' en cours · ' + ok + ' réussi(s) au dernier passage</p>' +
    '<ul class="t0-batches">' + r.slice(0, T0_BATCH_VISIBLE).map(ligne).join('') + '</ul>' +
    (r.length > T0_BATCH_VISIBLE ? '<details data-k="batch-' + esc(cle) + '"><summary>' + (r.length - T0_BATCH_VISIBLE) + ' autre(s) batch(s)</summary><ul class="t0-batches">' +
      r.slice(T0_BATCH_VISIBLE).map(ligne).join('') + '</ul></details>' : '') +
    '<p class="note">Un batch qui ne s’est pas lancé est signalé par Zabbix (« non exécuté ») dans les alertes.</p>' + planif + '</div>';
}

// Au-delà de 5 intervalles sans sonde, l'état affiché n'est plus une preuve : une tuile
// ne doit jamais rester « Opérationnel » sur une mesure périmée (audit SUP-06).
const T0_STALE_FACTOR = 5;
function t0ProbeStale(iso) {
  const t = Date.parse(iso || '');
  return !Number.isFinite(t) || (Date.now() - t) / 1000 > T0_STALE_FACTOR * T0_INTERVALS.probe;
}

function t0Tile(h, compact) {
  const p = h.probe || {}, perimee = p.status && p.status !== 'down' && t0ProbeStale(p.checked_at);
  const statut = perimee ? 'unknown' : p.status || 'unknown';
  // Mesure perturbée : on ne sait pas, et on le dit — ce n'est ni « OK » ni « tombé ».
  const libelle = perimee ? 'Mesure périmée'
    : p.perturbed && statut === 'unknown' ? 'Mesure perturbée' : T0_LABELS[statut];
  const zbx = h.zabbix || { problems: [] }, graves = zbx.problems.filter(x => x.severity === 'critical' || x.severity === 'warning');
  if (compact) {
    return '<button class="t0-pill status-' + statut + '" data-host="' + escAttr(h.key) + '" data-probe-at="' +
      escAttr(p.checked_at || '') + '"><span class="t0-dot"></span>' +
      esc(h.name) + ' · <span class="t0-label">' + libelle + '</span>' + (graves.length ? ' · ' + graves.length + ' alerte(s) Zabbix' : '') +
      ' ' + t0Age(p.checked_at, T0_INTERVALS.probe) + '</button>';
  }
  const b = h.batch || {}, a = h.audit || {};
  const pct = v => v == null ? '—' : Math.round(v) + ' %';
  return '<article class="t0-tile status-' + statut + '" data-probe-at="' + escAttr(p.checked_at || '') + '">' +
    '<div class="t0-head"><div><button class="link t0-name" data-host="' + escAttr(h.key) + '">' + esc(h.name) + '</button>' +
    '<small>' + esc(h.ip) + ' · ' + esc(h.role || '') + '</small></div><span class="t0-state">' + libelle + '</span></div>' +
    (statut === 'down' ? '<p class="t0-since">Hors service depuis <b data-since="' + escAttr(p.down_since || '') + '"></b></p>' : '') +
    '<div class="t0-line">' + t0Probe(h.probe) + '</div>' + t0Live(h) +
    '<div class="t0-block"><h4>Zabbix ' + t0Age(zbx.collected_at, T0_INTERVALS.zabbix) + '</h4>' +
    (h.push && h.push.length ? '<p class="t0-push">Poussé par Zabbix : ' + h.push.map(e => esc(e.trigger || 'événement')).join(' · ') + '</p>' : '') +
    (graves.length ? '<ul>' + graves.slice(0, 3).map(x => '<li><span class="badge ' + x.severity + '">' +
      (x.severity === 'critical' ? 'Critique' : 'Majeur') + '</span> ' + esc(x.description) + '</li>').join('') + '</ul>' +
      (graves.length > 3 ? '<p class="note">+ ' + (graves.length - 3) + ' autre(s)</p>' : '')
      : '<p class="note">Aucune anomalie majeure ou critique active.</p>') +
    (zbx.problems.length > graves.length ? '<p class="note">' + (zbx.problems.length - graves.length) +
      ' anomalie(s) préventive(s) ou d’information — voir Alertes.</p>' : '') + '</div>' +
    t0Batches(b, h.key) +
    '<div class="t0-block"><h4>Dernier audit SSH ' + t0Age(a.collected_at, T0_INTERVALS.audit) + '</h4>' +
    '<p>CPU ' + pct(a.cpu) + ' · RAM ' + pct(a.ram) + ' · Disque max ' + pct(a.disk_max) + '</p></div></article>';
}

// --- État du parc : une case par serveur, la couleur réservée à l'anormal ---------
// Gris = rien d'anormal dans une preuve récente. Hachuré = donnée ancienne : on ne
// sait pas. Rouge / orange / bleu = pire alerte RÉCENTE qui le vise. Les cases
// anormales viennent en premier : l'œil tombe dessus sans chercher.
const PARK_RANK = { critical: 0, warning: 1, preventive: 2, stale: 3, ok: 4 };
const PARK_LABELS = { critical: sevLabel('critical'), warning: sevLabel('warning'), preventive: sevLabel('preventive'),
  stale: 'Donnée ancienne', ok: 'Rien d’anormal' };

function t0ParkCells() {
  const hosts = (typeof state !== 'undefined' && state?.hosts) || [];
  const pire = {};
  const alertes = (typeof alertData !== 'undefined' && alertData?.alerts) || [];
  alertes.map(a => (typeof currentAlert === 'function' ? currentAlert(a) : a)).forEach(a => {
    // Une anomalie chronique (> 30 j) ne colore pas le parc : ce n'est pas l'état du moment.
    if (!a.fresh || a.chronic || !PARK_RANK.hasOwnProperty(a.severity)) return;
    (a.targets || []).forEach(t => {
      if (!t.host_key) return;
      const p = pire[t.host_key] || (pire[t.host_key] = { sev: 'ok', titres: [] });
      if (PARK_RANK[a.severity] < PARK_RANK[p.sev]) p.sev = a.severity;
      if (p.titres.length < 3) p.titres.push(a.title);
    });
  });
  return hosts.map(h => {
    const p = pire[h.key];
    const sev = p ? p.sev : (h.stale || h.status === 'unknown' ? 'stale' : 'ok');
    return { key: h.key, name: h.name || h.key, sev, titres: p ? p.titres : [] };
  }).sort((a, b) => PARK_RANK[a.sev] - PARK_RANK[b.sev] || a.name.localeCompare(b.name));
}

function t0Park() {
  const cells = t0ParkCells();
  if (!cells.length) return '';
  const compte = {};
  cells.forEach(c => { compte[c.sev] = (compte[c.sev] || 0) + 1; });
  return '<section class="park" aria-label="État du parc"><div class="park-head"><h2 class="t0-title">État du parc · ' + cells.length + ' serveurs</h2>' +
    '<div class="park-legend">' + Object.keys(PARK_RANK).map(s => '<span><i class="park-cell sev-' + s + '"></i>' + PARK_LABELS[s] +
      ' <b>' + (compte[s] || 0) + '</b></span>').join('') + '</div></div>' +
    '<div class="park-grid">' + cells.map(c => '<button class="park-cell sev-' + c.sev + '" data-host="' + escAttr(c.key) + '" title="' +
      escAttr(c.name + ' — ' + PARK_LABELS[c.sev] + (c.titres.length ? ' : ' + c.titres.join(' · ') : '')) + '" aria-label="' +
      escAttr(c.name + ', ' + PARK_LABELS[c.sev]) + '"></button>').join('') + '</div></section>';
}

// Majeur et préventif repliés : visibles, mais sans concurrencer les critiques.
function t0Folded() {
  if (typeof alertData === 'undefined' || !alertData?.alerts) return '';
  const actuelles = alertData.alerts.map(a => (typeof currentAlert === 'function' ? currentAlert(a) : a)).filter(a => a.fresh && !a.chronic);
  return ['warning', 'preventive'].map(sev => {
    const lot = actuelles.filter(a => a.severity === sev);
    if (!lot.length) return '';
    const niveau = (alertData.levels || []).find(l => l.key === sev) || { label: sev, delay: '' };
    return '<details class="panel folded" data-k="lvl-' + sev + '"><summary><span class="badge ' + sev + '">' + esc(niveau.label) +
      '</span> ' + lot.length + ' cause(s) · ' + lot.reduce((n, a) => n + a.count, 0) + ' cible(s) — ' + esc(niveau.delay) + '</summary>' +
      '<ul class="folded-list">' + lot.slice(0, 10).map(a => '<li><span class="state-count">' + a.count + '</span> ' + esc(a.title) +
        ' <small>' + esc(a.source) + '</small></li>').join('') + '</ul>' +
      '<button data-go="Alertes">Toutes les alertes ' + esc(niveau.label.toLowerCase()) + 's</button></details>';
  }).join('');
}

function t0Render() {
  let zone = $('#t0-zone');
  if (!zone) {
    zone = document.createElement('section');
    zone.id = 't0-zone';
    zone.setAttribute('aria-label', 'Fraîcheur et couverture du parc');
    $('#content').insertAdjacentElement('beforebegin', zone);
  }
  const accueil = page === 'Vue globale' && !selected;
  const visible = accueil && document.documentElement.dataset.display === 'noc';
  zone.hidden = !visible;
  if (!t0Data || !visible) { zone.replaceChildren(); return; }
  zone.classList.toggle('is-home', accueil);
  const sources = (t0Data.sources || []).map(s => '<span class="fresh-src' + (s.ok ? '' : ' ko') + '">' + esc(s.name) + ' ' +
    t0Age(s.collected_at, s.provider === 'Zabbix' ? T0_INTERVALS.zabbix : T0_INTERVALS.source) + '</span>').join('');
  // La zone est redessinée à chaque sonde (5 s) : on garde les blocs dépliés ouverts.
  const ouverts = new Set([...zone.querySelectorAll('details[data-k]')].filter(d => d.open).map(d => d.dataset.k));
  zone.innerHTML = '<div class="fresh-bar"><span id="t0-live" class="fresh-live">…</span>' +
    '<span class="fresh-src' + (t0Data.observer?.ok === false ? ' ko' : '') + '">Sonde critique ' + t0Age(t0Data.last_probe_at, T0_INTERVALS.probe) +
    (t0Data.observer?.ok === false ? ' · chemin de mesure perturbé' : '') + '</span>' +
    '<span class="fresh-src' + (t0Data.live_meta?.error ? ' ko' : '') + '" title="' + escAttr(t0Data.live_meta?.error || '') + '">Zabbix direct ' +
    t0Age(t0Data.live_meta?.fetched_at, t0Data.live_seconds || 10) + '</span>' + sources +
    '<span class="fresh-src' + (t0Data.webhook?.configured ? '' : ' ko') + '">Webhook Zabbix ' +
    (t0Data.webhook?.configured ? (t0Data.webhook.last_at ? t0Age(t0Data.webhook.last_at, T0_INTERVALS.push) : 'en attente du premier événement') : 'non configuré') + '</span></div>' +
    (accueil ? t0Park() + '<div class="folded-row">' + t0Folded() + '</div>' : '');
  zone.querySelectorAll('details[data-k]').forEach(d => { if (ouverts.has(d.dataset.k)) d.open = true; });
  t0Tick();
}

// Une transition réveille le centre : la décision du journal (prise en charge,
// maintenance et fraîcheur) s'applique aussi à la voie rapide.
function t0Notify() {
  let refresh = false;
  (t0Data?.hosts || []).forEach(h => {
    const statut = h.probe?.status;
    if (statut === 'down' && t0Previous[h.key] && t0Previous[h.key] !== 'down') refresh = true;
    if (statut) t0Previous[h.key] = statut;
  });
  if (refresh && typeof loadAlerts === 'function') loadAlerts();
}

// État poussé par SSE : on met à jour la sonde et les événements poussés, sans requête.
window.addEventListener('infraops:tier0', e => {
  t0LastPush = Date.now();
  if (!t0Data) { t0Load(); return; }
  const snap = e.detail || {};
  const sondes = Object.fromEntries((snap.hosts || []).map(s => [s.key, s]));
  t0Data.last_probe_at = snap.last_probe_at;
  t0Data.webhook = snap.webhook;
  t0Data.observer = snap.observer;
  t0Data.hosts.forEach(h => {
    if (sondes[h.key]) h.probe = sondes[h.key];
    if (snap.live && snap.live[h.key]) h.live = snap.live[h.key];
  });
  if (snap.live_meta) t0Data.live_meta = snap.live_meta;
  // Un nouvel événement poussé change la liste Zabbix : on relit la vue complète.
  if ((snap.webhook?.count || 0) !== (t0Data._webhookCount || 0)) { t0Data._webhookCount = snap.webhook?.count || 0; t0Load(); }
  t0Notify();
  t0Render();
});

async function t0Load() {
  try {
    const [data] = await Promise.all([api('/api/tier0'), typeof loadAlertMaintenance === 'function' ? loadAlertMaintenance() : Promise.resolve()]);
    data._webhookCount = data.webhook?.count || 0;
    t0Data = data;
    t0Notify();
    t0Render();
  } catch (e) { /* le bandeau signalera l'âge croissant des données */ }
}

renderHooks.push(t0Render);

t0Load();
poll('serveurs-critiques-horloge', 1000, t0Tick);
// Vue complète (Zabbix, batchs, audit) toutes les 15 s ; sonde par SSE. Si le
// flux se tait (onglet caché, proxy, coupure), on sonde toutes les 5 s.
poll('serveurs-critiques-vue', 15000, t0Load, { hidden: true, when: () => Date.now() - t0LastPush > 12000 || !document.hidden });
poll('serveurs-critiques-secours', 5000, t0Load, { hidden: true, when: () => Date.now() - t0LastPush > 12000 });
