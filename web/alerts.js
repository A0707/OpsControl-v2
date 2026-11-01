// Centre d'alertes : toutes les sources, regroupées par cause (/api/alerts).
//
// Trois canaux d'alerte, du plus discret au plus intrusif :
//   1. le compteur dans la navigation et le titre de l'onglet ;
//   2. un bandeau sur TOUTES les pages quand une alerte critique récente est
//      nouvelle pour cet opérateur ;
//   3. une notification du navigateur, uniquement si l'opérateur l'a activée.
// « Marquer comme vues » ne masque rien : l'alerte reste dans la liste tant que
// la preuve existe. Cela arrête seulement le bandeau et les notifications.
navGroups[0][1].splice(1, 0, ['Alertes', 'alert']);
subtitles.Alertes = 'Anomalies de toutes les sources, graduées par une politique commune : critique, majeur, préventif.';

let alertData = null, alertSource = '', alertLevel = '', alertFresh = '', alertQuery = '';
// Période par défaut : 7 derniers jours (date de début de l'alerte) ; '' = toutes les dates.
let alertPeriod = '7';
let alertAge = '', alertState = '';
const ALERT_NEW_SECONDS = 86400, ALERT_EVENT_SECONDS = 900;
const ALERT_STATES = {open:'Ouvert',reopened:'Réapparu',acknowledged:'Pris en charge',investigating:'En investigation',suppressed:'Masqué',resolved:'Résolu',unknown:'État non rapproché'};
// Alertes affichées par lots de 20 (57 groupes faisaient 12 000 px) ; remis à 20 à chaque filtre.
const ALERT_PAGE = 20;
let alertShown = ALERT_PAGE;
const ALERT_SEEN_KEY = 'infraops.alertes.vues';
const ALERT_NOTIFIED_KEY = 'infraops.alertes.notifiees.v2';
const ALERT_NOTIFY_COOLDOWN = 5 * 60 * 1000;
const ALERT_NOTIFY_TTL = 12 * 60 * 60 * 1000;
let alertLoading = false, alertReloadPending = false, alertFeedError = '', homeCriticalSignature = '';
let stripSignature = '';
let alertMaintenance = [], alertMaintenanceAt = 0, alertNotifyTimer = null;

function currentAlert(a) {
  const age = ageSeconds(a.observed_at);
  return {...a, fresh: Boolean(a.fresh && !alertFeedError && age !== null && age >= 0 && age <= (a.max_age_seconds ?? 900))};
}

function alertSeen() {
  try { return new Set(JSON.parse(localStorage.getItem(ALERT_SEEN_KEY) || '[]')); } catch (e) { return new Set(); }
}
function alertRemember(ids) {
  try { localStorage.setItem(ALERT_SEEN_KEY, JSON.stringify([...new Set([...alertSeen(), ...ids])].slice(-500))); } catch (e) { /* stockage indisponible : le bandeau restera affiché */ }
}
function alertNotificationState() {
  try {
    const value = JSON.parse(localStorage.getItem(ALERT_NOTIFIED_KEY) || '{}');
    return {last: Number(value.last) || 0, sent: value.sent && typeof value.sent === 'object' ? value.sent : {}};
  } catch { return {last: 0, sent: {}}; }
}
function alertSaveNotificationState(value) {
  try { localStorage.setItem(ALERT_NOTIFIED_KEY, JSON.stringify(value)); } catch { /* déduplication mémoire navigateur indisponible */ }
}
function alertNotificationSignature(a) {
  return alertCandidateEvents(a).map(alertEventKey).sort().join('|');
}
function alertEventKey(e) { return e.id + '@' + e.at; }
function alertCandidateEvents(a) {
  const events = Array.isArray(a.notification_events) ? a.notification_events : (a.targets || []).map(t=>({
    id:a.id+'|'+(t.host_key||t.name),at:t.started_at,name:t.name,host_key:t.host_key,
    observed_at:t.observed_at||a.observed_at,max_age_seconds:a.max_age_seconds??900,fresh:t.fresh!==false}));
  return events.filter(e=>{const age=ageSeconds(e.at),proof=ageSeconds(e.observed_at);
    return e.fresh!==false&&age!==null&&age>=0&&age<=ALERT_EVENT_SECONDS&&proof!==null&&proof>=0&&proof<=(e.max_age_seconds??900);});
}
function alertAgeOf(a) {
  const at=a.latest_event_at||(!Object.hasOwn(a,'latest_event_at')&&alertStartMs(a)!==null?new Date(alertStartMs(a)).toISOString():null);
  const age=ageSeconds(at);
  return age===null||age<0?'unknown':age<=ALERT_NEW_SECONDS?'recent':'old';
}
function alertClassification(a) {
  const counts=a.recency_counts||{},age=alertAgeOf(a),states=a.state_counts||{[a.ack?'acknowledged':'unknown']:a.count};
  const ageLabel={recent:'Nouveau · moins de 24 h',old:'Ancien · plus de 24 h',unknown:'Ancienneté inconnue'}[age];
  return '<div class="alert-classification"><span class="badge '+(age==='recent'?'observed':'unknown')+'">'+ageLabel+'</span>'+
    ((states.reopened||0)?'<span class="badge warning">'+states.reopened+' réapparu(s)</span>':'')+
    Object.entries(states).map(([k,n])=>'<span class="alert-processing">'+esc(ALERT_STATES[k]||k)+' : '+n+'</span>').join('')+
    (counts.recent&&counts.old?'<small>Groupe mixte : '+counts.recent+' cible(s) récente(s), '+counts.old+' ancienne(s)</small>':'')+'</div>';
}
async function loadAlertMaintenance(force = false) {
  if (!force && Date.now() - alertMaintenanceAt < 60000) return alertMaintenance;
  try {
    const data = await api('/api/incidents/maintenance');
    if (Array.isArray(data?.items)) { alertMaintenance = data.items.filter(w => w.active); alertMaintenanceAt = Date.now(); }
  } catch { /* ancienne API ou indisponibilité : les alertes restent visibles et actives */ }
  return alertMaintenance;
}
function notificationMaintenance(source, targets) {
  const values = (Array.isArray(targets) ? targets : [targets]).filter(Boolean).map(v => String(v).toLowerCase());
  return alertMaintenance.find(window => {
    if (!window.active || (window.source && window.source !== source)) return false;
    const target = String(window.target || '').toLowerCase();
    return !target || values.includes(target);
  });
}
function notificationInMaintenance(source, targets) { return Boolean(notificationMaintenance(source, targets)); }
// Critiques récentes : les seules qui justifient d'interrompre un opérateur.
function alertUrgent() {
  // Une alerte chronique (ouverte depuis plus de 30 j) ou déjà prise en charge
  // par quelqu'un n'interrompt plus personne. Elle reste listée.
  return (alertData?.alerts || []).map(currentAlert).filter(a => a.severity === 'critical' && a.fresh && !a.chronic && !a.ack)
    .map(a=>({...a,notification_events:alertCandidateEvents(a)})).filter(a=>a.notification_events.length);
}
function alertInterrupting() {
  return alertUrgent().map(a=>({...a,notification_events:a.notification_events.filter(e=>!notificationInMaintenance(a.source,[e.name,e.host_key]))}))
    .filter(a=>a.notification_events.length);
}
function alertNew() {
  const seen = alertSeen();
  return alertInterrupting().map(a=>({...a,notification_events:a.notification_events.filter(e=>!seen.has(alertEventKey(e)))}))
    .filter(a=>a.notification_events.length);
}

function alertBadge(a) {
  // Gravité OpsControl (politique commune) ; une preuve ancienne reste « à confirmer ».
  return '<span class="badge ' + (a.fresh ? a.severity : 'unknown') + '">' + (a.fresh ? '' : 'À confirmer · ') +
    esc(a.severity_label || a.severity) + '</span>';
}

function alertTargets(a) {
  const items = a.targets.map(t => {
    const detail = t.detail && t.detail !== a.title ? ' <small>' + esc(t.detail) + '</small>' : '';
    // Cible unique observée en même temps que le groupe : une seule date, celle du groupe.
    const same = a.targets.length === 1 && a.source !== 'Zabbix' && (t.observed_at || a.observed_at) === a.observed_at;
    const times = same ? '' : '<small class="target-age">' + freshnessMarkup(t.observed_at || a.observed_at,
      a.source === 'Zabbix' ? 'Lecture Zabbix' : 'Observation', a.max_age_seconds ?? 900) +
      (a.source === 'Zabbix' ? ' · ' + freshnessMarkup(t.measurement_at, 'Item le plus ancien', 30) : '') + '</small>';
    const treatment=t.state?'<small class="target-state">'+esc(ALERT_STATES[t.state]||t.state)+' · '+esc({recent:'Nouveau · moins de 24 h',old:'Ancien · plus de 24 h',unknown:'Ancienneté inconnue'}[t.recency]||'Ancienneté inconnue')+(t.event_at?' · '+exactTimeMarkup(t.event_at):'')+'</small>':'';
    return (t.host_key
      ? '<li><button class="link" data-host="' + escAttr(t.host_key) + '">' + esc(t.name) + '</button>' + detail + '</li>'
      : '<li>' + esc(t.name) + detail + '</li>').replace('</li>', treatment + times + '</li>');
  }).join('');
  if (!a.targets.length) return '';
  const reste = a.truncated ? '<li class="note">… et ' + (a.count - a.targets.length) + ' autre(s)</li>' : '';
  const liste = '<ul class="alert-targets">' + items + reste + '</ul>';
  return a.count > 6 ? '<details><summary>' + a.count + ' cible(s) concernée(s)</summary>' + liste + '</details>' : liste;
}

// Début le plus ancien parmi les cibles, quand la source le donne (déclenchement
// du trigger Zabbix, mise hors service de la sonde). Sinon « début non mesuré » :
// la date d'observation n'est pas une date de début.
function alertStartMs(a) {
  if (Object.hasOwn(a, 'started_at')) {
    const start = a.started_at ? Date.parse(a.started_at) : NaN;
    return Number.isFinite(start) ? start : null;
  }
  const debuts = (a.targets || []).map(t => t.started_at).filter(Boolean)
    .map(v => /^\d+$/.test(String(v)) ? Number(v) * 1000 : Date.parse(v)).filter(Number.isFinite);
  return debuts.length ? Math.min(...debuts) : null;
}
function alertSince(a) {
  const debut = alertStartMs(a);
  if (debut === null) return '<span class="alert-since unknown">début non mesuré</span>';
  return '<span class="alert-since">depuis <b data-since="' + new Date(debut).toISOString() + '"></b></span>';
}
// Plus récentes d'abord. Sans date de début, rien ne prouve qu'une alerte est ancienne :
// elle reste visible quelle que soit la période, en fin de liste.
function alertRecentFirst(a, b) {
  const da = Object.hasOwn(a,'latest_event_at') ? (a.latest_event_at?Date.parse(a.latest_event_at):null) : alertStartMs(a);
  const db = Object.hasOwn(b,'latest_event_at') ? (b.latest_event_at?Date.parse(b.latest_event_at):null) : alertStartMs(b);
  if (da === null || db === null) return (da === null) - (db === null) || String(a.id).localeCompare(String(b.id));
  return db - da || String(a.id).localeCompare(String(b.id));
}
function alertInPeriod(a) {
  const debut = Object.hasOwn(a,'latest_event_at') ? (a.latest_event_at?Date.parse(a.latest_event_at):null) : alertStartMs(a);
  return !alertPeriod || debut === null || Date.now() - debut <= Number(alertPeriod) * 86400000;
}

function alertVersion(a, maintenance, extra = '') {
  const value = JSON.stringify([a, maintenance?.id || null, maintenance?.ends_at || null, extra]);
  let hash = 2166136261;
  for (let i = 0; i < value.length; i++) { hash ^= value.charCodeAt(i); hash = Math.imul(hash, 16777619); }
  return String(hash >>> 0);
}

// Alerte compacte (≈ 2 lignes au lieu de 5) : gravité, source, titre, début, prise en charge sur la
// première ligne ; délai, règle, gravité d'origine, cible et âge de la preuve sur la seconde (toujours
// visibles). Preuve textuelle et liste complète des cibles : repliées, à un clic, ouverture mémorisée.
const alertOpenDetails = new Set();
function alertTargetLine(a) {
  const targets = a.targets || [];
  const max = a.max_age_seconds ?? 900;
  if (targets.length === 1 && a.count <= 1) {
    const t = targets[0];
    const name = t.host_key ? '<button class="link" data-host="' + escAttr(t.host_key) + '">' + esc(t.name) + '</button>' : '<b>' + esc(t.name) + '</b>';
    const detail = t.detail && t.detail !== a.title ? ' <small>' + esc(t.detail) + '</small>' : '';
    const ages = a.source === 'Zabbix'
      ? freshnessMarkup(t.observed_at || a.observed_at, 'Lecture Zabbix', max) + ' · ' + freshnessMarkup(t.measurement_at, 'Item le plus ancien', 30)
      : freshnessMarkup(t.observed_at || a.observed_at, 'Dernière preuve', max);
    return '<span class="alert-target">' + name + detail + '</span> · ' + ages;
  }
  const names = targets.slice(0, 2).map(t => esc(t.name)).join(', ');
  return '<span class="alert-target">' + a.count + ' cible(s) : ' + names + (a.count > 2 ? '…' : '') + '</span> · ' +
    freshnessMarkup(a.observed_at, a.source === 'Zabbix' ? 'Dernière lecture API' : 'Dernière preuve du groupe', max);
}
function alertItem(a) {
  const maintenance = notificationMaintenance(a.source, (a.targets || []).flatMap(t => [t.name, t.host_key]));
  const multiple = (a.targets || []).length > 1 || a.count > 1;
  const hasMore = a.evidence || multiple;
  const ack = alertAck(a);
  const inlineAck = ack.startsWith('<p class="alert-ack"><button') ? ack.replace('<p class="alert-ack">', '').replace('</p>', '') : '';
  const glpi = alertGlpi(a);  // badge du dossier compris : la version change avec le statut GLPI
  return '<article class="alert-item compact ' + (a.fresh ? a.severity : 'stale') + '" data-alert-key="' + escAttr(a.id) + '" data-alert-version="' + alertVersion(a, maintenance, glpi) + '">' +
    '<div class="alert-head">' + alertBadge(a) + '<span class="alert-source">' + esc(a.source) + '</span>' +
    '<h3>' + esc(a.title) + '</h3>' + (a.chronic ? '<span class="badge unknown">Chronique</span>' : '') +
    (maintenance ? '<span class="badge unknown">Maintenance · ' + esc(maintenance.name) + '</span>' : '') + alertSince(a) +
    '<span class="state-count">' + a.count + '</span>' + inlineAck + glpi + '</div>' + (inlineAck ? '' : ack) +
    alertClassification(a) +
    '<p class="alert-meta"><b>' + esc(a.delay || '') + '</b>' +
    (a.rule ? ' · Règle : ' + esc(a.rule) : '') +
    (a.source_severity ? ' · Gravité d’origine : ' + esc(a.source_severity) : '') + ' · ' + alertTargetLine(a) +
    (a.fresh ? '' : ' · <b>état à reconfirmer</b>') + '</p>' +
    '<div class="alert-exact-dates"><span>' + (multiple ? 'Plus ancien début connu du groupe' : 'Début déclaré') + ' : ' +
    (alertStartMs(a) === null ? '<span class="unknown">Non mesuré</span>' : exactTimeMarkup(new Date(alertStartMs(a)).toISOString())) +
    (multiple && a.started_at_complete === false ? ' · certaines cibles sans date de début' : '') +
    '</span>' + (a.latest_event_at?'<span>'+esc({journal:'Dernier premier suivi',reopened:'Dernière réapparition',source:'Dernier déclenchement déclaré',resolved:'Dernière résolution'}[a.latest_event_kind]||'Dernière occurrence')+' : '+exactTimeMarkup(a.latest_event_at)+'</span>':'')+
    '<span>' + (a.source === 'Zabbix' ? 'Dernière lecture API' : 'Dernière preuve') + ' : ' + exactTimeMarkup(a.observed_at) + '</span></div>' +
    (hasMore ? '<details class="alert-more" data-alert-more-key="' + escAttr(a.id) + '"' + (alertOpenDetails.has(a.id) ? ' open' : '') + '><summary>' +
      (a.evidence ? 'Preuve' : '') + (a.evidence && multiple ? ' et ' : '') + (multiple ? a.count + ' cible(s)' : '') + '</summary>' +
      (a.evidence ? '<p class="note">' + esc(a.evidence) + '</p>' : '') + (multiple ? alertTargets(a) : '') + '</details>' : '') +
    '</article>';
}
// Ouverture des détails mémorisée : les rafraîchissements remplacent les alertes modifiées.
document.addEventListener('toggle', e => {
  const d = e.target;
  if (!(d instanceof HTMLDetailsElement) || !d.dataset.alertMoreKey) return;
  if (d.open) alertOpenDetails.add(d.dataset.alertMoreKey); else alertOpenDetails.delete(d.dataset.alertMoreKey);
}, true);

// Ticket GLPI (web/itsm.js) : dossier ITSM relu côté serveur, prévisualisé puis confirmé.
// Bouton réservé aux administrateurs, pas pour une information ; le badge du dossier
// existant (web/itsm.js) est visible par tous. Une alerte affichée est active.
function alertGlpi(a) {
  const badge = typeof itsmBadge === 'function' ? itsmBadge('alert', a.id, true) : '';
  if (a.severity === 'info' || !roleAllows('admin')) return badge;
  return badge + '<button class="alert-glpi" data-itsm-origin="alert" data-itsm-id="' + escAttr(a.id) + '" title="Créer ou consulter le ticket GLPI de cette alerte">Ticket GLPI</button>';
}

// Prise en charge partagée (/api/alerts/ack) : visible par tous les postes.
function alertAck(a) {
  if (a.severity === 'info') return '';
  if (a.ack) {
    return '<p class="alert-ack">Pris en charge par <b>' + esc(a.ack.by) + '</b>' +
      (a.ack.authenticated ? '' : ' <small title="Nom saisi en mode local, non vérifié">(déclaratif, non authentifié)</small>') + ' il y a <b data-since="' + escAttr(a.ack.at) + '"></b>' +
      (a.ack.note ? ' — « ' + esc(a.ack.note) + ' »' : '') + ' · jusqu’à ' + esc(stamp(a.ack.until)) +
      ' <button class="link" data-alert-unack="' + escAttr(a.id) + '">Libérer</button></p>';
  }
  return a.chronic ? '' : '<p class="alert-ack"><button data-alert-ack="' + escAttr(a.id) + '">Prendre en charge</button></p>';
}

// Chroniques : export pour le nettoyage dans Zabbix (triggers jamais refermés).
function alertChronicCsv() {
  const lignes = [['Source', 'Gravité OpsControl', 'Gravité d’origine', 'Anomalie', 'Cible', 'Ouverte depuis', 'Jours']];
  (alertData?.alerts || []).filter(a => a.chronic).forEach(a => a.targets.forEach(t => {
    const v = t.started_at, ms = /^[0-9]+$/.test(String(v)) ? Number(v) * 1000 : Date.parse(v);
    lignes.push([a.source, a.severity_label, a.source_severity || '', a.title, t.name,
      Number.isFinite(ms) ? new Date(ms).toISOString().slice(0, 10) : '', Number.isFinite(ms) ? Math.floor((Date.now() - ms) / 86400000) : '']);
  }));
  const csv = lignes.map(l => l.map(c => '"' + String(c).split('"').join('""') + '"').join(';')).join('\r\n');
  const url = URL.createObjectURL(new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8' }));
  const lien = document.createElement('a');
  lien.href = url;
  lien.download = 'infraops-anomalies-chroniques.csv';
  lien.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function alertChronicSection(liste) {
  if (!liste.length) return '';
  return '<details class="panel critical-old chronic-block"><summary>' + liste.length + ' anomalie(s) chronique(s) — ouvertes depuis plus de 30 jours</summary>' +
    '<p class="note">Jamais refermées dans leur source : ni incident à traiter dans l’heure, ni état réel prouvé. ' +
    'Les corriger ou les fermer dans Zabbix rend l’écran à nouveau fiable.</p>' +
    '<button data-alert-csv>Exporter pour nettoyage (CSV)</button>' + liste.map(alertItem).join('') + '</details>';
}

function homeCriticalMarkup() {
  if (!alertData) return '<section class="panel critical-home"><h2>Incidents critiques</h2><p>' +
    esc(alertFeedError || 'Chargement des incidents…') + '</p></section>';
  const tout = alertData.alerts.map(currentAlert).filter(a => a.severity === 'critical');
  const all = tout.filter(a => !a.chronic), chroniques = tout.filter(a => a.chronic);
  const current = all.filter(a => a.fresh), old = all.filter(a => !a.fresh);
  // Une ligne de synthèse : l'âge et l'erreur de chaque source vivent dans le centre Sources
  // (ils étaient affichés ici, dans les tuiles et dans le journal).
  const known = alertData.sources || [], late = known.filter(s => !s.fresh);
  const sources = known.length ? '<span class="source-age">Sources : ' + (known.length - late.length) + ' / ' + known.length + ' récentes' +
    (late.length ? ' · à reconfirmer : ' + esc(late.map(s => s.name || s.provider).join(', ')) : '') +
    ' · <button class="link" data-go="Sources">détail</button></span>' : '';
  // « Rien à signaler » en vert seulement si des sources existent ET sont toutes récentes :
  // une source muette ne prouve pas l'absence d'incident (audit SUP-04).
  const unverified = !known.length || late.length > 0;
  const clear = !current.length && !old.length && !chroniques.length && !alertFeedError && !unverified;
  return '<section class="panel critical-home' + (clear ? ' is-clear' : '') + '"><div class="panel-head"><h2>Incidents critiques <span class="state-count">' +
    current.length + ' cause(s) récente(s)</span></h2><div><button data-briefing-open>Bilan d’ouverture</button> <button data-go="Alertes">Toutes les alertes</button></div></div>' +
    (clear ? '' : '<p class="note">Derniers incidents observés, y compris les cibles hors inventaire.</p>') +
    (alertFeedError ? '<p role="alert" class="form-error">' + esc(alertFeedError) + ' Derniers incidents conservés, à reconfirmer.</p>' : '') +
    (clear ? '' : '<div class="critical-sources">' + (sources || 'Aucune source API configurée.') + '</div>') +
    (current.slice(0,6).map(alertItem).join('') || '<p class="empty">' + (unverified
      ? 'Aucun incident critique observé, mais l’absence n’est pas confirmée : sources absentes ou à reconfirmer.'
      : 'Aucun incident critique récent.') + '</p>') +
    (current.length > 6 ? '<button data-go="Alertes">Voir les ' + (current.length-6) + ' autres causes critiques</button>' : '') +
    (old.length ? '<details class="critical-old"><summary>' + old.length + ' cause(s) critique(s) ancienne(s) à reconfirmer</summary>' + old.slice(0,6).map(alertItem).join('') + '<button data-go="Alertes">Consulter toutes les preuves anciennes</button></details>' : '') +
    (chroniques.length ? '<p class="note">' + chroniques.length + ' anomalie(s) critique(s) chronique(s), ouvertes depuis plus de 30 jours, ne sont pas comptées ici. <button class="link" data-go="Alertes">Voir et exporter</button></p>' : '') +
    '</section>';
}

function renderHomeCritical() {
  const target = $('#home-critical');
  if (!target) return;
  const signature = JSON.stringify({data: alertData ? {...alertData, generated_at: undefined} : null, error: alertFeedError,
    fresh: (alertData?.alerts || []).map(a => currentAlert(a).fresh)});
  if (signature === homeCriticalSignature && target.childElementCount) return;
  const expanded = target.querySelector('.critical-old')?.open;
  target.innerHTML = homeCriticalMarkup();
  if (expanded && target.querySelector('.critical-old')) target.querySelector('.critical-old').open = true;
  homeCriticalSignature = signature;
}

function alertPolicy() {
  return '<details class="panel alert-policy"><summary>Politique de gravité OpsControl — pourquoi chaque alerte a son niveau</summary>' +
    '<div class="table"><table><thead><tr><th>Niveau</th><th>Délai d’intervention</th></tr></thead><tbody>' +
    alertData.levels.map(l => '<tr><td><span class="badge ' + l.key + '">' + esc(l.label) + '</span></td><td>' + esc(l.delay) + '</td></tr>').join('') +
    '</tbody></table></div><div class="table"><table><thead><tr><th>Domaine</th><th>Règle</th></tr></thead><tbody>' +
    alertData.policy.map(r => '<tr><td>' + esc(r.domain) + '</td><td class="wrap">' + esc(r.rule) + '</td></tr>').join('') +
    '</tbody></table></div><p class="note">La gravité d’origine (Zabbix, audit) reste affichée sur chaque alerte : ' +
    'la requalification est explicite, jamais silencieuse.</p></details>';
}

function alertMarkup() {
  // Premier chargement en échec : on le dit, au lieu d'un « Chargement… » sans fin (audit SUP-17).
  if (!alertData) return '<div class="panel">' + (alertFeedError
    ? '<p role="alert" class="form-error">' + esc(alertFeedError) + ' Aucun état ne peut en être déduit.</p>'
    : 'Chargement des alertes…') + '</div>';
  const n = alertData.counts, q = alertQuery.trim().toLowerCase();
  // Les informations (états voulus, triggers de test) ne s'affichent que sur demande.
  const filtrees = alertData.alerts.map(currentAlert).filter(a =>
    (alertLevel ? a.severity === alertLevel : a.severity !== 'info') && (!alertSource || a.source === alertSource) &&
    (!alertFresh || String(a.fresh) === alertFresh) &&
    (!q || (a.title + ' ' + a.targets.map(t => t.name + ' ' + (t.detail || '')).join(' ')).toLowerCase().includes(q)));
  const actives = filtrees.filter(a => !a.chronic), chroniques = filtrees.filter(a => a.chronic);
  const periodVisible = actives.filter(alertInPeriod);
  const visibles = periodVisible.filter(a=>(!alertAge||alertAgeOf(a)===alertAge)&&(!alertState||(a.state_counts||{})[alertState])).sort(alertRecentFirst);
  const horsPeriode = actives.length - periodVisible.length;
  const sources = [...new Set(alertData.alerts.map(a => a.source))].sort();
  const muettes = alertData.sources.filter(s => !s.fresh);
  const carte = (cle, titre, cls) => '<button class="card stat-card ' + cls + '" data-alert-level="' + cle + '"><span class="stat-dot"></span>' +
    titre + '<strong>' + n[cle] + '</strong><small>' + esc((alertData.levels || []).find(l => l.key === cle)?.delay || '') +
    (n[cle + '_stale'] ? ' · + ' + n[cle + '_stale'] + ' à confirmer' : '') + '</small></button>';
  return (alertFeedError ? '<p role="alert" class="form-error">' + esc(alertFeedError) +
      ' Chiffres du dernier chargement réussi, à reconfirmer.</p>' : '') +
    '<div class="stats alert-stats alert-stats-5">' +
    carte('critical', 'Critiques confirmées', 'critical') + carte('warning', 'Majeures', 'warning') +
    carte('preventive', 'Préventives', 'preventive') +
    // Aucune source déclarée : ton neutre, jamais « toutes récentes » en vert (audit SUP-05).
    // Flux en échec : chiffres du dernier chargement réussi, jamais présentés comme à jour (SUP-17).
    '<div class="card stat-card' + (alertFeedError ? '' : muettes.length ? ' warning' : alertData.sources.length ? ' ok' : '') +
    '"><span class="stat-dot"></span>Sources à jour<strong>' +
    (alertData.sources.length - muettes.length) + '/' + alertData.sources.length + '</strong><small>' +
    (alertFeedError ? 'flux indisponible : à reconfirmer' : muettes.length ? esc(muettes.map(s => s.name).join(', ')) : alertData.sources.length ? 'toutes récentes'
      : 'Aucune source API déclarée') + '</small></div>' +
    '<button class="card stat-card" data-alert-level="info"><span class="stat-dot"></span>Informations<strong>' + (n.info + n.info_stale) +
    '</strong><small>masquées par défaut</small></button></div>' +
    '<section class="panel"><div class="panel-head"><h2>Alertes par cause <span class="state-count">' + visibles.length + '</span></h2>' +
    '<div><span class="mini">Notifications groupées · 5 min · maintenances respectées</span> <button data-alert-seen>Marquer comme vues</button> ' +
    ('Notification' in window && Notification.permission !== 'granted'
      ? '<button data-alert-notify>Activer les notifications du navigateur</button>' : '') + '</div></div>' +
    '<div class="filters"><input id="alert-search" type="search" aria-label="Rechercher une alerte" placeholder="Rechercher une cause, un serveur, un volume" value="' + escAttr(alertQuery) + '">' +
    '<select id="alert-source" aria-label="Source"><option value="">Toutes les sources</option>' + sources.map(s => '<option>' + esc(s) + '</option>').join('') + '</select>' +
    '<select id="alert-level" aria-label="Gravité"><option value="">Critique, majeur, préventif</option>' +
    alertData.levels.map(l => '<option value="' + l.key + '">' + esc(l.label) + ' seulement</option>').join('') + '</select>' +
    '<select id="alert-fresh" aria-label="Fraîcheur des preuves"><option value="">Récentes et anciennes</option><option value="true">Récentes seulement</option><option value="false">À confirmer seulement</option></select>' +
    '<select id="alert-period" aria-label="Période"><option value="7">7 derniers jours</option><option value="">Toutes les dates</option></select>'+
    '<select id="alert-age" aria-label="Ancienneté des alertes"><option value="">Toutes les anciennetés</option><option value="recent">Nouvelles · moins de 24 h</option><option value="old">Anciennes · plus de 24 h</option><option value="unknown">Ancienneté inconnue</option></select>'+
    '<select id="alert-state" aria-label="Traitement des alertes"><option value="">Tous les traitements</option>'+Object.entries(ALERT_STATES).map(([k,v])=>'<option value="'+k+'">'+esc(v)+'</option>').join('')+'</select></div>' +
    '<p class="note" id="alert-order">Plus récentes d’abord (dernière occurrence ou premier suivi) · dates exactes : Africa/Casablanca · notifications critiques : événement de moins de 15 min et preuve récente' +
    (horsPeriode ? ' · ' + horsPeriode + ' alerte(s) commencée(s) il y a plus de ' + alertPeriod + ' jours masquée(s) — <button class="link" data-alert-all-dates>toutes les dates</button>' : '') + '</p>' +
    '<div id="alert-list">' + (visibles.slice(0, alertShown).map(alertItem).join('') || '<div class="empty"><span class="empty-symbol">◎</span>Aucune alerte pour ces critères.</div>') + '</div>' +
    '<div id="alert-more">' + (visibles.length > alertShown ? '<div class="more-row"><button data-alert-more>Afficher ' + Math.min(ALERT_PAGE, visibles.length - alertShown) +
      ' alertes de plus (' + (visibles.length - alertShown) + ' restantes)</button><span class="note">' + alertShown + ' sur ' + visibles.length + ' affichées</span></div>' : '') + '</div>' +
    '<p class="note" id="alert-scope">' + esc(alertData.scope) + '</p></section><div id="alert-chronic">' + alertChronicSection(chroniques) + '</div><div id="alert-policy">' + alertPolicy() + '</div>';
}

// Bandeau global : présent sur toutes les pages, jamais sur une preuve ancienne.
function alertStrip() {
  let strip = $('#alert-strip');
  if (!strip) {
    strip = document.createElement('div');
    strip.id = 'alert-strip';
    strip.setAttribute('role', 'alert');
    // Premier bandeau sous la barre de contrôle, au-dessus de la synthèse et des serveurs critiques
    // (créé hors rendu quand les alertes arrivent : il ne doit pas s'intercaler plus bas).
    const anchor = document.getElementById('v2-ops') || document.getElementById('t0-zone') || document.getElementById('v2-hub-tabs') || $('#content');
    anchor.insertAdjacentElement('beforebegin', strip);
  }
  const nouvelles = alertNew();
  strip.hidden = !nouvelles.length || page === 'Alertes';
  const markup = nouvelles.length
    ? '<span class="badge critical">' + nouvelles.length + ' nouvelle(s) alerte(s) critique(s)</span><span>' +
      esc(nouvelles.slice(0, 2).map(a => a.title).join(' · ')) + (nouvelles.length > 2 ? ' …' : '') + '</span>' +
      '<button class="primary" data-go="Alertes">Voir les alertes</button><button data-alert-seen>Marquer comme vues</button>'
    : '';
  if (markup !== stripSignature) { strip.innerHTML = markup; stripSignature = markup; }
  const total = alertInterrupting().length;
  // Préfixe du titre de l'écran courant (app.js, syncDocument) : le titre par page reste lisible.
  alertTitleCount = total;
  applyDocumentTitle();
  alertAppBadge(total);
  // Les alertes vivent dans le centre Incidents (lot 3) : compteur sur son entrée de menu.
  const count = document.querySelector('#nav [data-page="Incidents"] .nav-count');
  if (count) count.textContent = total || '';
}

function alertNotify() {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  const now = Date.now(), state = alertNotificationState();
  for (const [key, at] of Object.entries(state.sent)) if (now - Number(at) > ALERT_NOTIFY_TTL) delete state.sent[key];
  const cibles = a => (a.notification_events || []).flatMap(t => [t.host_key, t.name]).filter(Boolean);
  // Serveurs déjà signalés par la voie rapide (registre commun, app.js) : pas de doublon.
  const nouvelles = alertNew().map(a=>({...a,notification_events:a.notification_events.filter(e=>!state.sent[alertEventKey(e)])})).filter(a=>a.notification_events.length)
    .filter(a => { const c = cibles(a); return !(c.length && c.every(n => notifiedRecently([n]))); });
  if (!nouvelles.length) return;
  const wait = ALERT_NOTIFY_COOLDOWN - (now - state.last);
  if (wait > 0) {
    if (!alertNotifyTimer) alertNotifyTimer = setTimeout(() => { alertNotifyTimer = null; alertNotify(); }, wait);
    return;
  }
  state.last = now;
  nouvelles.forEach(a => { a.notification_events.forEach(e=>state.sent[alertEventKey(e)]=now); markNotified(cibles(a)); });
  alertSaveNotificationState(state);
  // requireInteraction : un incident critique reste dans le centre de notifications Windows
  // jusqu'au clic, au lieu de disparaître en quelques secondes pendant une absence.
  const n = new Notification('OpsControl : ' + nouvelles.length + ' nouvelle(s) alerte(s) critique(s)', {
    body: nouvelles.slice(0, 3).map(a => a.source + ' — ' + a.title + ' · ' + a.notification_events.slice(0,2).map(e=>e.name).join(', ')).join('\n'), tag: 'infraops-alertes',
    requireInteraction: true, renotify: true, icon: '/assets/opscontrol-icon-96.png',
  });
  n.onclick = () => { window.focus(); navigate('Alertes'); };
}

// Pastille sur l'icône de l'application installée (Edge ou Chrome, barre des tâches) :
// nombre de critiques qui interrompent. Sans installation, l'API est absente ou sans effet.
let alertBadgeCount = null;
function alertAppBadge(total) {
  if (total === alertBadgeCount || !('setAppBadge' in navigator)) return;
  alertBadgeCount = total;
  (total ? navigator.setAppBadge(total) : navigator.clearAppBadge()).catch(() => { /* non installée : sans effet */ });
}

// Bouton permanent de la barre du haut : l'activation était cachée dans la page Alertes,
// alors que c'est le seul canal qui atteint l'opérateur fenêtre réduite.
const ALERT_NOTIFY_LABELS = {
  default: ['Activer les alertes', 'Recevoir une notification Windows à chaque nouvel incident critique'],
  granted: ['Alertes actives', 'Notifications actives : cliquer pour envoyer une notification de test'],
  denied: ['Alertes bloquées', 'Notifications refusées : cliquer pour savoir comment les réautoriser'],
};
function alertNotifyControl() {
  const actions = document.querySelector('.top-actions');
  if (!actions || !('Notification' in window)) return;
  let button = actions.querySelector('[data-notify-control]');
  if (!button) {
    button = document.createElement('button');
    button.type = 'button';
    button.className = 'v2-shell-button notify-control';
    button.dataset.notifyControl = '';
    const theme = actions.querySelector('#theme');
    if (theme) theme.before(button); else actions.prepend(button);
  }
  const etat = ALERT_NOTIFY_LABELS[Notification.permission] ? Notification.permission : 'default';
  if (button.dataset.state === etat) return;
  button.dataset.state = etat;
  // Cloche toujours visible ; libellé masqué sur écran étroit, comme « Menu » et « Rechercher ».
  button.innerHTML = '<span aria-hidden="true">' + (etat === 'denied' ? '🔕' : '🔔') + '</span>' +
    '<span class="v2-shell-label" aria-hidden="true"> ' + esc(ALERT_NOTIFY_LABELS[etat][0]) + '</span>';
  button.title = ALERT_NOTIFY_LABELS[etat][1];
  button.setAttribute('aria-label', ALERT_NOTIFY_LABELS[etat][1]);
}
async function alertNotifyAction() {
  if (Notification.permission === 'default') {
    const choix = await Notification.requestPermission();
    toast(choix === 'granted' ? 'Notifications activées : chaque nouvel incident critique s’affichera, même fenêtre réduite.'
      : 'Notifications refusées par le navigateur.');
  } else if (Notification.permission === 'granted') {
    const n = new Notification('OpsControl : notification de test', {
      body: 'Les incidents critiques s’afficheront ainsi et resteront visibles jusqu’au clic.',
      tag: 'infraops-test', icon: '/assets/opscontrol-icon-96.png',
    });
    n.onclick = () => window.focus();
    toast('Notification de test envoyée. Rien ne s’affiche ? Vérifier « Ne pas déranger » et les notifications de Microsoft Edge dans les paramètres Windows.');
  } else {
    toast('Notifications bloquées : « … » › Autorisations de l’application (ou cadenas de la barre d’adresse) › Notifications › Autoriser, puis recharger.');
  }
  alertNotifyControl();
  if ($('#alert-data')) alertPaint(false);
}
document.addEventListener('click', e => { if (e.target.closest('[data-notify-control]')) alertNotifyAction(); });
alertNotifyControl();
// Permission changée hors de la page (paramètres du site) : le bouton suit.
navigator.permissions?.query({name: 'notifications'}).then(p => { p.onchange = alertNotifyControl; }).catch(() => {});

function alertReconcileList(current, next) {
  if (!current || !next) return false;
  const old = new Map([...current.querySelectorAll(':scope > .alert-item')].map(node => [node.dataset.alertKey, node]));
  const nodes = [...next.children].map(node => {
    if (!node.classList.contains('alert-item')) return node;
    const prior = old.get(node.dataset.alertKey);
    return prior && prior.dataset.alertVersion === node.dataset.alertVersion ? prior : node;
  });
  current.replaceChildren(...nodes);
  return true;
}

function alertPaint(full = false) {
  const target = document.getElementById('alert-data');
  if (!target) return;
  const focus = document.activeElement?.id, start = document.activeElement?.selectionStart, end = document.activeElement?.selectionEnd;
  if (full || !target.querySelector('#alert-list')) target.innerHTML = alertMarkup();
  else {
    const tmp = document.createElement('div');
    tmp.innerHTML = alertMarkup();
    const nextList = tmp.querySelector('#alert-list'), currentList = target.querySelector('#alert-list');
    alertReconcileList(currentList, nextList);
    ['.alert-stats', '.panel > .panel-head', '#alert-order', '#alert-more', '#alert-scope', '#alert-chronic', '#alert-policy'].forEach(selector => {
      const next = tmp.querySelector(selector), current = target.querySelector(selector);
      if (next && current && next.outerHTML !== current.outerHTML) current.replaceWith(next);
    });
    for (const id of ['alert-source', 'alert-level', 'alert-fresh', 'alert-period']) {
      const next = tmp.querySelector('#' + id), current = target.querySelector('#' + id);
      if (next && current && next.innerHTML !== current.innerHTML) current.innerHTML = next.innerHTML;
    }
  }
  alertSelects();
  const element = focus && document.getElementById(focus);
  if (element && document.activeElement !== element) {
    element.focus({preventScroll: true});
    if (start != null && element.setSelectionRange) element.setSelectionRange(start, end ?? start);
  }
}

async function loadAlerts() {
  if (alertLoading) { alertReloadPending = true; return; }
  alertLoading = true;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const [received] = await Promise.all([api('/api/alerts', {signal: controller.signal}), loadAlertMaintenance()]);
    // Réponse ancienne ou tronquée : c'est une panne du flux, jamais « zéro incident ».
    if (!received || !Array.isArray(received.alerts)) throw Error('Réponse du centre d’alertes incomplète : aucun état n’en est déduit.');
    alertData = received;
    alertFeedError = '';
  } catch (e) {
    alertFeedError = 'Flux d’incidents indisponible.';
    const target = $('#alert-data');
    if (target) target.textContent = e.message;
  } finally {
    clearTimeout(timeout);
    alertLoading = false;
    if (alertReloadPending) { alertReloadPending = false; setTimeout(loadAlerts, 100); }
  }
  alertStrip();
  alertNotify();
  renderHomeCritical();
  const target = $('#alert-data');
  if (target && page === 'Alertes' && !selected) {
    alertPaint(false);
  }
}

function alertSelects() {
  if ($('#alert-source')) $('#alert-source').value = alertSource;
  if ($('#alert-level')) $('#alert-level').value = alertLevel;
  if ($('#alert-fresh')) $('#alert-fresh').value = alertFresh;
  if ($('#alert-period')) $('#alert-period').value = alertPeriod;
  if ($('#alert-age')) $('#alert-age').value = alertAge;
  if ($('#alert-state')) $('#alert-state').value = alertState;
}

navigationHooks.push(() => { if (alertData) alertStrip(); });
renderHooks.push(() => { renderHomeCritical(); if (alertData) alertStrip(); });
pageRenderers.Alertes = function () {
  $('#content').innerHTML = '<div id="alert-data"></div>';
  alertPaint(true);
};

$('#content').addEventListener('input', e => {
  if (e.target.id !== 'alert-search') return;
  alertQuery = e.target.value;
  alertShown = ALERT_PAGE;
  alertPaint(false);
});
$('#content').addEventListener('change', e => {
  const map = { 'alert-source': v => alertSource = v, 'alert-level': v => alertLevel = v, 'alert-fresh': v => alertFresh = v, 'alert-period': v => alertPeriod = v,
    'alert-age':v=>{alertAge=v;if(v)alertPeriod='';},'alert-state':v=>alertState=v };
  if (!map[e.target.id]) return;
  map[e.target.id](e.target.value);
  alertShown = ALERT_PAGE;
  alertPaint(false);
});
document.addEventListener('click', async e => {
  if (e.target.closest('[data-alert-all-dates]')) {
    alertPeriod = '';
    alertShown = ALERT_PAGE;
    alertPaint(false);
    return;
  }
  if (e.target.closest('[data-alert-more]')) {
    alertShown += ALERT_PAGE;
    alertPaint(false);
    return;
  }
  const niveau = e.target.closest('[data-alert-level]');
  if (niveau) {
    alertShown = ALERT_PAGE;
    alertLevel = alertLevel === niveau.dataset.alertLevel ? '' : niveau.dataset.alertLevel;
    alertPaint(false);
  }
  const prise = e.target.closest('[data-alert-ack]');
  if (prise) {
    // Même dialogue que les incidents (au lieu de deux prompt() bloquants) : durée au choix.
    alertOpenAckDialog(prise.dataset.alertAck);
    return;
  }
  const liberer = e.target.closest('[data-alert-unack]');
  if (liberer) {
    try { await post('/api/alerts/unack', { id: liberer.dataset.alertUnack }); toast('Prise en charge libérée.'); } catch (error) { toast(error.message); }
    loadAlerts();
    return;
  }
  if (e.target.closest('[data-alert-csv]')) { alertChronicCsv(); return; }
  if (e.target.closest('[data-alert-seen]')) {
    alertRemember(alertInterrupting().flatMap(a => a.notification_events.map(alertEventKey)));
    alertStrip();
    toast('Alertes marquées comme vues : elles restent listées tant que la preuve existe.');
  }
  if (e.target.closest('[data-alert-notify]')) await alertNotifyAction();
});

// Lecture seule et sans SSH : /api/alerts relit l'état déjà collecté. Il est
// interrogé même onglet caché, sinon aucune notification ne pourrait partir.
// Prise en charge d'une alerte : dialogue accessible (même gabarit que incidents.js).
// Derrière le reverse proxy authentifié, l'auteur est l'identité transmise : pas de saisie.
const alertAckDialog = document.createElement('dialog');
alertAckDialog.id = 'alert-ack-dialog';
document.body.append(alertAckDialog);
function alertOpenAckDialog(id) {
  const item = (alertData?.alerts || []).find(a => a.id === id);
  const local = !operatorIdentity?.authenticated;
  let who = '';
  try { who = localStorage.getItem('infraops.operateur') || operatorIdentity?.default_name || ''; } catch { /* stockage indisponible */ }
  alertAckDialog.innerHTML = '<form method="dialog"><div class="panel-head"><h2>Prendre en charge</h2><button type="button" data-alert-ack-close>Fermer</button></div>' +
    '<p><b>' + esc(item?.title || id) + '</b><br><span class="mini">' + esc(item?.source || '') + '</span></p>' +
    '<label>Durée<select name="hours"><option value="1">1 heure</option><option value="8" selected>8 heures</option>' +
    '<option value="24">24 heures</option><option value="72">72 heures</option></select></label>' +
    '<p class="note">Arrête le bandeau et les notifications pour toute l’équipe pendant cette durée ; l’alerte reste listée.</p>' +
    (local ? '<label>Votre nom (mode local non authentifié : déclaratif)<input name="by" required maxlength="60" value="' + escAttr(who) + '"></label>' :
      '<p class="note">Enregistré au nom de <b>' + esc(operatorIdentity.user) + '</b> (identité du reverse proxy).</p>') +
    '<label>Note (facultative)<input name="note" maxlength="300" placeholder="Ticket, action en cours…"></label>' +
    '<input type="hidden" name="id" value="' + escAttr(id) + '">' +
    '<p class="form-error" role="alert"></p><div class="panel-head"><span class="mini">Action locale à OpsControl</span>' +
    '<button class="primary" type="submit">Prendre en charge</button></div></form>';
  alertAckDialog.showModal();
  (alertAckDialog.querySelector('input[name=by]') || alertAckDialog.querySelector('select'))?.focus();
}
alertAckDialog.addEventListener('click', e => { if (e.target.closest('[data-alert-ack-close]')) alertAckDialog.close(); });
alertAckDialog.addEventListener('submit', async e => {
  e.preventDefault();
  const form = e.target, values = Object.fromEntries(new FormData(form)), button = form.querySelector('[type=submit]');
  const hours = Number(values.hours) || 8;
  button.disabled = true;
  try {
    await post('/api/alerts/ack', { id: values.id, by: (values.by || '').trim().slice(0, 60), note: (values.note || '').trim().slice(0, 300), hours });
    if (values.by) { try { localStorage.setItem('infraops.operateur', values.by.trim()); } catch { /* stockage indisponible */ } }
    alertAckDialog.close();
    toast('Prise en charge enregistrée pour ' + hours + ' h : bandeau et notifications arrêtés pour toute l’équipe.');
    loadAlerts();
  } catch (error) { form.querySelector('.form-error').textContent = error.message; }
  finally { button.disabled = false; }
});

// Onglet caché : toutes les 30 s (et non 10) — les notifications sont de toute façon
// groupées par fenêtres de 5 min.
loadAlerts();
poll('alertes', 10000, loadAlerts, { hidden: true, hiddenMs: 30000 });
poll('alertes-affichage', 1000, () => { alertStrip(); renderHomeCritical(); });
